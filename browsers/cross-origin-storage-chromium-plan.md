# Chromium: Cross-Origin Storage (COS) — Implementation Plan

## Context

Cross-Origin Storage (COS) is a new WICG API: a content-addressable file cache, keyed by
cryptographic hash rather than by origin, that lets independent sites share one stored copy of a
large, byte-identical resource (AI model weights, Wasm modules, popular JS libraries, fonts)
instead of each downloading and storing it separately. The spec defines the
`navigator.crossOriginStorage.requestFileHandle()` entry point; a registry of hash-keyed entries
that exist only once their bytes have been supplied and verified; three independent, additive
disclosure grants (the same-site baseline, an explicit origins list, and a PHL/GREASE-gated
global grant), bounded at write time by the `Cross-Origin-Storage-Allow-Origin` response header;
storage-budget and eviction rules; and rate-limiting/probing defenses. WPTs exist at
[web-platform-tests/wpt#61811](https://github.com/web-platform-tests/wpt/pull/61811).

Three independent prototype implementations (Servo, Ladybird, Firefox) came first and left
detailed engineering notes in `cross-origin-storage-implementation-notes.md`. Those notes were used as
prior art throughout, and they earned their keep: the outstanding-writer-count cleanup race
(§2), the `seek()`/`truncate()` unbounded-claim DoS (§10.2), per-algorithm hash validation as a
path-traversal defense (§10.1), and re-validation on the trusted side of a process boundary
(§10.3) were all designed in from the start here rather than discovered.

This document covers Chromium's first pass: the Blink IDL surface, the Mojo plumbing, and a
correct read/write round trip (disk-persisted, budget-accounted, PHL/GREASE-gated, and
rate-limited) across all three disclosure grants, in windows and both worker types that can
carry the feature. It also covers the inspection surfaces built on top of it: a DevTools protocol
domain with an Application-panel view, and a `chrome://settings` page.

**Status: not shipped.** This is a stack of work-in-progress Gerrit CLs against `chromium/src`,
each marked Work in Progress, unreviewed, and not landed:

| CL | What it adds |
| --- | --- |
| [8256403](https://chromium-review.googlesource.com/c/chromium/src/+/8256403) | The API: Blink IDL, Mojo, the registry, the Public Hash List |
| [8270451](https://chromium-review.googlesource.com/c/chromium/src/+/8270451) | The DevTools protocol domain |
| [8310397](https://chromium-review.googlesource.com/c/chromium/src/+/8310397) | Persisted read records and the sniffed content type |
| [8308719](https://chromium-review.googlesource.com/c/chromium/src/+/8308719) | The `chrome://settings` page |
| [8277053](https://chromium-review.googlesource.com/c/devtools/devtools-frontend/+/8277053) | The DevTools front-end panel (separate repository) | It is not in Chrome, not behind an origin trial, and not on
any release channel. Unlike the other prototypes described in this directory, Chrome does intend
to ship Cross-Origin Storage, so this is a first implementation pass on that path rather than an
experiment for its own sake — but intent is not a ship date, and everything in
[Deferred / follow-up work](#deferred--follow-up-work) stands between this and anything
shippable. The `CrossOriginStorage` runtime-enabled feature is set to `stable` **on this branch
only**, which means nothing more than "on by default for anyone who downloads a build produced
from this branch." Work happened on a `cross-origin-storage` branch in a local `chromium/src`
checkout.

## Key architectural decisions

1. **The registry is `BrowserContext` user data in a new `content/browser/cross_origin_storage/`
   directory — deliberately not hung off `StoragePartition`'s per-`StorageKey` machinery.** COS
   entries are shared by every origin that stored them, so partitioning them by `StorageKey` would
   contradict the feature. This follows the notes' §1 warning against extending an existing
   per-origin storage tree that assumes its partitioning. The registry lives on the UI thread and
   posts its blocking file I/O to a `base::ThreadPool` sequenced runner; because every decision is
   made synchronously on one sequence, operations are serialized in arrival order, which is what
   the spec's "Cross-Origin Storage queue" requires without a queue object. **Each writer gets a
   sequence of its own, separate from the registry's.** Everything the registry itself posts is
   short — a metadata write, an unlink, a rename, a stat — but hashing a multi-gigabyte payload is
   not, and a single shared sequence would make a concurrent read's `stat()` wait behind it.
2. **`FileSystemFileHandle` is reused with no Blink-side changes at all, by implementing the
   *browser* end of the File System Access Mojo interfaces.** This is the one place Chromium had
   it markedly easier than the other engines, and it is worth generalizing: Blink's
   `FileSystemFileHandle` is a thin wrapper over a
   `mojo::Remote<mojom::blink::FileSystemAccessFileHandle>`, so a COS-backed implementation of
   that interface (`CrossOriginStorageFileHandleImpl`) can be handed straight to the existing
   class. `instanceof FileSystemFileHandle` holds by construction, `getFile()` and
   `createWritable()` work through the standard paths, and neither `file_system_access/` nor OPFS
   is touched. **Before writing a parallel handle class, check whether your engine's file handle is
   a wrapper around an IPC interface you can implement yourself.**
   `CrossOriginStorageFileWriterImpl` does the same for `FileSystemAccessFileWriter`, which is what
   makes `write()`/`seek()`/`truncate()`/`close()` work with no new WebIDL.
3. **`kDataError` and `kQuotaExceededError` were added to the shared
   `FileSystemAccessStatus` enum.** The spec requires `close()` to reject with `DataError` on a
   hash mismatch and `QuotaExceededError` over budget, and the existing enum had neither. Two
   additive enum values plus two cases in Blink's error mapper is the whole change; the
   alternative (a COS-specific error channel) would have meant not reusing
   `FileSystemWritableFileStream`'s closing path.
4. **A create-request handle may not read the entry back until *that handle's own* write has
   verified — a per-handle gate, not a per-entry one.** `FileSystemFileHandle` carries a
   [`may read`](https://wicg.github.io/cross-origin-storage/#creating-and-writing-files) flag:
   true for a handle from a read request, which has already passed availability gating, and false
   for a handle from a create request until `verify and store` succeeds *for that same handle*.
   Gating per entry instead would make a create request into a read — any origin could ask for a
   handle and immediately `getFile()` an entry another origin wrote, learning its contents without
   satisfying `origins`, PHL membership or GREASE'ing, all of which are enforced on the read path
   only. Requiring the bytes first means a successful read through a create handle discloses
   nothing the caller did not already have. Worth testing explicitly: a per-entry check passes
   every ordinary single-origin round trip, because there the handle that wrote the entry is the
   handle reading it.

5. **Every recognized hash algorithm's digest shape is validated, on both sides of the process
   boundary.** `CrossOriginStorageHash::Create()` canonicalizes the algorithm name and enforces
   the exact hex length for SHA-1/256/384/512, not just SHA-256 (notes §10.1). The renderer
   validates so a malformed request becomes the spec's `TypeError` without a round trip; the
   browser re-validates because a compromised renderer can speak the Mojo interface directly and
   the digest becomes a filesystem path (notes §10.3). The same validation runs again when
   metadata is read back from disk, since a profile directory is not a trusted input either.
6. **Writes go to a disk-backed swap file from the start, with real backpressure.** Per notes §3,
   the swap file is real disk rather than memory, so a `truncate(huge)` claims disk rather than
   RAM, and it is capped (4 GiB) *before* each resize or write is attempted. The chunk reader does
   not re-arm its `mojo::SimpleWatcher` until the previous chunk has actually landed on disk, so a
   producer that outruns the disk cannot queue unbounded pending chunks. A failed chunk write sets
   an explicit flag that is checked *first* at `close()`, ahead of the digest — the digest is
   computed from what did land, so it cannot detect a chunk that never arrived (notes §3). The
   swap file stays open across chunks, and each chunk is fed to a running digest as it lands, so
   the common append-only write pays no second pass at `close()`. `seek()` and `truncate()` are
   genuine random-access edits that can invalidate bytes already hashed, so a write landing
   anywhere but immediately after the last hashed byte abandons the running digest and `close()`
   falls back to one full pass over the finished file — the ordering constraint notes §3
   describes, paid only by the writers that actually trigger it.
7. **A create request registers nothing, so an in-progress write is unobservable.** An entry is
   added only by `verify and store`, once a writer has supplied bytes that hash to the requested
   value. A read of a hash whose only write is in flight is therefore an ordinary
   `NotFoundError`, indistinguishable from a hash nobody has ever written, and an abandoned
   create handle leaves no trace. This replaced an earlier pending→written lifecycle, with
   outstanding-writer counts, a staleness timeout, and per-entry generation counters, all of which
   the new model makes unnecessary: there is no pending entry to reclaim, no count to settle, and
   nothing for a stale writer to disturb. It also closes what that lifecycle cost: a
   distinguishable "a write is in progress" answer handed any origin one noiseless bit about any
   hash, decided ahead of origins scoping, the PHL, and GREASE'ing, and without writing any bytes
   for the storage limit to bound — and an abandoned handle pinned its hash, suppressing every
   other origin's reads of it, for free and indefinitely.
8. **An entry's grants are independent and additive: an origins list, a globally-disclosable flag,
   and the same-site baseline every entry carries.** A single "scope" field, ordered same-site <
   list < wildcard, is the obvious model and is wrong: a later `origins: "*"` write would replace
   an existing list, and because the PHL gate applies to the global grant alone, every origin on
   that list would start getting `NotFoundError` whenever the hash was not on the list. Holding
   the two grants separately makes every visibility change strictly additive, which is what
   "upgradeable but never downgradeable" actually requires. `determine COS disclosure` checks the
   storing origins, then the same-site baseline, then the list, and only then the global grant, so
   the first three never reach the PHL gate at all.
9. **The `Cross-Origin-Storage-Allow-Origin` ceiling is read in the browser process, from its own
   record of the response.** An `origins` list is declared by script, which injected content can
   set; the header is the operator's authorization for it, which injected content cannot forge.
   The renderer never supplies it: the browser reads it from the last committed response of every
   document that owns the calling global (the document itself for a window, the ancestor frame for
   a dedicated worker, the current clients for a shared worker), intersects those sets, and drops
   every requested origin the result does not name. A list whose every member is dropped leaves
   the write succeeding with the same-site baseline alone, and the dropped origins are named in
   the writing document's console, since otherwise a developer sees a silently narrower entry and
   no reason for it.
10. **The Public Hash List is memory-mapped during the registry's async initialization, never
    read in and never loaded lazily on first lookup.** A lazy first-lookup load is the obvious
    design and is wrong here: the availability-gating decision runs on the UI thread, and a
    blocking read of a ~14 MiB file there trips Chromium's `AssertBlockingAllowed()` and would
    jank the browser regardless. Mapping happens on the file sequence alongside the entry scan,
    and requests arriving before initialization are queued rather than answered against an empty
    registry. The list is sorted at generation time and binary searched in place, so a lookup
    touches only the handful of pages the search visits: the file costs address space rather than
    ~14 MiB resident per profile, and a browser that never reaches the global grant pays nothing
    beyond the mapping. It ships as a loose data file next to the binary
    (`cross_origin_storage_public_hash_list.bin`, 458,164 sorted 32-byte digests) rather than
    compiled in, matching Firefox's choice for the same reason.
11. **`cross-origin-storage` is a real Permissions Policy feature, with `self` as its default
    allowlist**, registered in `permissions_policy_features.json5` and the
    `PermissionsPolicyFeature` Mojo enum. The renderer runs the policy gate *before* request
    validation, so a policy-blocked context gets `NotAllowedError` even for input that would
    otherwise be a `TypeError` — the WPT suite asserts exactly this ordering. The browser re-checks
    for frames as defense in depth.
12. **Clear-data uses revoke-and-GC, via a new `REMOVE_DATA_MASK_CROSS_ORIGIN_STORAGE`.** Clearing
    one origin strips it from every entry's storing origins, origins list, and provenance records,
    and deletes an entry only once no storing origin remains. Delete-if-involved was rejected:
    clearing site A's data silently destroying data site B still depends on, for an action B was
    never part of, is the worse failure mode. Neither the spec nor the explainer settles this
    (notes §16).
13. **Windows and both worker types that can carry the feature are wired; service workers fail
    closed.** Separate binder registrations for `RenderFrameHost`, `DedicatedWorkerHost` and
    `SharedWorkerHost`. In Chromium this is cheap because a per-context
    `BrowserInterfaceBroker` already exists; the notes' §1 warning about worker support being
    expensive to retrofit applies to engines without that route. A `ServiceWorkerGlobalScope`'s
    owner set is empty, so `check Cross-Origin Storage permission` returns false there: the
    renderer rejects with `NotAllowedError` before anything else, and the browser registers no
    binder for service workers at all, so a compromised one cannot reach the registry either.
    That is a deliberate fail-closed answer rather than a gap. A service worker's registration
    outlives the client that registered it, and one running global serves many clients whose
    policies need not agree, so there is no owning document whose policy could be consulted;
    covering it properly needs a policy captured from the worker's own script response, which
    Permissions Policy and Service Workers have yet to define.
14. **Every storing origin is charged an entry's full size; the global total counts it once.**
    The notes' §6 flagged multi-origin budget attribution as unresolved and suggested a
    fractional/shared scheme as the way to resolve it. That scheme is unsafe: if each of *N*
    storing origins is charged *S/N*, an origin's own charge drops when someone else stores bytes
    it also stores, and it can detect that by probing its own remaining headroom — learning that
    another origin stored a given hash, with none of the disclosure controls consulted. Charging
    each storing origin in full keeps an origin's usage a function of its own writes alone. The
    per-origin charges then sum to more than the bytes on disk, which is correct: the global cap
    protects the disk, while the per-origin share bounds what one origin can ask the registry to
    keep, matching the specification's own framing ("the total number of bytes an origin may
    contribute to the COS registry through successful writes"). Usage became derivable from an
    entry's storing origins, so the persisted attributed-origin field was dropped entirely
    (metadata version 2) and site-scoped clearing stopped needing reattribution logic. The
    tradeoff taken knowingly: an origin storing many already-popular entries burns its share
    without adding disk usage, and since it may only evict its own sole-owned entries, it can hit
    its cap holding little it is allowed to evict.

## Implementation plan

### Build order

Recommended order to build this in Chromium specifically, on a `cross-origin-storage` branch:

1. **Mojo interface + Blink IDL surface**, behind the `CrossOriginStorage` runtime-enabled
   feature: `CrossOriginStorageManager` plus the two dictionaries transcribed from the spec's IDL
   block, and the `NavigatorCrossOriginStorage` mixin on both `Navigator` and `WorkerNavigator`
   via a `Supplement<NavigatorBase>` (which covers windows and workers in one).
2. **Permissions Policy feature + request validation** in the renderer, in that order (decisions
   5, 11). Register in `permissions_policy_features.json5`, the `PermissionsPolicyFeature` enum,
   the UMA enum, and DevTools' `Page.pdl` — that last one is easy to miss and breaks the build.
3. **Browser-side registry** as `BrowserContext` user data, in-memory first (decision 1), with
   entries created only by `verify and store` (decision 7) and the three additive grants
   (decision 8).
4. **`CrossOriginStorageFileHandleImpl` + `CrossOriginStorageFileWriterImpl`** (decisions 2, 3, 6)
   and the three binder registrations (decision 13). At this point a read/write round trip works
   end to end.
5. **Vendor and run the COS WPT suite** — both the `cross-origin-storage/` directory and the
   separately-located `interfaces/cross-origin-storage.idl` that `idlharness.js` fetches, then
   regenerate the manifest. This validates the round trip before more scopes and persistence land
   on top of it.
6. **The three disclosure grants, the additive visibility-upgrade rule, and the
   `Cross-Origin-Storage-Allow-Origin` ceiling** (spec's `determine COS disclosure`,
   `upgrade resource visibility` and `apply a COS scope ceiling`; decisions 8 and 9).
7. **Persistence, storage budget and eviction, the Public Hash List, GREASE'ing, and rate
   limiting** — naturally bundled, since they all touch the registry and write path.
8. **Clear-data integration** (decision 12).
9. **Unit tests** directly against the registry, rate limiter and PHL, with no script or Mojo
   involved — see the Verification plan.
10. **A release build with the feature default-enabled**, packaged so testers can download and run
    it without building Chromium.
11. **The inspection surfaces**, once the registry is stable: a DevTools protocol domain, the
    Application-panel view built on it, and the `chrome://settings` page. Both of them are also
    what finally gives the spec's provenance records a consumer.

## Deferred / follow-up work

What is still open, beyond the architecture above:

- **The declarative integrations are not implemented**: the HTML `crossoriginstorage` attribute,
  the CSS `cross-origin-storage()` modifier, and the JavaScript `crossOriginStorage` import
  attribute. Each is defined in its own host-language specification, and the corresponding WPT
  subdirectories fail accordingly. Only the imperative API works.
- **Provenance has a consumer; the imperative API has nothing to give it.** The record described
  in the spec's
  [Provenance metadata](https://wicg.github.io/cross-origin-storage/#provenance-metadata) section
  is implemented — per-storing-origin, never exposed to script, persisted with the entry,
  discarded with the entry or the origin — and DevTools now surfaces it. But
  `requestFileHandle()` never names a URL, so in practice the records stay empty; the declarative
  integrations are where a meaningful claim would come from. What DevTools does show today is the
  Public Hash List's *own* provenance for a listed hash (which upstream section listed it, which
  source corroborated it, and a URL the bytes were seen at), which is a different thing and comes
  from a companion data file rather than from any writer.
- **The eviction index is still a scan-and-sort.** Running totals for global and per-origin usage
  are maintained incrementally (notes §6), but eviction candidate selection sorts the whole entry
  list per pass rather than walking an index keyed by `(last_read, hash)`. Same known gap Firefox
  documented.
- **Nothing schedules a Public Hash List refresh.** The scripting exists — `--check` compares the
  committed OID against upstream's Git LFS pointer in a few hundred bytes, and a full run
  re-fetches, verifies against the published `.sha256`, and re-packs — but no job runs it. This is
  the inadequate option the notes name, and it is named as such in the directory's own
  `README.chromium` rather than left implicit. Component Updater is the right end state for a
  browser that ships on a milestone cadence.
- **One platform.** Only Linux x86_64 has been built. macOS and iOS cannot be cross-compiled from
  Linux at all; Windows needs a toolchain that a stock checkout does not have; Android needs a
  `target_os` sync and produces an APK.
- **Review prerequisites.** The new `third_party/` directory carrying the ~14 MiB Public Hash
  List needs OWNERS and security review, and the new `.mojom` needs `ipc/SECURITY_OWNERS`
  sign-off — presubmit says so, correctly.
- **The declarative integrations' ceiling is not implemented either.** For a host integration the
  `Cross-Origin-Storage-Allow-Origin` header comes from the *fetched resource's* response rather
  than the loading document's, so the plumbing decision 9 describes covers only the imperative
  API. When the integrations land, the loader is where their ceiling has to be read.

## Risks

- **The inspection surfaces show browsing history to anyone who can open them.** A COS entry
  names every origin that stored or read it, which across the whole registry is a partial
  cross-site browsing record. Both surfaces are trusted, non-web ones and neither is reachable
  from script, but "trusted" is doing real work there: the DevTools protocol command is
  deliberately scoped to one origin rather than listing the whole registry, and the settings page
  is the broader view precisely because it is the user's own.
- **The Public Hash List is a large binary dependency** whose provenance chain runs through
  GitHub's Git LFS media endpoint. The generator verifies it against the checksum published beside
  it, which turns a corrupted or truncated transfer into a build failure rather than
  silently-wrong data shipped to users — but the trust root is still that repository.
- **A stale list fails closed, which is quiet.** If the data file is missing, unreadable or
  malformed, nothing is on the list, so no wildcard-scoped resource is ever shared cross-origin.
  The feature still works; it just silently stops delivering its main benefit. That is the right
  failure direction, but it argues for monitoring rather than trusting silence.
- **Default-enabling changes web-exposed surface**, so interface-listing baselines move. That is
  expected, but it means this branch cannot be diffed cleanly against trunk's expectations without
  those rebaselines.

## Verification plan

- **Unit tests against the registry directly**, with no script or Mojo (notes §12): hash
  validation including path-traversal rejection for every recognized algorithm; all three
  disclosure grants with genuinely distinct origins (same-site sibling, cross-site, listed,
  unlisted, and the explicit-empty-list case); the PHL gate in both directions; GREASE'ing
  asserted as a shape rather than a rate, plus the invariants that a large entry is *never*
  GREASE'd and a storing origin never is; additive visibility upgrades in both directions (a "*"
  write must not cost a listed origin its access, and a list must not withdraw the global grant)
  and merge-time capping; that a create request registers nothing and that a failed write
  therefore removes nothing; ceiling parsing, including that `"*"` and any unparseable token fail
  the whole header closed; that a storing origin is never charged against the probe budget while
  a listed one over budget is refused indistinguishably from a miss; and revoke-and-GC
  clear-data.
- **Persistence tests that span a simulated restart.** The notes warn (§7) that a suite which
  never restarts can stay green while the reload path is completely broken — Firefox shipped
  exactly that bug. Three tests build a registry, drop it, and build a second over the same
  directory: a full round trip of grants, origins lists, storing origins and sizes; an entry whose
  bytes went missing being dropped rather than served; and an off-the-record registry leaving
  nothing behind. The metadata format is versioned, and an older version is migrated in place on
  the next write rather than dropped — deleting a user's stored bytes to gain a metadata field is
  not a trade worth making, and the migration path needs a test of its own for the same reason the
  restart does.
- **The COS WPT suite**, vendored from the in-flight PR. The imperative tests pass across window,
  dedicated worker and shared worker; the service-worker assertions pass by refusing, which is
  what the spec now asks for. The declarative subdirectories fail, as they must, and so does the
  one `probe-budget` subtest that drives the `fetch()` integration.
- **A genuinely cross-origin, PHL-aware browser test.** `public-hash-list.tentative.https.html`
  stores jQuery 3.7.1 — a real entry in the shipped list's core section, with a known preimage —
  wildcard-scoped, and reads it from a cross-site origin, alongside invented content stored at the
  identical scope that must never be disclosed. This is the test that distinguishes a working
  implementation from one that discloses everything or nothing.
- **Interface-listing rebaselines.** Default-enabling adds `CrossOriginStorageManager`,
  `navigator.crossOriginStorage` and `cross-origin-storage` to the `webexposed` listings, in both
  the default and `--stable-release-mode` variants. Worth knowing: `--reset-results` may also
  delete unrelated baselines it judges redundant, which should be reverted rather than carried
  along.
- **Running the packaged build from a clean directory**, not from the build tree, before publishing
  it — the difference between "works on my machine" and "works for a tester" is exactly the set of
  data files that a build directory has and an archive does not.

## Rollout

There is no rollout yet. The change is a stack of Work in Progress Gerrit CLs against
`chromium/src` (see the table under [Context](#context)): public and readable, but explicitly not
ready for review, not reviewed, and not landed. Nothing about it is in Chrome, on any channel, or
behind an origin trial. Chrome does intend to ship this API, so the eventual path runs through the
usual process — landing the CLs, a Chromium feature entry, and an origin trial before any
default-on shipping decision — none of which has started.

For testing without building Chromium, a Linux x86_64 build with the feature enabled by default is
published at [github.com/tomayac/Chromium](https://github.com/tomayac/Chromium). Those are
unofficial developer builds: unsigned, never auto-updating, receiving no security fixes, and built
from this branch rather than from trunk. "Enabled by default" there means "on by default for
anyone who downloads that archive", and nothing more — it is not a statement about Chrome, and the
Deferred work above (declarative integrations, PHL refresh, security review) is what stands
between this and anything shippable.
