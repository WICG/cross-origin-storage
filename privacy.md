<!--
  Copyright 2026 Google LLC
  SPDX-License-Identifier: Apache-2.0
-->

# Privacy and Cross-Origin Storage

[Cross-Origin Storage](README.md) (COS) is a content-addressable cache shared
across origins. COS identifies a file by the cryptographic hash of its contents,
with no reference to where those contents came from, so identical bytes converge
on a single entry however each site obtained them. The hash doubles as an
integrity guarantee: the browser verifies the bytes against it at write time, so
a site can use an entry some other origin stored without having to trust that
origin. A site requests a file by hash, and the browser serves it without a
network request when _(i)_ it already has bytes matching that hash, and _(ii)_
the entry's grants permit the requesting origin to see them.

The benefit is the elimination of redundant downloads. A file fetched on one
site is available immediately on the next, reducing bandwidth, load latency,
disk usage, and energy consumption. Typical candidates are AI models,
WebAssembly modules, JavaScript libraries, game engines, and web fonts.

The cache is unpartitioned by design, which is where both the benefit and the
exposure come from. Whether a given hash is present depends on which other sites
the user visited and what those sites stored, so every answer crosses a site
boundary.

**Mitigations need to carefully balance between ensuring the user's privacy and
maintaining the usefulness of the feature.** Restrictions severe enough to
eliminate every attack described here would also eliminate the sharing that
motivates the feature. This document covers the attacks; the mitigations COS
proposes are in the [Privacy considerations](README.md#privacy-considerations)
section of the explainer.

## Glossary

### Sharing scope

The `origins` value a write declares, which decides who can later learn that the
entry exists. A storing origin can always read back what it wrote, mirroring the
Cache API, and that access needs no declaration. The grants add up and are never
removed, so a scope only ever widens. See [COS entry](README.md#cos-entry) and
[Availability gating](README.md#availability-gating). A write declares one of
three scopes.

- **Same-site scope.** The default, which a write selects by passing no
  `origins` value. Same-site origins of a storing origin can read the entry.

  ```js
  await navigator.crossOriginStorage.requestFileHandle(hash, { create: true });
  ```

- **List scope.** Only the named origins can read the entry, whether or not the
  hash is on the PHL. The list is capped in length and bounded by the
  byte-supplying origin's
  [`Cross-Origin-Storage-Allow-Origin`](README.md#the-cross-origin-storage-allow-origin-header)
  header.

  ```js
  await navigator.crossOriginStorage.requestFileHandle(hash, {
    create: true,
    origins: ['https://calculate.example', 'https://write.example'],
  });
  ```

- **Global scope.** Any origin can read the entry, provided the hash is on the
  PHL. GREASE'ing may still withhold it.

  ```js
  await navigator.crossOriginStorage.requestFileHandle(hash, {
    create: true,
    origins: '*',
  });
  ```

### Public Hash List (PHL)

A shared, vendor-neutral allowlist of hashes for resources deployed widely
enough that confirming their presence says nothing about an individual. That
k-anonymity argument is settled once, when a hash is admitted, so the browser
never repeats it at query time. It gates the global scope alone. See the
[PHL explainer](public-hash-list/phl-explainer.md).

### GREASE'ing

The browser occasionally reporting a file as absent although it holds it, so a
site cannot read a negative answer as proof of absence. It applies only to reads
that qualify through the global scope, and browsers withhold it for files whose
size would make a spurious re-download disproportionate. See the
[explainer's GREASE'ing section](README.md#greaseing).

## Background

Any party holding a file's bytes can compute its hash and query it, so the
addressable set spans the public web and anything the attacker authors.

Almost every attack below runs on the global scope, the only one under which an
unrelated origin learns that an entry exists. The narrower scopes carry nothing
across a site boundary, and a tracker can neither approximate the web with an
explicit list nor name origins the operator never authorized. Attack 1's
embedded frame is the exception: it reads back its own entries as a storing
origin, which is why it needs `allow="cross-origin-storage"` from each embedding
site.

Each COS lookup (or probe) returns one bit. Roughly **32 bits index a population
of several billion**, since 2³² is about 4.3 billion. That is the scale every
attack below accumulates toward and every mitigation tries to bound. How much an
attacker reaches in practice is an empirical question:
[Gómez-Boix et al.](https://doi.org/10.1145/3178876.3186097) (WWW 2018) analyzed
2,067,942 browser fingerprints from a top-15 French website and found 33.6% of
them unique, against the rates above 80% that earlier, self-selected samples had
reported. [Pugliese et al.](https://doi.org/10.2478/popets-2020-0041)
(PoPETs 2020) followed 1,304 users for three years with ground truth at the user
level and found 67.6% to 93.1% of them trackable, depending on the device split
and feature set, with trackable fingerprints staying stable for a mean of 3.1 to
3.4 weeks.

Attack 1 is stateful tracking: the tracker writes the identifier and reads it
back, which makes the cache a **supercookie**. Attacks 2 through 5 and Attack 8
are **XS-Leaks** over the existence oracle the cache exposes. Attacks 6 and 7
target the rate limiting that constrains the rest.

---

## Attack 1: Supercookie

The tracker picks a set of small files and stores a per-device subset on the
first site, one bit per file. A query for the same set on a second site recovers
the subset. Clearing cookies has no effect, since the identifier lives in the
shared cache. Eviction and the per-origin storage limit bound its lifetime and
size, and the tracker refreshes it on each visit.

The tracker can do this in two ways.

1. **Through an embedded frame.** Both sites embed an iframe from
   `tracker.example` and grant it `allow="cross-origin-storage"`, so the tracker
   writes under its own origin. A storing origin can always read its own
   entries, so the recovery bypasses the Public Hash List, GREASE'ing, and the
   `origins` grants entirely.

   ```html
   <!-- On every embedding site. -->
   <iframe src="https://tracker.example/" allow="cross-origin-storage"></iframe>
   ```

   ```js
   // Inside the frame, so every call runs as tracker.example, on every site.
   const cos = navigator.crossOriginStorage;
   const has = async (h) => !!(await cos.requestFileHandle(h).catch(() => 0));

   // One small file the tracker serves per bit of the identifier.
   const trackerHashes = [
     { algorithm: 'SHA-256', value: '4d7a…' },
     // …31 more
   ];

   // Read first: a storing origin sees whatever it stored on any earlier site.
   const bits = await Promise.all(trackerHashes.map(has));
   let id = bits.reduce((n, b, i) => n | (b << i), 0) >>> 0;

   // Nothing came back, so this is a new device. Mint an identifier and
   // store the file for each bit that is set, fetching bytes only for those.
   if (id === 0) {
     id = crypto.getRandomValues(new Uint32Array(1))[0];
     for (const [i, hash] of trackerHashes.entries()) {
       if (!((id >>> i) & 1)) continue;
       const handle = await cos.requestFileHandle(hash, { create: true });
       const w = await handle.createWritable();
       await w.write(await loadTrackerFile(i));
       await w.close();
     }
   }
   ```

2. **Through the Public Hash List.** A tracker running as the site's own script
   writes under that site's origin, unreadable elsewhere. Reaching it from a
   second site requires globally readable entries, meaning
   [Public Hash List](public-hash-list/phl-explainer.md) hashes written with
   `origins: '*'`. The codeword is therefore a subset of well-known public
   files. This variant is noisier: organic cache hits produce false positives,
   and GREASE'ing produces false negatives, so the tracker adds redundancy.

   ```js
   // Same cos, has, and id as above, but the carriers have to be on the PHL,
   // so the tracker picks well-known public files and serves their real bytes.
   const phlHashes = [
     { algorithm: 'SHA-256', value: 'e3b0…' },
     // …31 more
   ];

   // Site A, as the site's own origin: the global scope is what makes the
   // entry readable from anywhere else.
   for (const [i, hash] of phlHashes.entries()) {
     if (!((id >>> i) & 1)) continue;
     const opts = { create: true, origins: '*' };
     const handle = await cos.requestFileHandle(hash, opts);
     const w = await handle.createWritable();
     await w.write(await loadPhlFile(i));
     await w.close();
   }

   // Site B, a different origin: the read succeeds through the global scope,
   // which only applies to hashes on the Public Hash List.
   const bits = await Promise.all(phlHashes.map(has));
   ```

**Example.** A tracker on a news site stores 32 files, selecting the subset at
random for this device. A week later, on an unrelated shopping site, it queries
those 32 hashes, recovers the subset, and links the visits. Cookie clearing in
the interval is irrelevant.

---

## Attack 2: Cache-based fingerprinting

The distinguishing signal is the set of files the device accumulated through
ordinary browsing. The tracker writes nothing.

Entropy per query peaks at a prevalence (the share of devices holding a given
file) near one half, so near-universal files contribute nothing and the
informative ones are those roughly half of devices hold. Enough of them yield a
pattern unique to a device, supporting cross-site linking. Correlated files
reduce the yield, since a font family's subsets and a model's shards arrive
together and are effectively one observation.

**Example.** The same analytics script on a recipe blog and a local newspaper
queries the same 60 libraries and fonts. The patterns match across both visits,
so the script attributes them to one device and merges the browsing records.

Reliability is lower than Attack 1, because the tracker works with whatever the
device holds. It needs no cooperation from the embedding sites beyond script
inclusion, and it leaves nothing a user could find or clear.

---

## Attack 3: History sniffing

The cache-based analogue of the `:visited` leaks, over file presence in place of
link styling.

A hash deployed across two hundred sites narrows history to those two hundred, a
k-anonymity bound of 200. Composition erodes it: where one file appears on two
hundred hobby blogs and another on two hundred sites covering a region, holding
both narrows the candidates to the intersection. Per-resource k-anonymity gives
no guarantee over conjunctions.

**Example.** A hobby-blog plugin ships a distinctive stylesheet deployed on
roughly three hundred sites, establishing that the device visited one of them. A
second query, for a file specific to a German-language theme, is also positive.
Four sites deploy both, so the tracker narrows the history to four candidates.

---

## Attack 4: Attribute inference

The tracker establishes no identifier, which is what makes this resistant to
every mitigation aimed at identifiers. Files carry semantics: a Japanese font
subset implies a reading language, a game engine implies browser gaming, a
speech model implies dictation, and a model shipped by one application implies
use of that application. Presence alone assigns the cohort.

**Example.** An advertising script queries eight in-browser AI models and finds
one, establishing that the device runs local inference. A query for the Japanese
subset of a common font is also positive, establishing a language attribute.
Eight lookups, two accurate targeting attributes, no identifier.

Sensitivity varies with the file. A model distributed by a mental health or
addiction support application supports a strong inference about the user, and
the browser has no basis for distinguishing that query from a query for a font.

---

## Attack 5: Targeted de-anonymization

The relevant quantity here is surprisal: a positive answer on a hash with
prevalence 10⁻⁴ carries 13 bits. Where a tracker knows a specific person holds
an unusual file, observed during an authenticated session, one query elsewhere
approximates a test for that person.

Large AI models suit this well. Few devices hold any given one, they persist
across long intervals, and the size-proportionate rule withholds GREASE'ing from
files whose spurious re-download would be disproportionate, so the answer is
noise-free exactly where it is most identifying.

**Example.** A researcher signs in to a specialist site and fetches an uncommon
medical imaging model held by a few thousand devices worldwide. The same
operator later queries that hash on an unauthenticated forum, gets a positive,
and has substantial grounds to associate the forum account with the
authenticated identity.

---

## Attacks against the lookup budget

The explainer proposes bounding the number of cross-site lookups a site may
perform. These three attacks target that bound.

### Attack 6: Sybil attack on the budget

An attacker multiplies a budget keyed to the requesting origin by the number of
origins it brings. Wildcard DNS makes subdomains free, so one tracker presents
as several origins, embeds each as a frame, partitions the work, and collects
the answers in the parent through `postMessage`. Independent trackers on one
page can pool allowances the same way, making this collusion as well as Sybil.

**Example.** At eight lookups per origin per window, four frames on four
attacker-controlled subdomains spend eight each on disjoint sets, yielding 32
answers in one page view. This is why the explainer keys the budget to the
top-level site, shared across every frame.

### Attack 7: Rate-limit evasion by reload

A counter bound to a context the attacker controls is a counter the attacker
resets. A page reloads itself without user interaction, and a per-page-load
allowance is fresh on each load.

**Example.** At eight lookups per page load, four silent reloads inside two
seconds yield 32 answers. This is why the count has to persist across reloads
and navigations.

### Attack 8: Cross-site leak through the loading path

The imperative API is one of four paths to the cache. The
[HTML](README.md#html-integration),
[import attribute](README.md#javascript-import-attribute-integration),
[CSS](README.md#css-integration), and [fetch](README.md#fetch-integration)
integrations consult it as well, and return no value to the page.

The site recovers the bit from its own server logs, the standard XS-Leak pattern
of reading a side effect in place of a return value: a cache hit produces no
request, and that silence is the same bit.

**Example.** A tracker places 32 ordinary resource references on its page and
records which of them reach its server. The eleven producing no request are the
files the device already held. Thirty-two answers, no call to
`requestFileHandle()`. This is why a budget has to count all four surfaces.

---

## Attacks the design rules out

Both appear here because relaxing these properties would reopen them.

### Existence oracle through in-progress writes

Registering an entry when a write begins would let any origin distinguish "write
in progress" from "never stored," a noiseless one-bit oracle over an arbitrary
hash, obtained without storing bytes for the storage limit to bound and without
passing `origins`, the Public Hash List, or GREASE'ing.

COS adds an entry only after a writer supplies the complete contents and the
browser verifies them against the hash. Until then the hash reads as absent,
identically to one never written.

### Timing side channel

A refusal that resolved faster for a genuinely absent file than for a withheld
one would disclose the answer through elapsed time and bypass everything above.
Timing is the most common substrate for XS-Leaks on the web.

COS requires the refusal to be identical in content and timing across all of its
causes: absent, out of scope, or withheld.

---

## The mitigation problem

Every attack here passes through one API. A tracker working from timing
variation or accumulated platform quirks has many places to hide; a tracker
using COS has to issue an explicit, countable request that the browser can
count, delay, or decline.

That is what makes the problem tractable, and it locates the difficulty
precisely. The protection is worth exactly what the accounting is worth, which
is why Attacks 6 through 8 warrant the same attention as the identification
attacks above them.
