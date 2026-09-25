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

### Lookup budget

A cap the explainer proposes on how many cross-site lookups a site may perform
in a time window, on the order of 8 to 16. Lookups for files the requesting site
stored itself stay free. The budget belongs to the top-level site and every
frame on the page draws from it, it persists across reloads and tabs, and it
counts every surface that reaches the cache. Attacks 6 through 8 target those
three properties in turn. See
[Potential mitigations](README.md#potential-mitigations).

### Prevalence

The share of devices holding a given file, which sets what one answer about it
is worth. A file half of devices hold yields the most entropy per query, a
near-universal file yields almost none, and a positive answer on a rare file
carries its surprisal, −log₂ of the prevalence.

## Background

Any party holding a file's bytes can compute its hash and query it, so the
addressable set spans the public web and anything the attacker authors.

Almost every attack below runs on the global scope, the one under which an
origin with no prior relationship to an entry learns that it exists. A tracker
cannot approximate the web with an explicit list, and the same-site default
carries nothing across a site boundary. Attack 1 supplies the two exceptions,
and each costs the tracker something every participating site has to supply: its
embedded frame reads back its own entries as a storing origin, which takes
`allow="cross-origin-storage"` from each site, and its list-scoped variant takes
a response header from the writing site naming the reading one.

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
back, which makes the cache a **supercookie**. Attacks 2 through 5 and Attacks 8
through 10 are **XS-Leaks** over the existence oracle the cache exposes. Attacks
6 and 7 target the rate limiting that constrains the rest. The last two are the
ones the current design already answers, and they appear here because relaxing
either property would reopen them.

## Attack 1: Supercookie

### Objective

The objective is to recognize the same device across unrelated sites, through an
identifier the tracker plants and later reads back.

### Description

The tracker picks a set of small files and stores a per-device subset on the
first site, one bit per file. A query for the same set on a second site recovers
the subset. Eviction and the per-origin storage limit bound its lifetime and
size, and the tracker refreshes it on each visit.

The tracker can do this in three ways.

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
   // One hit or miss per hash, and those 32 answers are the identifier.
   let bits = await Promise.all(trackerHashes.map(has));

   // Nothing came back, so this is a new device. Mint an identifier and
   // store the file for each bit that is set, fetching bytes only for those.
   if (!bits.includes(true)) {
     bits = randomBits(trackerHashes.length);
     for (const [i, hash] of trackerHashes.entries()) {
       if (!bits[i]) continue;
       const handle = await cos.requestFileHandle(hash, { create: true });
       const w = await handle.createWritable();
       await w.write(await loadTrackerFile(i));
       await w.close();
     }
   }

   const id = bits.join(''); // '10110…'
   ```

   **Example.** A tracker's frame on a news site finds nothing stored, mints a
   32-bit identifier, and stores its own files for the bits that are set. A week
   later the same frame on an unrelated shopping site reads those 32 hashes
   back, recovers the pattern, and attributes both visits to one device.

2. **Through the Public Hash List.** A tracker running as the site's own script
   writes under that site's origin, unreadable elsewhere. Reaching it from a
   second site requires [Public Hash List](public-hash-list/phl-explainer.md)
   hashes written with `origins: '*'`. The tracker therefore carries the
   identifier in a subset of listed files that are small and, despite being on
   the PHL, comparatively rare. This variant is noisier: organic cache hits
   produce false positives, and GREASE'ing produces false negatives, so the
   tracker adds redundancy.

   ```js
   // Same `cos` and `has()` as above. The carriers have to be on the PHL, so
   // the tracker picks small ones that few devices are likely to hold.
   const phlHashes = [
     { algorithm: 'SHA-256', value: 'e3b0…' },
     // …31 or more, for redundancy
   ];

   // Runs as each site's own script. The read reaches entries another site
   // wrote, because the global scope covers unrelated origins.
   let bits = await Promise.all(phlHashes.map(has));

   // Organic cache hits set a few bits on any device, so the test for an
   // unmarked device relies on the redundancy the identifier carries.
   if (!looksMarked(bits)) {
     bits = randomBits(phlHashes.length);
     for (const [i, hash] of phlHashes.entries()) {
       if (!bits[i]) continue;
       // `origins: '*'` is what the next site's read needs, and the browser
       // only honors it for hashes on the Public Hash List.
       const opts = { create: true, origins: '*' };
       const handle = await cos.requestFileHandle(hash, opts);
       const w = await handle.createWritable();
       await w.write(await loadPhlFile(i));
       await w.close();
     }
   }
   ```

   **Example.** The same two visits, with the tracker running as each site's own
   script and the carriers drawn from the PHL.

3. **Through the list scope.** The tracker authors the carrier files itself, so
   their hashes exist nowhere else and no organic cache hit can fake a positive.
   A minted hash never reaches the PHL, so the global scope is closed to it, and
   the list scope carries the read instead: it works for any hash, and
   GREASE'ing leaves it alone. The tracker runs first-party on both sites, so no
   frame and no `allow="cross-origin-storage"` is involved.

   Two things bound it. Site A's write has to name site B ahead of time, and the
   declared list is intersected with what site A's own
   [`Cross-Origin-Storage-Allow-Origin`](README.md#the-cross-origin-storage-allow-origin-header)
   response header authorizes, which injected script cannot forge. That list is
   capped at a handful of origins, so a tracker can wire up a few site pairs
   this way and nothing resembling a network.

   ```js
   // The tracker's own files, so these hashes exist nowhere else on the web.
   const mintedHashes = [
     { algorithm: 'SHA-256', value: 'b40d…' },
     // …31 more
   ];

   // On site A, as site A's own origin: mint the identifier and name site B as
   // the one origin allowed to read it back.
   const bits = randomBits(mintedHashes.length);
   const opts = { create: true, origins: ['https://siteb.example'] };
   for (const [i, hash] of mintedHashes.entries()) {
     if (!bits[i]) continue;
     const handle = await cos.requestFileHandle(hash, opts);
     const w = await handle.createWritable();
     await w.write(await mintTrackerFile(i));
     await w.close();
   }
   ```

   ```js
   // Later on site B, first-party as https://siteb.example, the origin site A
   // named. The answers are noiseless, because nobody else holds these bytes.
   const recovered = await Promise.all(mintedHashes.map(has));
   ```

   **Example.** `newspaper.example` and `magazine.example` belong to one
   publisher, which is what lets the newspaper's response header authorize the
   magazine's origin. A reader marked while reading the newspaper is recognized
   on the magazine, with no shared cookie and no frame on either site.

## Attack 2: Cache-based fingerprinting

### Objective

The objective is to recognize the same device across unrelated sites, through
the files it already happens to hold.

### Description

The distinguishing signal is whatever the device accumulated through ordinary
browsing. The tracker writes nothing.

Entropy per query peaks at a prevalence near one half, so near-universal files
contribute nothing and the informative ones are those roughly half of devices
hold. Enough of them yield a pattern unique to a device, supporting cross-site
linking. Correlated files reduce the yield, since a font family's subsets and a
model's shards arrive together and are effectively one observation.

```js
// Same `cos` and `has()` as above. Nothing is written, so the probe set is
// chosen purely for yield: PHL hashes the tracker measured near one half
// prevalence on its own panel, and one file per correlated family, so that a
// font's subsets do not count as several observations.
const probes = [
  { algorithm: 'SHA-256', value: 'c1f5…' },
  // …59 more
];

// The pattern of hits is the fingerprint. The same script on another site
// computes it again and compares.
const fingerprint = (await Promise.all(probes.map(has))).join('');
```

Reliability is lower than Attack 1, because the tracker works with whatever the
device holds. It needs no cooperation from the embedding sites beyond script
inclusion, and it leaves nothing a user could find or clear.

### Example

The same analytics script on a recipe blog and a local newspaper queries the
same 60 libraries and fonts. The patterns match across both visits, so the
script attributes them to one device and merges the browsing records.

## Attack 3: Attribute inference

### Objective

The objective is to assign the user to a targeting cohort, with no identifier
involved at any point.

### Description

Files carry semantics: a Japanese font subset implies a reading language, a game
engine implies browser gaming, a speech model implies dictation, and a model
shipped by one application implies use of that application. Presence alone
assigns the cohort.

```js
// Same `has()` as above. Each probe is picked for what holding the file
// implies about the user, and carries the attribute it evidences.
const semantics = [
  { value: 'd31b…', attribute: 'runs local inference' },
  { value: '6ea0…', attribute: 'reads Japanese' },
  // …6 more
];

// The positives are the cohort. Nothing is written, and nothing here
// separates this device from any other holding the same files.
const cohort = [];
for (const { value, attribute } of semantics) {
  if (await has({ algorithm: 'SHA-256', value })) cohort.push(attribute);
}
```

Sensitivity varies with the file. A model distributed by a mental health or
addiction support application supports a strong inference about the user, and
the browser has no basis for distinguishing that query from a query for a font.
Keeping such a model off the global scope is the PHL's job.

### Example

An advertising script queries eight in-browser AI models and finds one,
establishing that the device runs local inference. A query for the Japanese
subset of a common font is also positive, establishing a language attribute.
Eight lookups, two accurate targeting attributes, no identifier.

## Attack 4: History sniffing

### Objective

The objective is to establish that a device visited one particular site, with no
cooperation from that site.

### Description

The attacker starts on the target site. Loading `game67.example` and recording
which COS-eligible resources it fetches yields the candidate hashes, and mapping
where else each of those is deployed yields the roster that later answers are
read against.

`game67.example` is built with a popular game engine, and the tracker has
observed about 200 games shipping the same engine build. A probe on that hash
comes back positive, which places the device on one of those 200 and stays
silent about which. That same answer already supports the weaker claim of Attack
3, that this is someone who plays browser games. Naming the site takes more
probes.

Composing probes narrows it, and every file probed is widely deployed in its own
right, so each one passes PHL admission. `game67.example` also embeds a cookie
banner library served identically to some 2,000 pages, three of them among the
200 games. A positive on that hash leaves `game12.example`, `game67.example`,
and `game88.example`. A third probe, on an ad SDK bundle present on thousands of
pages and used by `game67.example`, leaves one. Each positive is also consistent
with an unrelated visit elsewhere, so the result is evidence short of proof,
sharpening the fewer sites a person visits. Per-resource k-anonymity carries no
guarantee over conjunctions.

Building that roster is the expensive half, since an answer about contents says
nothing about a site until a deployment map names the sites. Trackers assemble
one from what their own script sees load across the sites carrying it, and from
public crawls like the [HTTP Archive](https://httparchive.org/) and
[Common Crawl](https://commoncrawl.org/), neither of them complete, so a map
understates where a file appears.

```js
// Same `cos` and `has()` as above. Each probe is a file whose deployment the
// tracker mapped beforehand, so a hit says the device visited at least one
// origin in that set. Every one of these files is widely deployed, so each
// passes PHL admission. The sets are truncated here.
const engineGames = ['https://game1.example', 'https://game67.example'];
const cookieBanner = ['https://game12.example', 'https://game67.example'];
const adSdk = ['https://game67.example', 'https://shop.example'];

const deployments = new Map([
  ['a7c2…', engineGames], // the engine build, about 200 games
  ['9f04…', cookieBanner], // the cookie banner library, some 2,000 pages
  ['5b31…', adSdk], // an ad SDK bundle, thousands of pages
]);

const hits = [];
for (const [value, sites] of deployments) {
  if (await has({ algorithm: 'SHA-256', value })) hits.push(sites);
}

// The overlap is the shortest history consistent with every hit, here just
// `game67.example`. It is a hypothesis: visits to a different site in each
// set produce the same answers, so the tracker weighs that against how much
// it expects this device to browse.
const overlap = hits.length
  ? hits.reduce((a, b) => a.filter((site) => b.includes(site)))
  : [];
```

### Example

An ad network's script on an unrelated news site runs the three probes and gets
three positives. It records the reader as having been on `game67.example`, a
site that never loaded that script and never consented to the disclosure.

## Attack 5: Targeted de-anonymization

### Objective

The objective is to decide whether an anonymous visitor is one specific person
the attacker already knows.

### Description

What matters here is how much a single positive answer tells the attacker. A hit
on a file that one device in ten thousand holds carries about 13 bits, and a hit
on a file most devices hold carries almost none. Where a tracker knows that a
specific person holds an unusual file, observed during an authenticated session,
one query elsewhere approximates a test for that person.

Large AI models suit this well. Few devices hold any given one, they persist
across long intervals, and the size-proportionate rule withholds GREASE'ing from
files whose spurious re-download would be disproportionate, so the answer is
noise-free exactly where it is most identifying.

```js
// Same `has()` as above. A single hash, recorded while the person was signed
// in on another property the same operator runs: a model held by a few
// thousand devices worldwide, so its prevalence is around 10⁻⁴.
const target = { algorithm: 'SHA-256', value: '0b8e…' };

// On an unauthenticated page, a positive answer is some 13 bits of evidence
// that this is the same person. The file is large enough that the
// size-proportionate rule withholds GREASE'ing, so the answer carries no
// noise.
if (await has(target)) linkToAccount(knownAccount);
```

### Example

A researcher's work involves an uncommon medical imaging model that a few
thousand devices worldwide hold, so their browser has it stored. The attacker
runs a forum where that researcher is suspected of posting anonymously, and adds
one probe for the model's hash to the pages the account is reading. It comes
back positive, which is substantial grounds for tying the account to the
researcher.

## Attack 6: Sybil attack on the budget

### Objective

The objective is to spend more lookups than the budget allows, by presenting as
several origins at once.

### Description

A [Sybil attack](https://doi.org/10.1007/3-540-45748-8_24) is one party posing
as many, which defeats any quota that assumes one allowance per participant.
Here the attacker multiplies a budget keyed to the requesting origin by the
number of origins it brings. Wildcard DNS makes subdomains free, so one tracker
presents as several origins, embeds each as a frame, partitions the work, and
collects the answers in the parent through `postMessage`. Independent trackers
on one page can pool allowances the same way, making this collusion as well as
Sybil.

The orchestrator page embeds one frame per origin.

```html
<!-- Four attacker-controlled subdomains, so four separate allowances. -->
<iframe src="https://a0.tracker.example/" allow="cross-origin-storage"></iframe>
<iframe src="https://a1.tracker.example/" allow="cross-origin-storage"></iframe>
<!-- …a2 and a3 -->
```

Each frame spends its own origin's whole allowance on a disjoint slice.

```js
// `n` is this frame's index, 0 through 3, over the same `probes` as Attack 2.
const mine = probes.slice(n * 8, n * 8 + 8);
parent.postMessage(await Promise.all(mine.map(has)), '*');
```

The orchestrator reassembles 32 answers out of four allowances of eight.

```js
const answers = [];
addEventListener('message', (e) => answers.push(...e.data));
```

### Example

At eight lookups per origin per window, four frames on four attacker-controlled
subdomains spend eight each on disjoint sets, yielding 32 answers in one page
view. This is why the explainer keys the budget to the top-level site, shared
across every frame.

## Attack 7: Rate-limit evasion by reload

### Objective

The objective is to spend more lookups than the budget allows, by resetting the
counter that holds it.

### Description

A counter bound to a context the attacker controls is a counter the attacker
resets. A page reloads itself without user interaction, and a per-page-load
allowance is fresh on each load.

```js
// Spend this load's allowance on a slice of the same `probes` as Attack 2,
// stash what came back, and reload for a fresh one. Four loads inside two
// seconds cover all 32.
const round = Number(sessionStorage.round ?? 0);
const mine = probes.slice(round * 8, round * 8 + 8);

sessionStorage.setItem(round, JSON.stringify(await Promise.all(mine.map(has))));
sessionStorage.round = round + 1;
if (round < 3) location.reload();
```

### Example

At eight lookups per page load, four silent reloads inside two seconds yield 32
answers. This is why the count has to persist across reloads and navigations.

## Attack 8: Cross-site leak by combining COS integration points

### Objective

The objective is to obtain lookups the budget never counts, by spreading them
across the COS integration points that return nothing to the page.

### Description

The imperative API is one of four COS integration points. The
[HTML](README.md#html-integration),
[import attribute](README.md#javascript-import-attribute-integration),
[CSS](README.md#css-integration), and [fetch](README.md#fetch-integration)
integrations consult the cache as well, and return no value to the page.

The site recovers the bit from its own server logs, the standard XS-Leak pattern
of reading a side effect in place of a return value: a cache hit produces no
request, and that silence is the same bit.

```html
<!-- No COS call anywhere on the page. Ordinary references consult the same
     cache, one per bit. -->
<link
  rel="stylesheet"
  href="https://tracker.example/p0.css"
  integrity="sha256-YWJj…"
  crossoriginstorage="*"
/>
<!-- …31 more, p1 through p31 -->
```

```js
// On the tracker's own server, where each of the same 32 `probes` as Attack 2
// has its own path: a request for p7.css means the device lacked that file,
// and silence means it held it. The page never sees the answer.
const bits = probes.map((probe) => !requestLog.has(probe.path));
```

### Example

A tracker places 32 ordinary resource references on its page and records which
of them reach its server. The eleven producing no request are the files the
device already held. Thirty-two answers, no call to `requestFileHandle()`. This
is why a budget has to count all four integration points.

## Attack 9: Existence oracle through in-progress writes

### Objective

The objective is to learn whether the device holds a given file in exactly the
cases where a read refuses to say: the requesting origin is out of scope, the
hash is not on the Public Hash List, or GREASE'ing withheld the answer.

### Description

A read has to clear three checks: the sharing scope must cover the requesting
origin, the global scope additionally requires PHL membership, and GREASE'ing
can still withhold a positive. A write has to clear none of them, because
storing bytes discloses nothing by itself. Anything the write path lets through
about the registry is therefore an answer to the question those three checks
exist to control, delivered without noise, for any hash the attacker names.

Asking to create costs nothing and supplies no bytes. A browser that consulted
the registry on that call, or registered a placeholder that a later read could
tell apart from "never stored", would answer differently for a hash the device
already holds, and that difference is the oracle.

COS adds an entry only after a writer supplies the complete contents and the
browser verifies them against the hash, and `requestFileHandle()` with
`create: true` neither reads nor writes the registry. Until an entry is
complete, the hash reads as absent, identically to one never written.

```js
// Same `cos` as above. Whoever stored this file named a short list of partner
// origins, and this attacker is not one of them, so an ordinary read refuses.
const target = { algorithm: 'SHA-256', value: '7f2e…' };

// Creating names the same hash and applies no scope, PHL, or GREASE'ing
// check, so it is the only path left.
const handle = await cos.requestFileHandle(target, { create: true });
await handle.createWritable(); // nothing written, nothing closed

// A design that consulted the registry on either call would have to answer
// differently for a hash the device already holds, and that is the oracle.
```

### Example

A bank stores a WebAssembly transaction-signing module, naming its own origins
and its payment partner's, so a read from anywhere else refuses outright and the
PHL never enters into it. An unrelated site asks to create that same hash and
supplies no bytes. Under a placeholder design, the answer to that request
differs from the answer for a hash nobody holds, and the site learns that this
device belongs to a customer of that bank, which is what a phishing campaign
needs to pick its targets. COS answers identically either way.

## Attack 10: Timing side channel

### Objective

The objective is to read the answer a refusal withholds, out of how long the
refusal takes.

### Description

A refusal that resolved faster for a genuinely absent file than for a withheld
one would disclose the answer through elapsed time and bypass everything above.
Timing is the most common substrate for XS-Leaks on the web.

COS requires the refusal to be identical in content and timing across all of its
causes: absent, out of scope, or withheld.

```js
// Same `cos` as above. Every one of these rejects, so the returned value
// carries nothing and the elapsed time is all the attacker has to work with.
const time = async (hash) => {
  const t = performance.now();
  await cos.requestFileHandle(hash).catch(() => {});
  return performance.now() - t;
};
```

### Example

A tracker times a few hundred refusals for a hash GREASE'ing may be withholding
and a few hundred for a hash the device certainly lacks. A difference in the two
distributions would recover the bit that the refusal was designed to hide, and
averaging over repetitions would recover it however small the difference is.

## The mitigation problem

Every attack here passes through one API. A tracker working from timing
variation or accumulated platform quirks has many places to hide; a tracker
using COS has to issue an explicit, countable request that the browser can
count, delay, or decline.

That is what makes the problem tractable, and it locates the difficulty
precisely. The protection is worth exactly what the accounting is worth, which
is why Attacks 6 through 8 warrant the same attention as the identification
attacks above them.
