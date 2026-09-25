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

### Prevalence

The share of devices holding a given file, which sets what one answer about it
is worth. A file half of devices hold yields the most entropy per query, a
near-universal file yields almost none, and a positive answer on a rare file
carries its surprisal, −log₂ of the prevalence.

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
the subset. Eviction and the per-origin storage limit bound its lifetime and
size, and the tracker refreshes it on each visit.

**Example.** A tracker on a news site stores 32 files, selecting the subset at
random for this device. A week later, on an unrelated shopping site, it queries
those 32 hashes, recovers the subset, and links the visits.

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

---

## Attack 2: Cache-based fingerprinting

The distinguishing signal is the set of files the device accumulated through
ordinary browsing. The tracker writes nothing.

Entropy per query peaks at a prevalence near one half, so near-universal files
contribute nothing and the informative ones are those roughly half of devices
hold. Enough of them yield a pattern unique to a device, supporting cross-site
linking. Correlated files reduce the yield, since a font family's subsets and a
model's shards arrive together and are effectively one observation.

**Example.** The same analytics script on a recipe blog and a local newspaper
queries the same 60 libraries and fonts. The patterns match across both visits,
so the script attributes them to one device and merges the browsing records.

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

---

## Attack 3: History sniffing

The cache-based analogue of the `:visited` leaks, over file presence in place of
link styling.

A hash deployed across two hundred sites narrows history to those two hundred, a
k-anonymity bound of 200. Composition erodes it: where one file appears on two
hundred hobby blogs and another on two hundred sites covering a region, holding
both narrows the candidates to the intersection. Per-resource k-anonymity gives
no guarantee over conjunctions.

**Example.** A game engine ships a distinctive WebAssembly build deployed on
roughly three hundred sites, establishing that the device visited one of them. A
second query, for a German-language UI pack, is also positive. Four sites deploy
both, so the tracker narrows the history to four candidates. The cohort the same
two answers imply, a German-speaking player, is Attack 4.

```js
// Same `cos` and `has()` as above. Each probe is a file whose deployment the
// tracker crawled, so a hit maps to the origins known to serve it. Narrow
// deployments are what pay off here.
const deployments = new Map([
  // ~300 sites embedding the same build of one game engine.
  ['a7c2…', ['https://play.example', 'https://arcade.example']],
  // ~200 sites shipping the engine's German-language UI pack.
  ['9f04…', ['https://spiele.example', 'https://arcade.example']],
]);

// Every hit constrains the history further, and the intersection of the
// matched sets is the candidate list: here, the German-language sites
// running that engine.
let candidates = null;
for (const [value, sites] of deployments) {
  if (!(await has({ algorithm: 'SHA-256', value }))) continue;
  candidates = candidates?.filter((site) => sites.includes(site)) ?? sites;
}
```

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

```html
<!-- Four attacker-controlled subdomains, so four separate allowances. -->
<iframe src="https://a0.tracker.example/" allow="cross-origin-storage"></iframe>
<iframe src="https://a1.tracker.example/" allow="cross-origin-storage"></iframe>
<!-- …a2 and a3 -->
```

```js
// In each frame, spending that origin's whole allowance on a disjoint slice
// of the same `probes` as Attack 2. `n` is the frame's index, 0 through 3.
const mine = probes.slice(n * 8, n * 8 + 8);
parent.postMessage(await Promise.all(mine.map(has)), '*');

// In the parent, reassembling 32 answers out of four allowances of eight.
const answers = [];
addEventListener('message', (e) => answers.push(...e.data));
```

### Attack 7: Rate-limit evasion by reload

A counter bound to a context the attacker controls is a counter the attacker
resets. A page reloads itself without user interaction, and a per-page-load
allowance is fresh on each load.

**Example.** At eight lookups per page load, four silent reloads inside two
seconds yield 32 answers. This is why the count has to persist across reloads
and navigations.

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
