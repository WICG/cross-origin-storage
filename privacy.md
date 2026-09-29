<!--
  Copyright 2026 Google LLC
  SPDX-License-Identifier: Apache-2.0
-->

# Privacy and Cross-Origin Storage

[Cross-Origin Storage](README.md) (COS) is a content-addressable cache shared
across origins. COS identifies a file by the cryptographic hash of its contents,
with no reference to where those contents came from. The hash doubles as an
integrity guarantee: the browser verifies the bytes against it at write time, so
a site can use an entry some other origin stored without having to trust that
origin. A site requests a file by hash, and the browser serves it without a
network request when _(i)_ it already has bytes matching that hash, and _(ii)_
the entry's grants permit the requesting origin to see them.

The benefit is the elimination of redundant downloads. A file fetched on one
site is available immediately on the next, reducing bandwidth, load latency,
disk usage, and energy consumption. Typical candidates are AI models,
WebAssembly modules, JavaScript libraries, game engines, and web fonts.

The COS cache is unpartitioned by design, which is where both the benefit and
the exposure come from. Whether a given hash is present depends on which other
sites the user visited and what those sites stored, so every answer crosses a
site boundary.

**Mitigations need to carefully balance between ensuring the user's privacy and
maintaining the usefulness of the feature.** Restrictions severe enough to
eliminate every attack described here would also eliminate the sharing that
motivates the feature.

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

A shared, vendor-neutral allowlist of hashes. A hash is admitted after evidence
that its resource is deployed widely enough that confirming its presence says
nothing about an individual. That evidence is reviewed once, at admission, so at
query time the browser only tests list membership. The list gates the global
scope (`origins: '*'`) and nothing else. See the
[PHL explainer](public-hash-list/phl-explainer.md).

### GREASE'ing

The browser occasionally reporting a file as absent although it holds it, so a
site cannot read a negative answer as proof of absence. It applies only to reads
that qualify through the global scope, and browsers withhold it for files whose
size would make a spurious re-download disproportionate.

### Lookup budget

A cap the explainer proposes on how many cross-site lookups a site may perform
in a time window, on the order of 8 to 16. Lookups for files the requesting site
stored itself stay free. The budget belongs to the top-level site, so every
frame on the page draws from the same one. It persists across reloads and tabs,
and counts every surface that reaches the cache.

### Prevalence

The share of devices holding a given file, which sets what one answer about it
is worth. A file half of devices hold yields the most entropy per query, a
near-universal file yields almost none, and a positive answer on a rare file is
worth the most of all.

## Background

Any party holding a file's bytes can compute its hash and query it, so the
addressable set spans the public web and anything the attacker authors.

Almost every attack below runs on the global scope, the one under which an
origin with no prior relationship to an entry learns that it exists. A tracker
cannot approximate the web with an explicit list, and the same-site default
carries nothing across a site boundary.

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

### Overview

The following sections present fourteen attacks, each with its objective and how
far a mitigation reaches against it. **Partially** means the mitigations raise
the cost and slow accumulation without ending the attack. **Completely** means
they close the evasion the attack targets. **Not addressed** means no mitigation
below reaches the attack at all. **By design** means the current design already
rules the attack out, and it appears here because relaxing that property would
reopen it. [Coverage gaps](#coverage-gaps) works through each verdict.

| Attack                                                                                                                           | Objective                                                                                                  | Solvable with mitigation                                               |
| -------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| [Attack 1: Supercookie](#attack-1-supercookie)                                                                                   | Recognize the same device across unrelated sites, through an identifier the tracker plants and reads back. | **Partially**. Meter the writes and the cross-site reads.              |
| [Attack 2: Cache-based fingerprinting](#attack-2-cache-based-fingerprinting)                                                     | Recognize the same device across unrelated sites, through the files it already happens to hold.            | **Partially**. Cap the answers per window.                             |
| [Attack 3: Attribute inference](#attack-3-attribute-inference)                                                                   | Assign the user to a targeting cohort, with no identifier involved at any point.                           | **Partially**. Cap the answers, and keep revealing files off the list. |
| [Attack 4: History sniffing](#attack-4-history-sniffing)                                                                         | Establish that a device visited one particular site, with no cooperation from that site.                   | **Partially**. Cap the answers, and narrow what goes out globally.     |
| [Attack 5: Targeted de-anonymization](#attack-5-targeted-de-anonymization)                                                       | Decide whether an anonymous visitor is one specific person the attacker already knows.                     | **Not addressed**. Bound what a single answer discloses.               |
| [Attack 6: Induced write as a state oracle](#attack-6-induced-write-as-a-state-oracle)                                           | Learn the state of a user's account on another site, by making that site write and asking whether it did.  | **Partially**. Hold sharing until a user gesture.                      |
| [Attack 7: Query oracle through result-dependent caching](#attack-7-query-oracle-through-result-dependent-caching)               | Read private data out of another site, by choosing what that site is asked.                                | **Partially**. Hold sharing until a gesture, and count each question.  |
| [Attack 8: Cache flooding to force eviction](#attack-8-cache-flooding-to-force-eviction)                                         | Control what the device holds, by filling the cache until the browser reclaims space.                      | **Partially**. Meter writes by size.                                   |
| [Attack 9: Sybil attack on the budget](#attack-9-sybil-attack-on-the-budget)                                                     | Spend more lookups than the budget allows, by presenting as several origins at once.                       | **Completely**. Key the budget to the top-level site.                  |
| [Attack 10: Rate-limit evasion by reload](#attack-10-rate-limit-evasion-by-reload)                                               | Spend more lookups than the budget allows, by resetting the counter that holds it.                         | **Completely**. Persist the count across reloads.                      |
| [Attack 11: Cross-site leak by combining COS integration points](#attack-11-cross-site-leak-by-combining-cos-integration-points) | Obtain lookups the budget never counts, by taking paths that return nothing to the page.                   | **Completely**. Count every surface that reaches the cache.            |
| [Attack 12: GREASE'ing evasion](#attack-12-greaseing-evasion)                                                                    | Recover the answers GREASE'ing withholds, by making the noise cancel, repeat, or never apply.              | **Partially**. Decide from origin and epoch as well.                   |
| [Attack 13: Existence oracle through in-progress writes](#attack-13-existence-oracle-through-in-progress-writes)                 | Learn whether the device holds a file in the cases where a read refuses to say.                            | **By design**. Keep create off the registry.                           |
| [Attack 14: Timing side channel](#attack-14-timing-side-channel)                                                                 | Read the answer a refusal withholds, out of how long the refusal takes.                                    | **By design**. Keep every refusal identical.                           |

### Shared setup

Every sample below builds on these three declarations: a shorthand for the API
entry point, a `has()` helper that runs one lookup and reports the single bit an
attacker learns from it, and the object shape that names a hash.

```js
const cos = navigator.crossOriginStorage;

// One probe. True when the browser holds the file and will disclose it to
// this origin, false when it refuses for any reason. The attacker cannot tell
// the reasons apart, which is what Attack 14 tries to change.
const has = async (h) => !!(await cos.requestFileHandle(h).catch(() => 0));

// Hashes appear as this pair throughout, with the digest truncated.
const example = { algorithm: 'SHA-256', value: '8f43…' };
```

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

#### Variant 1: Through an embedded frame

Both sites embed an iframe from `tracker.example` and grant it
`allow="cross-origin-storage"`, so the tracker writes under its own origin. A
storing origin can always read its own entries, so the recovery bypasses the
Public Hash List, GREASE'ing, and the `origins` grants entirely. Nothing checks
the files, so the tracker mints its own marker resources: a few hundred random
bytes each, keyed by their SHA-256. Those hashes exist nowhere else on the web,
so no organic cache hit can fake a positive.

```html
<!-- On every embedding site. -->
<iframe src="https://tracker.example/" allow="cross-origin-storage"></iframe>
```

```js
// Inside the frame, so every call runs as tracker.example, on every site.

// One minted file per bit of the identifier.
const trackerHashes = [
  { algorithm: 'SHA-256', value: '4d7a…' },
  /* …31 more */
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
later the same frame on an unrelated shopping site reads those 32 hashes back,
recovers the pattern, and attributes both visits to one device.

#### Variant 2: Through the Public Hash List

A tracker running as the site's own script writes under that site's origin,
unreadable elsewhere. Reaching it from a second site requires
[Public Hash List](public-hash-list/phl-explainer.md) hashes written with
`origins: '*'`. The tracker therefore carries the identifier in a subset of
listed files that are small and, despite being on the PHL, comparatively rare.
This variant is noisier: organic cache hits produce false positives, and
GREASE'ing produces false negatives, so the tracker adds redundancy.

```js
// The marker resources have to be on the PHL, so the tracker picks small
// ones that few devices are likely to hold.
const phlHashes = [
  { algorithm: 'SHA-256', value: 'e3b0…' },
  /* …31 or more, for redundancy */
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

**Example.** The same two visits as in Variant 1, with the tracker running as
each site's own script and the marker resources drawn from the PHL.

#### Variant 3: Through the list scope

The tracker mints its marker resources as in Variant 1, so the answers stay
noiseless. A minted hash never reaches the PHL, so the global scope is closed to
it, and the list scope carries the read instead: it works for any hash, and
GREASE'ing leaves it alone. The tracker runs first-party on both sites, so no
frame and no `allow="cross-origin-storage"` is involved.

Two things bound it. Site A's write has to name site B ahead of time, and the
declared list is intersected with what site A's own
[`Cross-Origin-Storage-Allow-Origin`](README.md#the-cross-origin-storage-allow-origin-header)
response header authorizes, which injected script cannot forge. That list is
capped at a handful of origins, so a tracker can wire up a few site pairs this
way and nothing resembling a network.

```js
// The tracker's own files, so these hashes exist nowhere else on the web.
const mintedHashes = [
  { algorithm: 'SHA-256', value: 'b40d…' },
  /* …31 more */
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

**Example.** `newspaper.example` and `magazine.example` belong to one publisher,
which is what lets the newspaper's response header authorize the magazine's
origin. A reader marked while reading the newspaper is recognized on the
magazine, with no shared cookie and no frame on either site.

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
// Nothing is written, so the probe set is chosen purely for yield: PHL hashes
// the tracker measured near one half prevalence on its own panel, and one file
// per correlated family, so a font's subsets do not count as several
// observations.
const probes = [
  { algorithm: 'SHA-256', value: 'c1f5…' },
  /* …59 more */
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
engine implies browser gaming, a speech model implies dictation, and an office
suite's proofreading model implies use of that suite. Presence alone assigns the
cohort.

```js
// Each probe is picked for what holding the file implies about the user, and
// carries the attribute it evidences.
const semantics = [
  { value: 'd31b…', attribute: 'runs local inference' },
  { value: '6ea0…', attribute: 'reads Japanese' },
  /* …6 more */
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

An advertising script queries seven in-browser AI models and finds one,
establishing that the device runs local inference. An eighth query, for the
Japanese subset of a common font, is also positive, establishing a language
attribute.

## Attack 4: History sniffing

### Objective

The objective is to establish that a device visited one particular site, with no
cooperation from that site.

### Description

The attacker starts on the target site, `game67.example`. One visit shows which
COS-eligible resources it fetches, and those are the candidate hashes. Mapping
where else each of those is deployed yields the roster that later answers are
read against.

`game67.example` is built with a popular game engine, and the attacker has
observed about 200 games shipping the same engine build. A probe on that hash
comes back positive, which places the device on one of those 200 but does not
tell the attacker yet which. That same answer already supports the weaker claim
of Attack 3, that this is someone who plays browser games. Naming the site takes
more probes.

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
// Each probe is a file whose deployment the attacker mapped beforehand, so a
// hit says the device visited at least one origin in that set. Every one of
// these files is widely deployed, so each passes PHL admission, and each set
// below runs to hundreds or thousands of entries, truncated to two here.

// The engine build, which about 200 games ship.
const engineGames = [
  'https://game1.example',
  /* …and many more games */
  'https://game67.example', // ← the target
  'https://game88.example',
  /* …and many more games */
];

// The cookie banner library, on some 2,000 pages, three of them games.
const cookieBanner = [
  'https://blog.example',
  'https://game12.example',
  /* …and many more pages */
  'https://game67.example', // ← the target
  'https://forum.example',
  /* …and many more pages */
];

// The ad SDK bundle, on thousands of pages, one of them a game.
const adSdk = [
  'https://shop.example',
  'https://news.example',
  /* …and many more pages */
  'https://game67.example', // ← the target
  'https://video.example',
  /* …and many more pages */
];

const deployments = new Map([
  ['a7c2…', engineGames],
  ['9f04…', cookieBanner],
  ['5b31…', adSdk],
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
on a file most devices hold carries almost none. Where an attacker has reason to
think a specific person holds an unusual file, one query on a page that person
loads approximates a test for that person.

Large AI models suit this well. Few devices hold any given one, they persist
across long intervals, and the size-proportionate rule withholds GREASE'ing from
files whose spurious re-download would be disproportionate, so the answer is
noise-free exactly where it is most identifying.

```js
// One hash: a model held by a few thousand devices worldwide, so its
// prevalence is around 10⁻⁴, and the attacker has reason to think this
// particular person holds it.
const target = { algorithm: 'SHA-256', value: '0b8e…' };

// On a page the suspected account is reading, a positive is some 13 bits of
// evidence. The file is large enough that the size-proportionate rule
// withholds GREASE'ing, so the answer carries no noise.
if (await has(target)) linkToAccount(suspectedAccount);
```

### Example

A researcher's work involves an uncommon medical imaging model that a few
thousand devices worldwide hold, so their browser has it stored. The attacker
runs a forum where that researcher is suspected of posting anonymously, and adds
one probe for the model's hash to the pages the account is reading. It comes
back positive, which is substantial grounds for tying the account to the
researcher.

## Attack 6: Induced write as a state oracle

### Objective

The objective is to learn the state of a user's account on another site, by
making that site write and then asking whether it did.

### Description

What a site stores depends on where the user is inside it. A signed-in dashboard
loads a charting library that the marketing pages never touch, and a media
player bundle appears once a subscription is active. A site that stores those
files in COS has made its own per-user state observable to whoever can read the
entry.

Two conditions narrow this sharply. The entry has to qualify under the global
scope, so the hash has to be on the PHL, which the site's logo or any other file
unique to it never reaches. What passes that filter is the widely deployed
resource that one state alone pulls in: the charting library, a common player
bundle, a font subset. Thousands of devices hold those files for unrelated
reasons, so a single positive answer is ambiguous.

The attacker removes that ambiguity by probing first. A negative answer
establishes that the device does not hold the file, and that is the only
starting point the attack works from. A positive answer means this device can
tell the attacker nothing, so it moves on to the next one. From a negative
start, it makes the victim site run inside the user's own session, which a popup
or a framed navigation does, carrying the user's cookies. `SameSite=Lax` sends
them on the top-level navigation a popup performs, so the session is live for
that load. A second probe then settles it, because a file that was absent before
that load and present after it can only have arrived from it.

```js
// A charting library that bank.example loads on its signed-in dashboard and
// nowhere else, deployed widely enough to be on the PHL, so any origin may ask.
const dashboardOnly = { algorithm: 'SHA-256', value: '3c9d…' };

// Establish the baseline. A positive here says nothing, because thousands of
// unrelated sites ship this same file.
if (await has(dashboardOnly)) return;

// Run the victim site as the user. The dashboard renders, and stores, only if
// the session is live.
const popup = open('https://bank.example/', '_blank', 'width=1,height=1');
setTimeout(() => popup.close(), 3000);

// The second answer belongs to that load, and the bank disclosed nothing.
const signedIn = await has(dashboardOnly);
```

Two lookups and one induced load, so a lookup budget of 8 never binds and the
whole sequence fits in a single page view.

### Example

`evil.example` establishes that the dashboard library is absent, opens
`bank.example` in a 1×1 popup, closes it three seconds later, and probes again.
The second answer is positive, so this reader holds a live session at that bank,
which is what a phishing campaign needs to choose its possible attack targets.
The bank served no byte to `evil.example` and has no way to observe that any of
this happened.

## Attack 7: Query oracle through result-dependent caching

### Objective

The objective is to read private data out of another site, by choosing what that
site is asked and observing what it stores.

### Description

Attack 6 reads one bit about a session. The same machinery reads the data inside
an account wherever a site's storage depends on a query the attacker supplies. A
search endpoint is the clearest case. Its empty-results page loads a sad face
image, and a populated one loads a table widget. Each page stores what it loads.
The query travels in the URL, so the attacker picks it.

Each induced load then answers one question about data the attacker cannot see.
"Does this account have a transaction matching `acme`" costs one load and one
probe, and the answers compose the way search results do, so an attacker walks a
list of merchants, correspondents, or amounts.

```js
// bank.example renders its empty-results page with a sad face image that a
// populated result page never loads. Both files are common enough for the PHL.
const emptyStatePicture = { algorithm: 'SHA-256', value: 'ae51…' };

// One question per iteration, each answered by what the victim site stores.
const merchants = ['pharmacy', 'casino', 'lawyer'];
const found = [];
for (const q of merchants) {
  await flushCache(emptyStatePicture); // Attack 8, to reset the baseline
  const url = `https://bank.example/transactions?q=${q}`;
  const popup = open(url, '_blank', 'width=1,height=1');
  await settle(popup);
  // No empty-state file means the query matched something.
  if (!(await has(emptyStatePicture))) found.push(q);
}
```

This costs more than Attack 6 and yields more. Every question needs its own
load, its own reset, and its own lookup, so the lookup budget binds here in a
way it never does on a single-bit probe, and the resets make the attack slow and
heavy on the network. The target is also specific: the attacker has to find a
site whose per-account search is reachable by `GET` and whose storage varies
with the result, and study it beforehand. What it buys is the contents of an
account the attacker cannot sign in to.

### Example

An attacker walks 40 merchant names through `bank.example`'s transaction search,
one induced load each. Eleven come back as matches, which is a partial statement
for an account the attacker has no credentials for. Every query ran with the
user's own cookies, on a `GET` the bank considers ordinary.

## Attack 8: Cache flooding to force eviction

### Objective

The objective is to control what the device holds, by filling the cache until
the browser reclaims space.

### Description

Every other attack reads a cache the attacker did not arrange, which is what
makes a positive answer ambiguous: the file may have arrived at any time, from
any of the sites that ship it. An attacker who can empty the cache turns it into
a slate it controls, and that is the baseline Attacks 6 and 7 are built on.

The mechanism is ordinary use at volume. Under storage pressure the explainer
expects user agents to reclaim space, for example, by deleting the least
recently used files (see [Eviction](README.md#eviction)). The attacker's own
entries are the most recently used, so what leaves is what other sites stored.

```js
// Write until the browser refuses, then continue from the next origin.
for (const filler of fillerFiles) {
  try {
    const handle = await cos.requestFileHandle(filler.hash, { create: true });
    const w = await handle.createWritable();
    await w.write(await fetch(filler.url).then((r) => r.blob()));
    await w.close();
  } catch {
    break; // QuotaExceededError: this origin has spent its storage limit.
  }
}
```

The per-origin storage limit (see [Cache flooding](README.md#cache-flooding)) is
what bounds one origin. It is keyed to the origin, and an attacker brings as
many origins as it cares to, which is Attack 9's move applied to the write path.

```html
<!-- Sixteen subdomains, sixteen storage limits, one flood. -->
<iframe src="https://f0.tracker.example/" allow="cross-origin-storage"></iframe>
<iframe src="https://f1.tracker.example/" allow="cross-origin-storage"></iframe>
<!-- …f2 through f15 -->
```

What bounds it in practice is the transfer. Filling a cache sized for AI models
means moving gigabytes, which takes time, appears in the network panel, and
costs the user on a metered connection. Eviction is also indiscriminate: the
attacker names no entry and drops everything colder than its own flood, so
resetting one answer takes the user's whole cache with it.

### Example

A tracker's page embeds sixteen frames on sixteen subdomains, each writing
filler until it gets a `QuotaExceededError`. Some gigabytes later the entries
the device had accumulated are gone, and the tracker runs Attack 6 against a
baseline it arranged itself. The user pays twice, once for the flood and again
in re-downloads across the sites they visit next.

## Attack 9: Sybil attack on the budget

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

## Attack 10: Rate-limit evasion by reload

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

## Attack 11: Cross-site leak by combining COS integration points

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

## Attack 12: GREASE'ing evasion

### Objective

The objective is to recover the answers GREASE'ing withholds, by arranging for
the noise to cancel, to repeat identically, or never to apply.

### Description

GREASE'ing is the one mitigation that makes a single answer unreliable. Its
strength rests on a detail the explainer leaves open: which inputs decide
whether a given file is withheld from a given site.

The attacker can do this in three ways.

#### Variant 1: Repetition against a per-call decision

A browser that decides anew on every call makes the noise independent per probe,
so the same question asked `r` times is withheld only when every one of those
decisions goes the browser's way. The false-negative rate falls to `g^r`, and
GREASE'ing only ever turns a file that is present into one reported absent, so a
single positive anywhere in the run is the true answer.

```js
// Ask the same question until it answers or the repeats run out.
const hasDespiteGrease = async (hash, r = 4) => {
  for (let i = 0; i < r; i++) if (await has(hash)) return true;
  return false;
};
```

**Example.** At `g = 0.5`, four repeats cut the miss rate from one in two to one
in sixteen, at a cost of four lookups per answer. Deciding per call makes
GREASE'ing a multiplier on the lookup budget, worth exactly as much as the
allowance behind it.

#### Variant 2: A fixed origin against a deterministic mask

Deciding from the device, the requesting origin, and the hash stops Variant 1,
since the same call then always returns the same thing. It also makes the mask a
fixed function of the requesting origin, so an attacker that holds that origin
constant sees one mask everywhere. An embedded frame does exactly that, and the
answers on site A and site B then pass through a single deterministic map and
link as cleanly as on a channel with no noise at all.

```html
<!-- One origin on every embedding site, so the mask never changes. -->
<iframe src="https://tracker.example/" allow="cross-origin-storage"></iframe>
```

This choice leaves the attacker better off than no GREASE'ing at all. The masked
file is rarer than the real one, so a surviving positive carries
`log₂(1/p) + log₂(1/(1−g))` where a noiseless channel carries `log₂(1/p)`.

**Example.** Deciding from the device and the hash alone is worse again. Every
origin sees one mask forever, which hides a fixed fraction of the device's cache
from everybody and links exactly as well as no noise would.

#### Variant 3: Selection above the size threshold

GREASE'ing is withheld from files whose spurious re-download would be
disproportionate, so an attacker probes only files above that threshold. Those
answers carry no noise, and the exempt set is the one worth probing anyway:
large files are the rarest, so a positive is worth the most, and the most
persistent, so the answer holds from one visit to the next.

```js
// Every probe is over the size threshold, so nothing is ever withheld. The Hugging
// Face section of the PHL alone carries six figures of candidates.
const probes = largePhlHashes.slice(0, 64);
const fingerprint = (await Promise.all(probes.map(has))).join('');
```

**Example.** Past a certain probability, raising `g` changes nothing, because
the attacker has already moved to the exempt subset. Attack 5 is this variant
with a single probe.

### The inputs to settle

Variants 1 and 2 answer to one choice: decide from the device, the requesting
origin, the hash, and a time epoch. Repeats inside an epoch then return one
answer, and two visits in different epochs see independent noise. The explainer
does not say, so an implementation can satisfy its current wording with a choice
of inputs worth nothing, and this is the detail to settle. Variant 3 survives
every choice, since nothing is withheld from it in the first place.

## Attack 13: Existence oracle through in-progress writes

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
// Whoever stored this file named a short list of partner origins, and this
// attacker is not one of them, so an ordinary read refuses.
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

## Attack 14: Timing side channel

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
// Every one of these rejects, so the returned value carries nothing and the
// elapsed time is all the attacker has to work with.
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

## Proposed mitigations

### A single mediation point

Every attack in this document passes through one API. Classic browser
fingerprinting, surveyed by [Laperdrix et al.](https://doi.org/10.1145/3386040)
(ACM TWEB 2020), draws on signals the browser never sees as signals, from timing
variation to accumulated platform quirks, spread across the whole platform with
no one call to count. A COS lookup is an explicit request, so the browser sees
each one, knows which origin made it and which hash it named, and can count it,
delay it, or decline it.

The browser therefore knows exactly where to look, in advance and in one place.
That reduces the problem to bookkeeping: count every request that could disclose
what another site stored, and decide which of them to answer. Attacks 9 through
11 all target that bookkeeping, and a gap in it costs the whole protection.
Attack 12 targets the other half, the noise the browser adds to the answers it
does give.

Mitigations 1 through 4 are the ones the explainer lists today. Mitigations 5
through 8 are under discussion, and each acts on a surface the first four leave
alone: the browser's own third-party cookie setting, the user, the developer
writing the entry, and the write path itself.

### Mitigation 1: Cross-site lookup budget

Every lookup that could reveal what another site stored counts against a small
allowance, on the order of 8 to 16 per time window, whether or not it finds the
file. Both numbers are the user agent's to choose. Lookups for files the
requesting site stored itself stay free. The allowance belongs to the top-level
site the user is visiting, by scheme and registrable domain, and every frame on
the page draws from the same one.

#### Coverage

| Attacks                                                                                                                             | Description                                                                                                                                                                                                   |
| ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Attack 9](#attack-9-sybil-attack-on-the-budget)                                                                                    | Closed. Extra origins and extra frames all draw from the one allowance the top-level site owns, so adding them mints nothing.                                                                                 |
| [Attack 11](#attack-11-cross-site-leak-by-combining-cos-integration-points)                                                         | Closed, provided implementations count the declarative integration points alongside `requestFileHandle()`, which the wording "every lookup that could reveal what another site stored" supports.              |
| [Attack 2](#attack-2-cache-based-fingerprinting), [Attack 3](#attack-3-attribute-inference), [Attack 4](#attack-4-history-sniffing) | Bounded without being closed. Eight bits per window against the roughly 32 an identifier needs, so a patient attacker accumulates across windows, paced by the user's own visits.                             |
| [Attack 7](#attack-7-query-oracle-through-result-dependent-caching)                                                                 | Bounded, and this is the one attack the allowance bites. Every question costs a lookup, so eight of them is how much of an account a single page view reads.                                                  |
| [Attack 1](#attack-1-supercookie)                                                                                                   | Variants 2 and 3 count against the allowance. Variant 1 reads entries its own origin stored, which the exemption leaves free, so the budget does not reach the variant the explainer compares to a 3P cookie. |
| [Attack 12](#attack-12-greaseing-evasion)                                                                                           | Variant 1 only, and the budget is what prices it. Each repeat costs a lookup, so `n` probes at `r` repeats have to fit one allowance. Variants 2 and 3 need no repeats.                                       |
| [Attack 5](#attack-5-targeted-de-anonymization), [Attack 6](#attack-6-induced-write-as-a-state-oracle)                              | Untouched. One probe suffices for Attack 5 and two bracket Attack 6's induced load, so an allowance of 8 never binds.                                                                                         |
| [Attack 8](#attack-8-cache-flooding-to-force-eviction)                                                                              | Out of reach. It writes, and the allowance counts reads. What bounds it is the per-origin storage limit, keyed to the origin this budget deliberately stopped trusting.                                       |

### Mitigation 2: A user gesture before an entry becomes shareable

A written file becomes readable by other sites only after a user gesture on the
page. The writing page itself can use the file right away, so the performance
benefit survives intact, and what waits for the gesture is the cross-site
disclosure.

#### Coverage

| Attacks                                                                                                                                                                              | Description                                                                                                                                                                                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Attack 1](#attack-1-supercookie)                                                                                                                                                    | Bounded on the write side: no gesture, no cross-site entry, so a device cannot be marked during a silent load. A gesture is one click, and a tracker on a site the user interacts with will get one.             |
| [Attack 10](#attack-10-rate-limit-evasion-by-reload)                                                                                                                                 | Helps, since a page reloading itself cannot write on each pass.                                                                                                                                                  |
| [Attack 2](#attack-2-cache-based-fingerprinting), [Attack 3](#attack-3-attribute-inference), [Attack 4](#attack-4-history-sniffing), [Attack 5](#attack-5-targeted-de-anonymization) | Out of reach. None of them writes anything.                                                                                                                                                                      |
| [Attack 7](#attack-7-query-oracle-through-result-dependent-caching)                                                                                                                  | Closed in practice, and this is the mitigation aimed at it. Every question needs an induced load on a URL the attacker chose, which the user has no reason to touch, so the victim site's write stays same-site. |
| [Attack 6](#attack-6-induced-write-as-a-state-oracle)                                                                                                                                | Bounded the same way on the induced half. An entry written during a genuine, gesture-bearing visit stays shareable, so a passive variant survives that reads the state as of that visit.                         |
| [Attack 9](#attack-9-sybil-attack-on-the-budget), [Attack 11](#attack-11-cross-site-leak-by-combining-cos-integration-points)                                                        | Out of reach. Both concern reads.                                                                                                                                                                                |
| [Attack 12](#attack-12-greaseing-evasion)                                                                                                                                            | Out of reach. It reads, and nothing it reads was written for it.                                                                                                                                                 |
| [Attack 8](#attack-8-cache-flooding-to-force-eviction)                                                                                                                               | Out of reach. Flooding needs no entry to be shareable, since a same-site write consumes the same space and forces the same eviction.                                                                             |

Variant 1 of Attack 1 raises the same question the budget does: a storing origin
reading back its own entries widens no scope, so whether the gate applies to it
depends on reading "shareable with other sites" to cover use under a different
top-level site.

### Mitigation 3: A count that survives reloads and tabs

The lookup count persists across page reloads for the whole top-level site, and
across tabs.

#### Coverage

| Attacks                                                                                                                                                                | Description                                                                                                                                    |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| [Attack 10](#attack-10-rate-limit-evasion-by-reload)                                                                                                                   | Closed. The count belongs to the top-level site and survives reloads and tabs, so a fresh load starts with the allowance already spent.        |
| [Attack 1](#attack-1-supercookie), [Attack 2](#attack-2-cache-based-fingerprinting), [Attack 3](#attack-3-attribute-inference), [Attack 4](#attack-4-history-sniffing) | Carries Mitigation 1's partial bounds. Without persistence the allowance would cover one page load, and any of these could reload for another. |
| [Attack 7](#attack-7-query-oracle-through-result-dependent-caching)                                                                                                    | Closes the refresh that would otherwise give each question its own allowance, since the attacker's page can reload between induced loads.      |
| [Attack 5](#attack-5-targeted-de-anonymization), [Attack 6](#attack-6-induced-write-as-a-state-oracle)                                                                 | Untouched, for the same reason the budget misses it.                                                                                           |
| [Attack 12](#attack-12-greaseing-evasion)                                                                                                                              | Carries Mitigation 1's bound on Variant 1, since an attacker cannot reload to buy further repeats.                                             |
| [Attack 8](#attack-8-cache-flooding-to-force-eviction)                                                                                                                 | Out of reach, for the same reason the budget misses it: the count tracks lookups, and this attack writes.                                      |

### Mitigation 4: Tighter limits for sites known to be malicious

A user agent can restrict `requestFileHandle()` further for sites it already
knows to be malicious, from a source such as Safe Browsing.

#### Coverage

| Attacks                                                                                           | Description                                                                                                                                                                                    |
| ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Attack 1](#attack-1-supercookie) through [Attack 12](#attack-12-greaseing-evasion), in principle | Reached. A flagged site can be refused ahead of any counting, which bounds every attack that needs the API.                                                                                    |
| The same attacks in practice                                                                      | Not reached. They run from ordinary sites: an analytics script on a recipe blog, an ad network's script on a news site, a forum the attacker operates. None of those is a Safe Browsing match. |

This is containment for cases already identified, and on its own it bounds none
of the attacks above.

### Mitigation 5: Availability tied to third-party cookies

A user agent that still supports third-party cookies can make COS's cross-site
disclosure follow that setting. Where third-party cookies are on, COS answers as
this document describes throughout. Where the user has turned them off, for the
browser or for one site, every lookup that would reveal what another site stored
reports absence, and clearing third-party cookies clears the entries a
cross-site read could have reached. A site reading back what it stored itself is
unaffected, so the same-origin performance benefit survives in both states.

The argument is one of marginal exposure. A tracker holding a third-party cookie
already has a stable identifier that COS cannot improve on, so tying the two
together keeps COS from adding to a tracking surface the browser has already
accepted.

#### Coverage

| Attacks                                                                                                                                                                                                             | Description                                                                                                                                                                                                                                                                                                     |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Attack 1](#attack-1-supercookie), [Attack 2](#attack-2-cache-based-fingerprinting), [Attack 3](#attack-3-attribute-inference)                                                                                      | Reached by comparison. All three link a device across the sites carrying the tracker, which is what a third-party cookie does more reliably, so wherever the lookups work the attacker held a better instrument already.                                                                                        |
| [Attack 4](#attack-4-history-sniffing), [Attack 5](#attack-5-targeted-de-anonymization), [Attack 6](#attack-6-induced-write-as-a-state-oracle), [Attack 7](#attack-7-query-oracle-through-result-dependent-caching) | The comparison fails. A third-party cookie reports the sites that carry the tracker, and these four reach sites it never touched: a game it is absent from, a model the user fetched elsewhere, a bank the attacker only opened in a popup. Where third-party cookies are off, the gate removes them wholesale. |
| [Attack 8](#attack-8-cache-flooding-to-force-eviction) through [Attack 12](#attack-12-greaseing-evasion)                                                                                                            | Removed wherever third-party cookies are off, since nothing crosses a site boundary there. Unaffected wherever they are on, and [Attack 8](#attack-8-cache-flooding-to-force-eviction) survives in both states, since a same-site write fills the same cache.                                                   |
| [Attack 13](#attack-13-existence-oracle-through-in-progress-writes), [Attack 14](#attack-14-timing-side-channel)                                                                                                    | Unaffected. Both are properties of the design and hold in either state.                                                                                                                                                                                                                                         |

Two limits come with it. A browser that has already removed third-party cookies
cannot apply this at all, so the mitigation is absent exactly where the rest of
the privacy work is furthest along, and COS in those browsers rests on the other
mitigations listed here. The comparison also covers deliberate trackers only. An
unintended leak happens between parties that never set a cookie for each other,
and a reader of one of those learns something a third-party cookie would never
have told them.

### Mitigation 6: Permission prompts

A user agent can ask the user before letting a site read what other sites
stored. Three granularities have been considered: one grant per browser, one per
requesting origin, and one per resource, the last plausibly attached to a
browser-controlled page element so the prompt can name the file at stake. At
every granularity the grant gates cross-site disclosure alone, and a site
reading back its own entries never prompts. A lookup never raises the prompt
itself, so a probe loop cannot be used to summon one; the grant is requested
from a user gesture, which keeps a page from asking on load or asking
repeatedly.

#### Coverage

| Attacks                                                                                           | Description                                                                                                                                                                                                                           |
| ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Attack 1](#attack-1-supercookie) through [Attack 12](#attack-12-greaseing-evasion), in principle | Reached. An origin without a grant learns nothing another site stored, whatever it asks and by whichever surface it asks. [Attack 8](#attack-8-cache-flooding-to-force-eviction) is the exception, since it writes and reads nothing. |
| [Attack 5](#attack-5-targeted-de-anonymization)                                                   | Reached, and this is the only mitigation in this document that reaches it. The others bound how many answers a site may collect, and one answer is all this attack needs; a prompt bounds whether the site may ask at all.            |
| The same attacks in practice                                                                      | Contingent on users declining. A grant nobody can evaluate is a grant most people give.                                                                                                                                               |

The cost falls on both sides. The disclosure is hard to put to a user: the grant
has no visible effect either way, the user cannot check what was read
afterwards, and the honest phrasing, that this site wants to know which files
other sites left on the device, describes a mechanism most people have no model
for. Per-origin and per-resource prompts multiply that decision across the web,
which is the decision fatigue that has degraded other permissions over time.
Friction also works directly against the feature, since a shared cache pays off
when the second site gets its hit with no ceremony, and a prompt on every new
origin removes most of what motivates COS. The per-resource variant is the one
that can be explained concretely, naming the multi-gigabyte model the user
already has, and it is also the one that scales worst.

### Mitigation 7: Developer guidance

The user agent tells developers what a write exposes, at the moment they write
it, through the DevTools Issues panel or a console warning. This earns a place
among the mitigations because Attacks 6 and 7 need a site whose storage varies
with its users' state, that site is attacking nobody, and nothing in its own
telemetry will ever show that it leaked. Guidance is the only mitigation here
aimed at the supply of leaky writes.

Cases worth a message: a write declaring `origins: '*'` for a hash the PHL does
not carry, which the user agent silently narrows to same-site; a write whose
bytes differ per user, which is the shape of a minted identifier; a write on a
path that only an authenticated session reaches; and an `origins` list that the
[`Cross-Origin-Storage-Allow-Origin`](README.md#the-cross-origin-storage-allow-origin-header)
header trimmed. The explainer already calls for console warnings on the last of
these (see
[Resource visibility upgrades](README.md#resource-visibility-upgrades)). For the
first, the message has to name the outcome, since the call itself succeeded:

> ⚠️ Cross-Origin Storage: `origins: '*'` was requested for a hash that is not
> on the Public Hash List. The entry is readable by same-site origins only.

#### Coverage

| Attacks                                                                                                                                                                                                                                                                                   | Description                                                                                                                                                                                    |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Attack 6](#attack-6-induced-write-as-a-state-oracle), [Attack 7](#attack-7-query-oracle-through-result-dependent-caching)                                                                                                                                                                | Reached on the supply side, which nothing else here addresses. Both need a site that made its own state observable without meaning to, and a warning at write time is what tells that site so. |
| [Attack 4](#attack-4-history-sniffing)                                                                                                                                                                                                                                                    | Partially, for the same reason. A site warned that a distinctive resource is going out globally may narrow its scope, which shortens the deployment map an attacker reads answers against.     |
| [Attack 1](#attack-1-supercookie), [Attack 2](#attack-2-cache-based-fingerprinting), [Attack 3](#attack-3-attribute-inference), [Attack 5](#attack-5-targeted-de-anonymization), [Attack 8](#attack-8-cache-flooding-to-force-eviction) through [Attack 12](#attack-12-greaseing-evasion) | Not reached. A deliberate attacker reads the warning as confirmation that the write worked.                                                                                                    |

Guidance changes what honest sites deploy and constrains an attacker not at all.
It earns its place because the attacks it touches need an honest site's
cooperation, and withdrawing that cooperation is a defense no demand-side
mitigation can supply.

### Mitigation 8: A write budget weighted by size

Writes count as well as reads. Small writes count one by one against an
allowance, and large ones are metered by total bytes, so a site storing one
multi-gigabyte model spends bytes and barely touches the count, and a tracker
storing 64 files of a few hundred bytes each hits it at once. The two shapes
separate cleanly: the files COS exists to share run from 8 MB to several
gigabytes, and the files an identifier is made of have to be small enough to
afford dozens of them. Switching to large marker resources to escape the count
means pushing gigabytes onto the device for 32 bits, which the storage limit
stops and the user's bandwidth bill notices. See
[Rule 4](public-hash-list/research/proposed-solution.md#rule-4-count-small-writes-weigh-large-ones-by-size).

#### Coverage

| Attacks                                                                                                                                                                                                      | Description                                                                                                                                                                                       |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Attack 1](#attack-1-supercookie)                                                                                                                                                                            | Reached across all three variants, on the side the lookup budget misses. Sixty-four marker resources fit in about 48 KB, so counting small writes is what makes planting an identifier expensive. |
| [Attack 8](#attack-8-cache-flooding-to-force-eviction)                                                                                                                                                       | Reached, and this is the first mitigation on the list to touch it. Flooding is writing at volume, which is exactly what a size-weighted allowance meters.                                         |
| [Attack 6](#attack-6-induced-write-as-a-state-oracle), [Attack 7](#attack-7-query-oracle-through-result-dependent-caching)                                                                                   | Out of reach. The writes belong to the victim site, at ordinary volume, and the attacker writes nothing.                                                                                          |
| [Attack 2](#attack-2-cache-based-fingerprinting) through [Attack 5](#attack-5-targeted-de-anonymization), [Attack 9](#attack-9-sybil-attack-on-the-budget) through [Attack 12](#attack-12-greaseing-evasion) | Out of reach. None of them writes anything.                                                                                                                                                       |

The write budget and the per-origin storage limit bound different things. The
limit caps what one origin holds at any moment, and an attacker spread across
sixteen subdomains gets sixteen of them. Keyed like the lookup budget, to the
top-level site, a write budget is one allowance however many origins a page
brings, which is the opening the storage limit leaves in
[Attack 8](#attack-8-cache-flooding-to-force-eviction).

## Coverage gaps

| Attack                                                                                                                    | Covered by                                     | Degree                                                        |
| ------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------- |
| [1: Supercookie](#attack-1-supercookie)                                                                                   | Mitigations 1, 2, 3, 5, 6, 8                   | Partially, and Variant 1 escapes 1 and 2                      |
| [2: Cache-based fingerprinting](#attack-2-cache-based-fingerprinting)                                                     | Mitigations 1, 3, 5, 6                         | Partially                                                     |
| [3: Attribute inference](#attack-3-attribute-inference)                                                                   | Mitigations 1, 3, 5, 6                         | Partially, and 8 lookups already yield a cohort               |
| [4: History sniffing](#attack-4-history-sniffing)                                                                         | Mitigations 1, 3, 6, 7                         | Partially                                                     |
| [5: Targeted de-anonymization](#attack-5-targeted-de-anonymization)                                                       | Mitigation 6                                   | Not addressed by anything the explainer lists                 |
| [6: Induced write as a state oracle](#attack-6-induced-write-as-a-state-oracle)                                           | Mitigations 2, 6, 7                            | Partially, and the passive variant survives                   |
| [7: Query oracle through result-dependent caching](#attack-7-query-oracle-through-result-dependent-caching)               | Mitigations 1, 2, 3, 6, 7                      | Partially, and Mitigation 2 blocks the induced load           |
| [8: Cache flooding to force eviction](#attack-8-cache-flooding-to-force-eviction)                                         | Mitigation 8, and the per-origin storage limit | Partially, and the limit alone lets extra origins multiply it |
| [9: Sybil attack on the budget](#attack-9-sybil-attack-on-the-budget)                                                     | Mitigation 1                                   | Completely                                                    |
| [10: Rate-limit evasion by reload](#attack-10-rate-limit-evasion-by-reload)                                               | Mitigations 2, 3                               | Completely                                                    |
| [11: Cross-site leak by combining COS integration points](#attack-11-cross-site-leak-by-combining-cos-integration-points) | Mitigation 1                                   | Completely                                                    |
| [12: GREASE'ing evasion](#attack-12-greaseing-evasion)                                                                    | Mitigations 1, 3, 6                            | Partially, and Variant 3 is not addressed                     |
| [13: Existence oracle through in-progress writes](#attack-13-existence-oracle-through-in-progress-writes)                 | None needed                                    | Ruled out by design                                           |
| [14: Timing side channel](#attack-14-timing-side-channel)                                                                 | None needed                                    | Ruled out by design                                           |

Attack 5 is the one no mitigation the explainer lists reaches. Each of
Mitigations 1 through 4 bounds something the attack does not need: volume
(Mitigations 1 and 3), the write side (Mitigation 2), or sites already known to
be bad (Mitigation 4). Targeted de-anonymization spends one probe, writes
nothing, and runs from a site nobody has flagged, so it passes through all four
untouched.

GREASE'ing is the design feature that would answer it, by making a single
negative unreliable. The size-proportionate rule withholds GREASE'ing from files
whose spurious re-download would be disproportionate, which is exactly the class
of large, rare files the attack is strongest on, so the answer stays noise-free
where it identifies best, and [Attack 12](#attack-12-greaseing-evasion) turns
that same exemption against GREASE'ing wholesale. Among the mitigations under
discussion, the permission prompt is the only one that reaches this attack, and
it does so by bounding whether a site may ask at all. Everything else above
bounds how many answers a site may collect, and one answer is all this attack
needs, so closing it inside the API calls for a bound keyed to how much a single
answer discloses.

Mitigation 5 appears in the rows above where its argument holds, and it acts on
all of them at once. Wherever third-party cookies are off it removes every
attack that crosses a site boundary, and wherever they are on it changes none of
them. What it contributes is the comparison, that a tracker able to run these
lookups held a third-party cookie already, and that comparison covers Attacks 1
through 3. Attacks 4 through 7 reach sites the tracker never touched, which no
third-party cookie reports, so they are the ones it leaves standing.

Attack 8 is reached by Mitigation 8 and, in the explainer as it stands, by the
per-origin storage limit alone. That limit is keyed to the origin, and the
lookup budget is keyed to the top-level site precisely because an attacker
brings as many origins as it cares to
([Attack 9](#attack-9-sybil-attack-on-the-budget)). A write budget keyed the
same way carries that lesson to the write path. Until one exists, sixteen
subdomains buy sixteen storage limits, and what bounds flooding is the bandwidth
it takes to fill a cache sized for AI models.

Attack 12 is the only attack here aimed at a mitigation the rest of the document
treats as given. Variants 1 and 2 turn on one unsettled specification detail,
which inputs GREASE'ing decides from, and the lookup budget prices the repeats
Variant 1 needs. Variant 3 answers to nothing on this list. The
size-proportionate rule withholds noise from large files for a performance
reason that stands on its own, and those are the files an attacker most wants to
ask about, so Variant 3 and Attack 5 share one opening and will share one fix or
none.

Attacks 6 and 7 are the only two that need a party who is not attacking anyone,
which is why Mitigation 7 reaches them and reaches nothing else. Their exposure
shrinks as sites learn what their own writes disclose, making developer guidance
the one mitigation surface here whose reach grows with adoption.
