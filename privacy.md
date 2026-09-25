<!--
  Copyright 2026 Google LLC
  SPDX-License-Identifier: Apache-2.0
-->

# Privacy and Cross-Origin Storage

[Cross-Origin Storage](README.md) (COS) is a content-addressable cache shared
across origins. A file is identified by the cryptographic hash of its contents,
with no reference to where those contents came from, so identical bytes converge
on a single entry however each site obtained them. The hash doubles as an
integrity guarantee: the browser verifies the bytes against it at write time, so
a site can use an entry some other origin stored without having to trust that
origin. A site requests a file by hash, and the browser serves it without a
network request when _(i)_ it already has bytes matching that hash, and _(ii)_
the requesting origin is permitted to see them.

The benefit is the elimination of redundant downloads. A file fetched on one
site is available immediately on the next, reducing bandwidth, load latency,
disk usage, and energy consumption. Typical candidates are AI models,
WebAssembly modules, JavaScript libraries, game engines, and web fonts.

The cache is unpartitioned by design, which is where the benefit comes from and
where the exposure comes from. Whether a given hash is present depends on which
other sites the user visited and what those sites stored, so every answer
crosses a site boundary.

**Mitigations need to carefully balance between ensuring the user's privacy and
maintaining the usefulness of the feature.** Restrictions severe enough to
eliminate every attack described here would also eliminate the sharing that
motivates the feature. This document covers the attacks; the mitigations COS
proposes are in the [Privacy considerations](README.md#privacy-considerations)
section of the explainer.

## Preliminaries

Content addressing means no prior relationship with a file's publisher is
required: any party holding the bytes can compute the hash and query it. The
addressable set is therefore the entire public web, plus anything the attacker
authors.

Each COS lookup (or probe) returns one bit. Roughly **32 independent bits
distinguish one device among several billion**, since 2³² is about 4.3 billion,
and that is the quantity every attack below accumulates and every mitigation
tries to bound. Quantifying tracking capacity in bits of identifying information
follows Eckersley's
[Panopticlick study](https://doi.org/10.1007/978-3-642-14527-8_1) (PETS 2010),
which placed a lower bound of 18.1 bits on browser fingerprint entropy across
470,161 browsers and found 83.6% of them instantaneously unique.

Attack 1 is stateful tracking: the tracker writes the identifier and reads it
back, which makes the cache a **supercookie**. Attacks 2 through 5 and Attack 8
are **XS-Leaks** over the existence oracle the cache exposes. Attacks 6 and 7
target the rate limiting that constrains the rest.

---

## Attack 1: Supercookie

The tracker constructs the identifier, so this attack is independent of the
device's existing contents and of the prevalence distribution the read-side
attacks depend on.

A set of small files is chosen, and a per-device subset is stored on the first
site, one bit per file. A query for the same set on a second site recovers the
subset. Clearing cookies has no effect, since the identifier lives in the shared
cache. Eviction and the per-origin storage limit bound its lifetime and size,
and the tracker refreshes it on each visit.

**Through an embedded frame.** An iframe from `tracker.example` on both sites,
granted `allow="cross-origin-storage"` by each, writes under its own origin. A
storing origin can always read its own entries, so recovery is exact: the Public
Hash List, GREASE'ing, and the `origins` grants are all bypassed.

**Through the Public Hash List.** A tracker running as the site's own script
writes under that site's origin, unreadable elsewhere. Reaching it from a second
site requires globally readable entries, meaning
[Public Hash List](public-hash-list/phl-explainer.md) hashes written with
`origins: '*'`. The codeword is therefore a subset of well-known public files.
This variant is noisier: organic cache hits produce false positives, and
GREASE'ing produces false negatives, so the tracker adds redundancy.

**Example.** A tracker on a news site stores 32 files, selecting the subset at
random for this device. A week later, on an unrelated shopping site, it queries
those 32 hashes, recovers the subset, and links the visits. Cookie clearing in
the interval is irrelevant.

---

## Attack 2: Cache-based fingerprinting

The distinguishing signal is the set of files accumulated through ordinary
browsing. No writes are involved.

Entropy per query peaks at a prevalence near one half, so near-universal files
contribute nothing and the informative ones are those roughly half of devices
hold. Enough of them yield a pattern unique to a device, supporting cross-site
linking. Correlated files reduce the yield, since a font family's subsets and a
model's shards arrive together and are effectively one observation.

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
Four sites deploy both, so history is narrowed to four candidates.

---

## Attack 4: Attribute inference

No identifier is established, which is what makes this resistant to every
mitigation aimed at identifiers. Files carry semantics: a Japanese font subset
implies a reading language, a game engine implies browser gaming, a speech model
implies dictation, and a model shipped by one application implies use of that
application. Cohort assignment follows directly from presence.

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

A budget keyed to the requesting origin is multiplied by the number of origins
the attacker brings. Wildcard DNS makes subdomains free, so one tracker presents
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
records which its server is asked for. The eleven producing no request are the
files already held. Thirty-two answers, no call to `requestFileHandle()`. This
is why a budget has to count all four surfaces.

---

## Attacks the design rules out

Both are recorded because they reopen if these properties are relaxed.

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
