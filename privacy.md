<!--
  Copyright 2026 Google LLC
  SPDX-License-Identifier: Apache-2.0
-->

# Privacy and Cross-Origin Storage

[Cross-Origin Storage](README.md) (COS) is a content-addressable cache shared
across origins. A file is identified by the cryptographic hash of its contents,
so the same bytes served from two different URLs form a single cache entry, and
the hash doubles as an integrity guarantee. A site asks for a file by hash. If
the browser already holds those exact bytes and the requesting site is permitted
to see them, the file is returned without any network request.

The benefit is the elimination of redundant downloads for large assets: AI
models, WebAssembly modules, widely used JavaScript libraries, game engines, and
web fonts. A four-gigabyte model downloaded on one site is available immediately
on the next, which reduces bandwidth consumption, load latency, disk usage, and
energy use, and avoids transferring identical bytes repeatedly across the
network.

Both properties follow from the same design decision: the cache is shared
between unrelated sites. A site that asks whether a file is present receives an
answer determined by activity on other sites. Every attack described here is
constructed from that one question, repeated.

**Mitigations need to carefully balance between ensuring the user's privacy and
maintaining the usefulness of the feature.** Restrictions severe enough to
eliminate every attack described here would also eliminate the sharing that
motivates the feature. This document covers the attacks. The mitigations COS
proposes are described in the
[Privacy considerations](README.md#privacy-considerations) section of the
explainer.

## Why these attacks are possible

Three properties of the design underlie every attack below.

**The cache is shared across sites.** Conventional browser storage, including
cookies, is partitioned per site, so what one site stores is unreadable by the
next. A content-addressable shared cache crosses that boundary by design.

**Files are addressed by their contents.** Any party holding a copy of a file
can compute its hash, so any site can ask about any file whose bytes it knows.
No prior relationship with the file's publisher is required.

**Each lookup yields one bit.** A lookup either returns the file or reports it
as absent. A single answer carries little information. Roughly **32 independent
yes-or-no answers are sufficient to distinguish one device among several
billion**, which is the quantity every attack below works to accumulate.

## How these attacks are classified

The attacks fall into two families that privacy research treats separately,
because they call for different defenses.

**Stateful tracking** covers attacks where the tracker writes something and
reads it back. The written state is the identifier. Attack 1 is of this kind,
and the established term for state that survives cookie clearing and crosses
site boundaries is a **supercookie**.

**Cross-site leaks**, commonly abbreviated **XS-Leaks**, cover attacks where the
tracker writes nothing and infers information about the user's state on other
sites from an observable side effect. Attacks 2 through 5 and Attack 8 are
XS-Leaks. The shared cache acts as an **existence oracle**: a primitive that
answers whether a given item is present.

Attacks 6 and 7 target the rate limiting that constrains the others.

---

## Attack 1: Supercookie

Also described as a persistent cross-site identifier. The tracker constructs the
identifier itself, so this attack does not depend on the device's existing
contents.

The tracker selects a set of small files and stores a chosen subset of them on
the first site. The presence or absence of each file encodes one bit. On a
second site it queries the same set and recovers the subset, which serves as a
cross-site identifier. Clearing cookies does not affect it, because the
identifier resides in the shared cache.

Two variants differ in the permissions they require.

**Through an embedded frame.** An iframe from `tracker.example` embedded on both
sites, granted `allow="cross-origin-storage"` by each, stores the files under
its own origin. An origin can always read entries it stored, so recovery is
exact: the Public Hash List, GREASE'ing, and the `origins` grants play no part.

**Through the Public Hash List.** A tracker running as the site's own script
stores files under that site's origin, which a second site cannot read. To reach
them from elsewhere it must use files that are globally readable, meaning
entries on the [Public Hash List](public-hash-list/phl-explainer.md) of
well-known resources written with `origins: '*'`. The encoding is therefore a
chosen subset of well-known public files. This variant is noisier: the device
may already hold some of those files from ordinary browsing, producing false
positives, and GREASE'ing may report a stored file as absent. The tracker
compensates with redundancy.

**Example.** A tracker embedded on a news site stores 32 small files, selecting
the subset at random for this device. A week later the same tracker, embedded on
an unrelated shopping site, queries those 32 hashes and recovers the same
subset. The two visits are linked to one device, and cookie clearing in the
interval has no effect.

---

## Attack 2: Cache-based fingerprinting

Fingerprinting constructs a stable device identifier from observable properties.
Here the observable property is the set of files the cache already holds,
accumulated through ordinary browsing. The attack performs no writes.

The tracker queries a fixed set of well-known files and records which are
present. Near-universal files contribute nothing, since almost every device has
them. Files held by roughly half of devices are the informative ones, because
each answer divides the population approximately in two. A sufficient number of
such files produces a pattern unique to one device, which supports **cross-site
linking**: attributing two visits on unrelated sites to the same device.

**Example.** The same analytics script is present on a recipe blog and on a
local newspaper. On each site it queries the same 60 well-known libraries and
fonts. The pattern of present and absent files matches across the two visits, so
the script attributes both to one device and merges the two browsing records.

This attack is less reliable than Attack 1, because the tracker works with
whatever the device happens to hold. It requires no cooperation from the
embedding sites beyond script inclusion, and it writes nothing that a user could
later find or clear.

---

## Attack 3: History sniffing

History sniffing determines which sites a user has visited. The classic form
exploited the styling of visited links; the cache-based form queries files
deployed by a limited set of sites, where presence establishes that the device
visited one of them.

A file used across half the web carries no such information. A file used by two
hundred sites narrows the device's history to those two hundred. Combining
lookups narrows it further: where one file appears on two hundred hobby blogs
and a second appears on two hundred sites covering a particular region, holding
both restricts the candidates to the intersection, which may be a single site.

**Example.** A plugin for hobby blogs ships a distinctive stylesheet deployed on
roughly three hundred sites. A tracker queries that stylesheet and establishes
that the device visited one of them. It then queries a second file specific to a
German-language theme. Both are present, and only four sites in the world deploy
both, so the device's reading history is narrowed to four candidates without any
access to browsing history.

---

## Attack 4: Attribute inference

Attribute inference derives characteristics of the user, including interests,
language, and profession, without establishing an identity. The absence of an
identifier is what makes it resistant to the mitigations aimed at identifiers.

Files carry semantic meaning. A font covering Japanese script indicates the user
reads Japanese. A game engine indicates browser gaming. A speech recognition
model indicates dictation use. A model loaded by an application in a specific
domain indicates use of that application. Grouping users this way is also known
as **cohort inference**.

**Example.** An advertising script queries eight AI models that run in the
browser and finds one present, establishing that the device runs in-browser AI
workloads. It then queries the Japanese subset of a common web font and finds it
present, establishing a language attribute. Eight lookups yield two accurate
targeting attributes, and no identifier was required.

The sensitivity varies with the file. A model distributed by a mental health or
addiction support application carries a strong inference about the user, and the
browser has no basis for distinguishing a query for that file from a query for a
font.

---

## Attack 5: Targeted de-anonymization

De-anonymization links an anonymous session to a known identity. The preceding
attacks operate across a population; this one targets a known individual.

Common files are unsuitable here and rare files are ideal. Where a tracker knows
that a specific person holds an unusual file, perhaps observed during an
authenticated session, a single query elsewhere approximates a test for that
person's presence. Large AI models are well suited to this purpose: few devices
hold any given one, they persist for long periods, and GREASE'ing is withheld
for files whose size makes a spurious re-download disproportionate, so the
answer is reliable.

**Example.** A researcher signs in to a specialist site and downloads an
uncommon model for medical image analysis, held by perhaps a few thousand
devices worldwide. The same operator later queries that hash on an
unauthenticated public forum, receives a positive answer, and has substantial
grounds to associate the anonymous forum account with the authenticated
identity.

---

## Attacks against the lookup budget

The explainer proposes limiting the number of cross-site lookups a site may
perform. The following attacks target that limit.

### Attack 6: Sybil attack on the budget

A Sybil attack defeats a per-identity limit by acquiring many identities. Where
the limit is counted per requesting origin, subdomains are unlimited and cost
nothing, so one tracker can present itself as several origins, embed each as a
frame, assign each a distinct portion of the work, and collect the results in
the parent frame through `postMessage`. Independent trackers on one page can
pool their allowances the same way, which makes this a **collusion** attack as
well.

**Example.** A limit permits eight lookups per origin per time window. The
tracker embeds four frames on four subdomains it controls. Each frame spends its
own eight lookups on a distinct set of files and returns the answers to the
page, producing 32 answers within a single page view. This is the reason the
explainer scopes the budget to the top-level site, shared across every frame on
the page.

### Attack 7: Rate-limit evasion by reload

A limit scoped to a single page load can be reset by the page, which can reload
itself without user interaction. The general pattern is a rate limit whose
counter is bound to a context the attacker controls.

**Example.** A tracker is permitted eight lookups per page load. Its page
reloads itself four times in under two seconds. Each load receives a fresh
allowance and spends it on a distinct set of files, yielding 32 answers. This is
the reason the count must persist across reloads.

### Attack 8: Cross-site leak through the loading path

The imperative lookup function is one of several paths to the cache. The
[HTML](README.md#html-integration),
[import attribute](README.md#javascript-import-attribute-integration),
[CSS](README.md#css-integration), and [fetch](README.md#fetch-integration)
integrations consult it as well.

These paths return no value to the page. The site nonetheless learns the outcome
by observing its own server, which is the classic XS-Leak pattern of reading a
side effect in place of a return value: a file served from the shared cache
produces no request, and that absence carries the same single bit as an explicit
answer.

**Example.** A tracker places 32 ordinary resource references on its page and
records which of them its server is asked for. The eleven that produce no
request are the files the device already held. The tracker obtains 32 answers
without calling the lookup function. This is the reason a limit must count every
path that reaches the cache.

---

## Attacks the design rules out

Two attacks are excluded by the current design. Both are described here because
they would become available if these properties were relaxed.

### Existence oracle through in-progress writes

Writing a large file takes time. If the browser registered an entry when a write
began, any site could distinguish "a write is in progress" from "never stored,"
which is a reliable one-bit existence oracle for an arbitrary hash, obtained
without storing anything and without passing the `origins` grants, the Public
Hash List, or GREASE'ing.

COS adds an entry only after a writer supplies the complete contents and the
browser verifies them against the hash. Until then the hash is reported as
absent, identically to a hash never written.

### Timing side channel

If a refusal returned faster for a file that is genuinely absent than for one
the browser is withholding, the elapsed time would disclose the answer and
bypass the protections above. Timing side channels of this kind are the most
common foundation for XS-Leaks on the web.

COS requires a refusal to be identical in content and in timing across all of
its causes: the file is absent, the requesting site is out of scope, or the
browser is withholding a file it holds.

---

## The mitigation problem

Every attack described here passes through one API. A tracker exploiting timing
side channels or accumulated platform quirks has many places to operate
undetected. A tracker using COS must issue an explicit, countable request, which
the browser can count, delay, or decline.

That property is what makes the problem tractable, and it also locates the
difficulty precisely. The protection is only as good as the accounting, which is
why Attacks 6 through 8, directed at the budget itself, warrant the same
attention as the identification attacks that precede them.
