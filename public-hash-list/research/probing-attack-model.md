<!--
  Copyright 2026 Google LLC
  SPDX-License-Identifier: Apache-2.0
-->

# Cross-site probing of the Public Hash List: models and measurements

This document develops the probabilistic models behind the cross-site probing attack that
[Cross-Origin Storage](https://wicg.github.io/cross-origin-storage/) (COS) and its
[Public Hash List](../phl-explainer.md) (PHL) have to survive, and it reports what those
models say once they are calibrated against the real published list and run.
[`probing-simulator.html`](probing-simulator.html) is the implementation: every number in
§12 names the preset that reproduces it.

This is exploratory research. Nothing here is a proposed change to the COS specification or to
the PHL inclusion criteria, and where a model contradicts a claim in the explainers, the
contradiction is an open question for discussion.

The attack under study is the one a fingerprinting library would actually run:

> Pick `n` hashes from the PHL, either at random or strategically. On every site that embeds
> the tracker, probe those `n` hashes and record the resulting bit vector. Two visits whose
> vectors agree, or agree closely enough, are very likely the same device, and the two sites
> are thereby linked despite storage partitioning, despite third-party cookie removal, and
> without ever writing any state.

That last clause is what makes COS interesting as a tracking surface. The COS store is
**global and unpartitioned**, and every probe is a *read* of state the attacker never had to
write. There is nothing to clear on a per-site basis and nothing that appears as the
attacker's own storage.

**Contents**

1. [Threat models](#1-threat-models)
2. [What the PHL actually contains](#2-what-the-phl-actually-contains)
3. [Notation and the observation channel](#3-notation-and-the-observation-channel)
4. [Model A: how much is in a probe set](#4-model-a-how-much-is-in-a-probe-set)
5. [Model B: cross-site linking as a hypothesis test](#5-model-b-cross-site-linking-as-a-hypothesis-test)
6. [Model C: targeted re-identification](#6-model-c-targeted-re-identification)
7. [Model D: history inference and the composition question](#7-model-d-history-inference-and-the-composition-question)
8. [Model E: cohort inference](#8-model-e-cohort-inference)
9. [Defenses, modeled](#9-defenses-modeled)
10. [Calibrating prevalence](#10-calibrating-prevalence)
11. [Attacker selection strategies](#11-attacker-selection-strategies)
12. [Results](#12-results)
13. [The write channel](#13-the-write-channel)
14. [Comparison to traditional fingerprinting](#14-comparison-to-traditional-fingerprinting)
15. [Directions worth evaluating](#15-directions-worth-evaluating)
16. [Limitations](#16-limitations)

---

## 1. Threat models

Four attacker goals share the same probe mechanics but have different optima, and conflating
them is the most common way to get this analysis wrong. A probe set that is excellent for one
is often worthless for another, and §12 contains a measured example of a probe set that scores
at chance on one goal while succeeding on another.

| | Goal | What the attacker wants from a resource | Optimal prevalence |
| --- | --- | --- | --- |
| **A** | **Cross-site linking.** Same device, two unrelated sites, same tracker. | Maximum linking margin per probe. | mid-range |
| **B** | **Targeted re-identification.** "Is this the device that visited *my* site last week?" | Maximum surprisal when present. | `p → 0` |
| **C** | **History inference.** "Which sites has this device visited?" | Small, well-understood serving set. | at the k-anonymity floor |
| **D** | **Cohort inference.** "Does this device run in-browser AI? Read Japanese?" | Category-diagnostic, any prevalence. | the cohort's base rate |

The PHL's inclusion criteria bound the number of *hosts* a resource is served from, which is a
statement about goal C. Goals A, B, and D turn on how a resource's presence is distributed
across *users*, or on what the resource means, and the criteria do not speak to them. §12
measures how much that matters for each.

Assume throughout that the resources probed are `origins: '*'` entries on the PHL, so
availability gating passes and only GREASE'ing and rate limiting stand between the attacker and
a truthful answer. Resources scoped to an explicit `origins` list are out of a third party's
reach by construction and are not modeled.

### The attacker's execution context matters

Two deployments of the same tracker differ in one respect that turns out to decide whether
origin-keyed defenses work at all (§9.2):

* **Third-party frame.** The tracker loads `https://tracker.example/frame.html` in an iframe
  and probes from there. The **requesting origin is `tracker.example` on every site.** This is
  the deployment that storage partitioning and third-party cookie removal were built to defeat,
  and it is the natural one for a tracker.
* **First-party script.** The tracker ships as `<script src="…/t.js">` executing in the
  embedding page. The **requesting origin is the embedding site**, different on every site.
  This is how most analytics and anti-fraud vendors deploy today.

The attacker chooses. Any defense whose strength depends on the requesting origin differing
between site A and site B is a defense the attacker opts out of by moving into an iframe.

---

## 2. What the PHL actually contains

Everything below is measured from the published list, `VERSION: 2026-09-14T09:25:20Z`,
`COMMIT: d5092c6`, fetched from
[`data/public-hash-list.dat`](https://media.githubusercontent.com/media/WICG/cross-origin-storage/refs/heads/main/public-hash-list/implementation/data/public-hash-list.dat).
These numbers are the simulator's default calibration. The explainer's "301,618 distinct
hashes" is a figure from an earlier run; the list has grown by 45% since.

**438,684 digests total.**

| Section | Digests | Share |
| --- | ---: | ---: |
| `===BEGIN SHA-256===` (core) | 293,522 | 66.9% |
| `===BEGIN SHA-256 HUGGING-FACE===` | 145,161 | 33.1% |
| `===BEGIN SHA-256 MANUAL===` | 1 | <0.1% |

Core section, by the source that vouched for the entry:

| Provenance | Digests |
| --- | ---: |
| HTTP Archive only | 254,077 |
| Google Fonts only | 33,181 |
| cdnjs (npm download rank) | 2,258 |
| YouTube player | 1,351 |
| Google Fonts + HTTP Archive | 1,304 |
| Google Hosted Libraries only | 270 |
| HTTP Archive + Microsoft Ajax CDN | 264 |
| Microsoft Ajax CDN only | 199 |
| everything else (jsDelivr, Maps, Chromium pervasive, nuxt-cos, multi-source combinations) | ~618 |

Core section by file type: `.js` 151,059, `.css` 82,061, `.woff2` 47,289, `.ttf` 3,615,
`.woff` 3,050, `.otf` 542, `.mjs` 306, `.wasm` 125.

Hugging Face section, by file type:

| Type | Digests | Runtime | Typical size |
| --- | ---: | --- | --- |
| `params_shard_*.bin` | 80,564 | WebLLM | 8–128 MB per shard |
| `.gguf` | 33,342 | wllama / llama.cpp-Wasm | up to the 20 GiB cap |
| `.onnx` | 21,923 | Transformers.js, ORT Web | 10 MB–2 GB |
| `.tflite` | 7,858 | LiteRT.js / MediaPipe | 1 MB–4 GB |
| `tokenizer.json` | 1,026 | sidecar | median 0.80 MB, p90 5.7 MB, max 17.1 MB, measured over the 1,478 sidecars in the build's download cache |
| `.litertlm`, `.task` | 448 | LiteRT / MediaPipe | 1 MB–4 GB |

### 2.1 The HTTP Archive tier is self-hosted assets, and this matters

The HTTP Archive source admits a hash once it appears on ≥100 distinct origins, and the query
defines an origin as `NET.HOST(url)` over the *request* URL. That counts the hosts the bytes
are **served from**, and the sites that **embed** them never enter the count. For a self-hosted asset (a plugin's
script, copied into every installation) the two coincide. For a CDN-hosted asset they diverge
completely: every site on the web loading jQuery from one CDN is a single serving host, so the
gate sees 1.

The published list bears this out. Taking the example URL of each of the 254,077
HTTP-Archive-only entries:

| Measurement | Value |
| --- | ---: |
| distinct example hosts | 237,328 |
| hosts appearing exactly once | 225,289 |
| most frequent single host (`usercontent.one`) | 52 entries |
| entries whose example URL contains `wp-content` or `wp-includes` | 108,224 (42.6%) |

`cdnjs.cloudflare.com`, `cdn.jsdelivr.net`, and `fonts.gstatic.com` appear 15, 19, and 24 times
respectively. CDN-hosted resources essentially cannot enter through this source, which is
exactly why the nine curated catalogs exist. Two consequences follow, and §7 measures both:

* The gate is a real, working control **for the tier it governs**, and it governs a tier that
  is overwhelmingly per-site self-hosted assets, 43% of them WordPress plugin and theme files.
* It governs nothing else. The curated catalogs and the model hub admit entries on other
  grounds, so raising or lowering the number does not touch them.

### 2.2 Three structural facts

1. **Eighty-six percent of the core section is the HTTP Archive tier**, sitting at or just
   above the k-anonymity gate.
2. **A third of the whole list is AI model weights**, which are rare per user, enormous, and,
   under the size-proportionate GREASE rule, **exempt from GREASE'ing**.
3. **The list is orders of magnitude larger than the attack needs.** Linking across the whole
   web needs roughly 30 bits (§5.4). §12 reaches that with 64 probes.

---

## 3. Notation and the observation channel

A device `d` has a cache state `X_d ∈ {0,1}^R` over the PHL's `R` hashes, where `X_{d,i} = 1`
iff hash `i` is present in `d`'s COS store. Write `p_i = P(X_i = 1)` for the **population
prevalence** of resource `i` over devices, `S` for the attacker's probe set with `|S| = n`, and
`V ∈ {0,1}^n` for the observed vector.

### 3.1 The channel is one-sided

From the [read-path response table](../../README.md#read-path), a probe answers `1` only when
the entry is present, globally disclosable, on the PHL, and not GREASEd. No path returns a
handle for an absent file. So

```
P(V_i = 1 | X_i = 0) = 0
P(V_i = 0 | X_i = 1) = g_i
```

where `g_i` is the GREASE'ing probability. This is a **Z-channel**: false negatives only, no
false positives. Three consequences run through everything below.

* **A `1` is proof.** Every observed `1` is ground truth about the device's cache, and the
  attacker never has to discount a positive. This is why cohort inference has precision 1 by
  construction (§8).
* **Repetition erases independent noise.** If the GREASE coin is flipped per probe, `r` probes
  of one hash produce a false negative only when all `r` flip against the attacker: `g_i^r`.
  The attacker takes the OR; there is no symmetric move for the defender.
* **Noise is asymmetric in cost.** Suppressing a `1` costs a real download for a real user,
  while a false `1` would cost only a wasted COS read. The specification permits only the
  expensive kind, which is what forces the size exemption of §9.3.

Define the **effective observed prevalence** of a single probe as `a_i = p_i(1 − g_i)`, and
with `r` independent repeats OR'd together, `a_i(r) = p_i(1 − g_i^r)`. Everything downstream
uses `a_i`, the quantity the attacker measures directly; `p_i` can only be inferred.

---

## 4. Model A: how much is in a probe set

### 4.1 Three entropies, and why none of them is the answer

Under independence across resources the vector distribution factorizes. With
`h(x) = −x log₂ x − (1−x) log₂(1−x)`:

```
H₁(V) = Σᵢ h(aᵢ)                                   Shannon: average surprisal      (4.1)
H₂(V) = −log₂ Πᵢ (aᵢ² + (1−aᵢ)²)                   collision: two devices agree    (4.2)
H_∞(V) = −Σᵢ log₂ max(aᵢ, 1−aᵢ)                    the most common vector's crowd  (4.3)
```

Always `H_∞ ≤ H₂ ≤ H₁`, with equality only when every `aᵢ = ½`. For skewed prevalences the gap
is large, and reporting `H₁` alone, as the fingerprinting literature usually does, overstates
the attacker. For 1,000 resources at `p = 0.001`: `H₁ = 11.4` bits, `H₂ = 2.88` bits,
`H_∞ = 1.44` bits. The same 1,000 at `p = 0.5` give 1,000 bits on all three.

But all three describe a *single* observation, and linking compares *two*. They say nothing
about GREASE noise that differs between the visits, and nothing about a cache that changed
between them. §12 (F9) contains a probe set with `H₁ = 63.5` bits and `H₂ = 63.1` bits whose
actual linking margin, once the channel is accounted for, is 0.1 bits.

### 4.2 The quantity that does answer it

For the two-hypothesis problem of §5, the right additive quantity is the **Bhattacharyya
distance** between the same-device joint `θᵢ` and the different-device product `mᵢ`:

```
B = Σᵢ −log₂ ( Σ_{k ∈ {00,01,10,11}} √( θᵢ(k) · mᵢ(k) ) )                        (4.4)
```

`B` is additive across independent probes, so an attacker maximizes it by simply taking the
top-`n` resources by per-probe contribution, and the probability of confusing the two
hypotheses is bounded by `2^−B`. It is the simulator's headline number, called the **linking
margin**, and it accounts for GREASE'ing, for the keying of that GREASE'ing, and for cache
drift, all three of which the entropies leave out. When there is no noise and no drift it coincides with the
entropies; when there is, it is the only one of the four that tracks measured performance.

### 4.3 Anonymity sets

For an observed vector `v`, the self-information and the expected number of devices that look
identical in a population of `N` are

```
I(v) = −log₂ P(v)      A(v) = N · 2^(−I(v))                                      (4.5)
```

A device is **singled out** when `A(v) < 1`. `A` is a per-vector quantity: the all-zeros
vector has a huge anonymity set while a vector with three rare hits is usually unique.
Averaging hides exactly the users most at risk, so the simulator reports the distribution and
the fraction of the population that is unique, and it reports the self-information of
*carriers* separately (§6).

### 4.4 Correlation

Independence is false in the PHL in a structured way, and the simulator's generative mode
(§10.2) exists to measure the error: all Unicode subsets of one font family arrive together
(47,289 `.woff2` files across ~1,500 families), all `params_shard_*.bin` of one model arrive
together (80,564 shards across a few thousand models), and a site's `.js` and `.css` arrive
together. Correlation only ever reduces joint entropy below `Σ h(aᵢ)`, so (4.1)–(4.3) are upper
bounds. An attacker who knows the clustering (public information: load the pages) avoids
wasting budget on correlated resources, which is the `decorrelated` strategy of §11.

---

## 5. Model B: cross-site linking as a hypothesis test

Site A produces `v` at `t₁`, site B produces `w` at `t₂`, and the attacker decides whether they
are the same device.

### 5.1 State drift between the two visits

Model each resource's state as a stationary two-state Markov chain with stationary distribution
`p` and a single **persistence** parameter `ρ ∈ [0,1]`: the lag correlation across the
inter-visit interval, `ρ = 1` a frozen cache, `ρ = 0` a fully re-randomized one. Stationarity
then fixes the joint with no further parameters:

```
P(X_A = 1, X_B = 1) = p² + ρ·p(1−p)
P(X_A = 1, X_B = 0) = P(X_A = 0, X_B = 1) = p(1−p)(1−ρ)
P(X_A = 0, X_B = 0) = (1−p)² + ρ·p(1−p)                                          (5.1)
```

This is where the defender has the most real leverage and the least control: `ρ` is set by
eviction policy and by how far apart the visits are, and COS controls neither. `ρ` is
per-resource, because multi-gigabyte weights are evicted and re-acquired on quite different
timescales than a 12 KB stylesheet, and the tier table sets it from 0.75 for the long tail to
0.98 for GGUF weights.

### 5.2 The likelihood ratio

Let `θᵢ(vᵢ, wᵢ)` be the joint probability of the observation *pair* under `H₁` (same device),
obtained by pushing (5.1) through the GREASE channel of §9.2, and `aᵢ` the marginal. Under `H₀`
the two observations are independent with those marginals, so the log-likelihood ratio is
additive:

```
Λ(v, w) = Σᵢ log₂ [ θᵢ(vᵢ, wᵢ) / (P(vᵢ) · P(wᵢ)) ]                               (5.2)
```

and the attacker links iff `Λ ≥ τ`. This is the Neyman–Pearson optimal test for the model, so
it upper-bounds any heuristic; the simulator also implements Hamming distance and Jaccard
similarity on the `1`-sets so the cost of a heuristic can be seen.

The per-bit contributions explain the attack's character. With no GREASE and `ρ = 1`:

```
(1,1): log₂(1/a)        a rare match is worth many bits
(0,0): log₂(1/(1−a))    a common miss is worth almost nothing
(1,0) or (0,1): −∞      one mismatch refutes the hypothesis outright
```

Drift and GREASE'ing are what turn that `−∞` into a finite penalty, which is why the attack
degrades gracefully as noise rises, and why "similar enough" in the informal statement of
the attack is the right formulation.

### 5.3 Deciding, and the false-positive budget

* **Verification.** One pair, one decision: report the ROC and the AUC. The relevant operating
  point is the TPR at an FPR small enough to keep the tracker from drowning in false links; with `M` gallery entries, `FPR = 1/M` yields `O(1)` false matches per query.
* **Identification (1:M).** Score `v` against all `M` gallery vectors and take the argmax:
  report **rank-1 accuracy**. This is the realistic setting and it is strictly harder, because
  the attacker must beat `M−1` impostors.

With a uniform prior over `M` candidates the posterior odds of a particular pairing are
`2^Λ / M`, so the attacker needs `Λ ≳ log₂ M + log₂(1/η)` for confidence `1−η`.

### 5.4 The 30-bit rule of thumb

In the noiseless, no-drift case `Λ = I(v)` when `v = w` and `−∞` otherwise, which collapses the
threshold to a rule worth memorizing:

> **Linking works when the probe set carries more than `log₂ M` bits of margin.**

| Attacker scale `M` | bits required |
| --- | ---: |
| One site's monthly uniques (10⁶) | 20 |
| A large ad network (10⁸) | 27 |
| Every device on the web (10¹⁰) | 33 |

Against ~33 bits, consider what the list offers: `H₂ = 33` needs 33 resources at `p ≈ ½`, or
~150 at `p ≈ 0.1`, or ~3,000 at `p ≈ 0.01`, out of 438,684. The conclusion does not depend on
fine details of the prevalence model.

---

## 6. Model C: targeted re-identification

The attacker holds a target vector `u` captured once, tied to an identity, and wants to
recognize that device elsewhere. The test is still (5.2), but the optimum inverts: what matters
is the surprisal of a *match*, `−log₂ aᵢ`, and the average margin drops out. A single `p = 10⁻⁴` resource
matching contributes 13.3 bits; three are 40 bits, past the whole-web threshold.

The catch is coverage. A rare resource is informative only for the small fraction of devices
that have it, so the targeted probe set is built *from the victim's own vector*. This makes the
average-case metrics of §5 the wrong instrument, and the simulator reports a separate
**carrier-restricted** block: the devices holding at least one probed resource, their median
self-information, and rank-1 accuracy among them. §12 shows a probe set scoring 0.000 rank-1
overall and 0.121 among carriers, from the same run.

This is the mode where the Hugging Face section is most exposed. A specific quantization of a
specific model, on a device that fetched it once, is close to a persistent identifier: rare, so
high surprisal; enormous, so `ρ ≈ 1`; and, per §9.3, never GREASEd.

---

## 7. Model D: history inference and the composition question

This is the goal the `num_origins ≥ 100` gate is aimed at, and the one place where the gate
does direct work.

Let resource `i` be served by host set `O_i` and embedded on site set `E_i`, and let `q_j` be
the probability that a device visited site `j` within the retention window. Prevalence follows
from the *embedding* sites, while the gate counts the *serving* hosts (§2.1):

```
pᵢ = 1 − Π_{j ∈ Eᵢ} (1 − q_j) ≈ 1 − exp(−λᵢ),   λᵢ = Σ_{j ∈ Eᵢ} q_j             (7.1)
```

Observing `Vᵢ = 1` licenses exactly one conclusion: the device visited at least one site in
`Eᵢ`. Observing `Vᵢ = Vⱼ = 1` licenses the conjunction, and the intuition that this collapses
onto `Eᵢ ∩ Eⱼ` is where the analysis has to be careful. **A small intersection is not on its
own evidence.** Between two resources each on thousands of sites, a singleton intersection
arises by chance and means nothing; the device most likely hit the two resources on two
different sites. The correct test compares the two explanations:

```
odds(shared site) = ( Σ_{s ∈ Eᵢ ∩ Eⱼ} q_s ) / ( pᵢ · pⱼ )                        (7.2)
```

The numerator is the chance of one visit explaining both observations; the denominator is the
chance of two independent visits doing so. The simulator pins a site only when this exceeds
10:1 and the intersection is at most `c`.

Two mitigations are exposed as knobs and measured in §12: raising the floor, and the
co-deployment structure of the site graph, which is what decides how often two probed resources
are held by the same device at all.

---

## 8. Model E: cohort inference

Cohort inference needs no identification and survives every defense in §9 except removing
resources from the list. Assign each resource a cohort; observing any `1` in a cohort raises
the posterior of membership, with

```
P(≥1 hit | member) = 1 − Π (1 − pᵢ | member)                                      (8.1)
```

over the probed members. Because the attacker chooses how many members to probe, this can be
pushed close to 1 for a handful of probes, and because the channel has no false positives,
**precision is 1 by construction**. Recall is the only thing probes buy.

The PHL's own documentation
[accepts this explicitly](../phl-explainer.md#a-hand-curated-source-a-recognized-ai-model-hub)
for the Hugging Face section: "the disclosure such an entry permits is coarse interest
inference ('this user runs in-browser AI models')". The models let that claim be priced, and
they say two things about it. "Runs in-browser AI" is indeed one bit, and §12
measures how cheaply it is obtained. But the section does not stop at one bit: *which* model,
at which quantization, is a much finer signal, and a medical-imaging ONNX model, a specific
language's speech model, or an uncensored GGUF are not as innocuous as the headline framing.
Font subsets are the other cheap cohort, since a `.woff2` subset file carries its Unicode range
and its presence is a language and region signal.

---

## 9. Defenses, modeled

### 9.1 What is on the table

From the explainer and specification: PHL membership gating (assumed passed), GREASE'ing, probe
rate limiting, and machine-learning fingerprinting detection. The models cover the first three.
Detection is modeled only as a hard probe budget, since modeling a classifier's accuracy would
be inventing numbers.

### 9.2 GREASE'ing: the keying question decides everything

The specification says "occasionally responding as if the entry were absent" without saying
what the coin is keyed on. That choice decides whether GREASE'ing does anything against linking,
and the probability `g` only matters once the keying is right. Four keyings are all consistent with the text:

| Keying | Defeated by repeats? | Decorrelates A from B? | Verdict |
| --- | --- | --- | --- |
| **K1** per probe (i.i.d.) | Yes, at cost `r` | Yes | Strength equals the probe budget |
| **K2** PRF(device, origin, hash) | No | **Only if the origin differs** | Attacker moves to an iframe |
| **K3** PRF(device, origin, hash, epoch) | No, within an epoch | Only across epochs | The only one that works |
| **K4** PRF(device, hash) | No | **No** | No unlinkability value at all |

**K1 (fresh coin per call).** `r` repeats reduce the false-negative rate to `g^r`. With budget
`B` and identical resources of prevalence `p`, the attacker solves

```
maximize over r ∈ ℕ:   I(r) = (B / r) · (per-probe margin at gᵣ = g^r)            (9.1)
```

and the simulator plots it so the optimum can be read off. **Under K1, GREASE'ing acts as a
multiplier on the probe budget, worth exactly as much as the rate limit behind it.**

**K2 (keyed on the requesting origin).** Repetition is useless, but the mask is a deterministic
function of `(device, origin, hash)`, so an attacker probing from one fixed origin observes the
*same* mask on both sites. The observations pass through an identical deterministic map, and
linking proceeds as on a noiseless channel with effective prevalence `a = p(1−g)`. A surviving
`1` is now *more* informative than it was without GREASE'ing, because it is rarer:

```
(1,1) contribution under K2, same origin:  log₂(1/a) = log₂(1/p) + log₂(1/(1−g))
```

§12 confirms the prediction and its sign: at `g = 0.5` the measured margin is **higher** than
with GREASE'ing off. For a first-party deployment K2 behaves like K3, so the attacker simply
declines that deployment.

**K3 (keyed on origin and a time epoch).** Masks are independent across epochs, so two visits
in different epochs see genuinely independent noise. This is the only keying that provides
cross-site unlinkability against an iframe attacker, and it is the one to specify if
GREASE'ing is meant to be more than decorative. Its benefit decays as the attacker probes
across many epochs and ORs the results, so epoch length trades directly against how long a
tracker has to observe a device.

**K4 (keyed on the device and hash only).** Every origin sees the same mask forever, which
suppresses a random `g`-fraction of the device's cache globally and permanently and provides
**zero** protection against linking: the masked vector is a deterministic function of the true
state and is identical everywhere. It is the worst of the four and it is what a naive "seed the
RNG per device" implementation produces.

The general statement:

> GREASE'ing that is deterministic in the attacker's observable context provides no cross-site
> unlinkability, and GREASE'ing that is random per observation is defeated by repeated probing.
> The only configuration that resists both re-randomizes on an axis the attacker cannot hold
> fixed, namely time, combined with a probe budget that makes repetition expensive.

### 9.3 The size-proportionate rule creates a noise-free channel

The specification requires that user agents "must not apply GREASE'ing to entries whose size
makes a spurious re-download clearly disproportionate", which is unarguable as a performance
matter and has an unfortunate corollary. With `L` the size threshold,

```
gᵢ = g   if sizeᵢ ≤ L
gᵢ = 0   if sizeᵢ > L                                                             (9.2)
```

and the attacker's response is immediate: **probe only resources larger than `L`.** Those
probes are noiseless, there are 145,161 of them in the Hugging Face section alone, and they are
also the rarest (high surprisal on a match) and the most persistent (`ρ ≈ 1`). The rule removes
noise from exactly the subset where noise would matter most, and §12 measures the consequence:
past a certain `g` the attacker switches to the exempt subset and **raising `g` further changes
nothing at all.**

### 9.4 Probe budgets

A budget `B` per (origin, site, epoch) caps `n·r ≤ B`, which is what makes (9.1) a real
constraint. Two observations:

* **The bar is tens of probes.** §12 reaches rank-1 1.000 with 64 probes and 0.718 with 16. A
  budget of 100 probes per visit leaves linking fully available and only limits exhaustive
  history enumeration.
* **Budgets must be per requesting origin and must count every surface.** The explainer already
  says this (the fetch, Service Worker, and preload integrations all count). The models add
  that a budget resetting per top-level site is no budget at all against the iframe attacker,
  who gets a fresh allocation on every site it is embedded in.

---

## 10. Calibrating prevalence

### 10.1 Parametric mode: prevalence from traffic-weighted reach

Equation (7.1) bridges the list's own data to a prevalence, `pᵢ = 1 − exp(−λᵢ)`, where `λᵢ` is
the expected number of visited sites serving resource `i`. The HTTP Archive query the PHL
already runs computes an estimator of exactly that:

```sql
SUM(100000.0 / min_rank) AS traffic_weighted_score
```

Under a Zipf popularity law, visit probability is proportional to `1/rank`, so
`traffic_weighted_score ∝ λ` with one calibration constant. The simulator draws
`λᵢ ~ LogNormal(μ, σ)` per tier, fitted from a median and a p99 prevalence entered in the tier
table, with tier sizes taken from §2. Draws are truncated at twice the tier's p99 so that the
lognormal tail cannot manufacture a single near-universal outlier inside a tier of rare
resources. It also accepts the published `public_hash_list.csv` so the fitted distribution can
be replaced with the measured one; that host is not reachable from every environment, which is
why the parametric defaults are the primary path.

Default tier parameters, chosen so the prevalence distribution reproduces the known anchors:

| Tier | Count | median `p` | `p` at p99 | median size |
| --- | ---: | ---: | ---: | ---: |
| Core, pervasive (Chromium, GHL, Maps, YouTube, top cdnjs) | 1,800 | 0.35 | 0.93 | 90 KB |
| Core, Google Fonts latin | 24,000 | 0.004 | 0.30 | 25 KB |
| Core, Google Fonts non-latin | 10,485 | 0.0008 | 0.06 | 35 KB |
| Core, HTTP Archive long tail | 254,077 | 0.002 | 0.10 | 35 KB |
| Core, wasm/mjs/misc | 3,160 | 0.02 | 0.50 | 120 KB |
| HF, tokenizers | 1,026 | 4·10⁻⁴ | 0.01 | 0.8 MB |
| HF, ONNX / TFLite / LiteRT | 30,229 | 1·10⁻⁴ | 6·10⁻³ | 120 MB |
| HF, WebLLM shards | 80,564 | 6·10⁻⁵ | 3·10⁻³ | 40 MB |
| HF, GGUF | 33,342 | 4·10⁻⁵ | 2·10⁻³ | 2.5 GB |

Every one of these is a slider, and the findings in §12 are reported as sweeps across them,
because the absolute numbers depend on these values.

### 10.2 Generative mode: sites, resources, and correlation

Parametric mode cannot produce correlation, composition, or history inference, so the simulator
also builds an explicit bipartite graph:

1. `S` sites with Zipf(`α`) popularity, normalized to a visit probability `q_j`.
2. Resource clusters (a font family's subsets, a model's shards, a plugin's `.js` + `.css`)
   assigned to sites with a Pareto-distributed count, drawn partly from the cluster's own
   **community** and partly from the whole pool. Communities stand in for co-deployment: the
   sites running the same CMS, theme, or plugin bundle.
3. **Serving hosts are tracked separately from embedding sites**, per §2.1: for a self-hosted
   tier they coincide, for a CDN-backed tier there are one to three hosts however many sites
   embed the resource.
4. PHL admission applies the `kAnon` gate to serving hosts for the self-hosted tier only; the
   curated catalogs and the model hub are admitted on other grounds, as the explainer states.
5. A device samples visits by popularity, caches the union of resources on visited sites, and
   drifts between the two visits.

Prevalence then falls out of the graph, correlation appears for free, and the ground
truth needed for §7 and §8 is available for scoring the attacker's inferences.

---

## 11. Attacker selection strategies

| Strategy | Objective | Notes |
| --- | --- | --- |
| `random` | none | Uniform over the PHL. The baseline in the informal attack description. |
| `linkage` | `max Σ Bᵢ` (4.4) | The correct attacker. Additive, so top-`n` is optimal. |
| `entropy` | `max Σ h(aᵢ)` | The naive attacker. See the warning below. |
| `collision` | `max Σ H₂(aᵢ)` | Between the two. |
| `rarest` | `max −log₂ aᵢ` subject to `aᵢ ≥ 5/N` | Goal B. The floor matters: a resource nobody has is maximally surprising and completely useless. |
| `greaseExempt` | `max Σ Bᵢ` s.t. `sizeᵢ > L` | The §9.3 counter-strategy. |
| `decorrelated` | greedy `max Σ Bᵢ`, one per cluster | A competent attacker that does not waste budget on co-arriving resources. |
| `nearFloor` | smallest embedding-site set, any section | Goal C, site mode. |
| `nearFloorGated` | the same, restricted to the gated tier | Goal C with the gate actually binding, site mode. |

**Maximizing observed entropy is a trap, and the simulator demonstrates it.** Under noisy
GREASE'ing, the resources whose *observed* prevalence sits near ½ are those whose *true*
prevalence is near 1: their apparent entropy is entirely the user agent's noise,
and they link nothing. Measured against an `entropy` attacker, epoch-keyed GREASE'ing looks
far stronger than it is (F9). The defender should assume the attacker optimizes (4.4).

Two realism knobs are exposed. **Prevalence knowledge**: the strategies assume the attacker
knows `aᵢ`, which a tracker embedded on many sites measures directly from its own traffic; the
simulator can perturb the estimates (`â = a·exp(N(0,σ²))`) to show how much precision is needed,
and the answer is very little, because the objective is flat near its optimum. **Selection
visibility**: a probe set concentrated at `p ≈ ½` is itself anomalous and is plausibly what a
detector would look for, so the simulator reports the mean `|a − ½|` of the chosen set as a
crude detectability proxy.

---

## 12. Results

All runs use the parametric universe at full scale (438,684 resources) unless stated, 20,000
simulated devices, a gallery of 2,000, `M = 10⁹`, seed 12345, and the default tier table.
"Margin" is `B` from (4.4); "rank-1" is 1:2,000 identification accuracy. Presets in the
simulator's scenario dropdown reproduce each row.

### F1. The list is far larger than the attack requires

Linking across the whole web needs ~33 bits of margin. The measured margin of a
channel-aware 64-probe set with no GREASE'ing is **15.3 bits at rank-1 1.000**, and 256 probes
give **61.0 bits**. Since the criteria bound serving-host counts and the attack turns on user
prevalence, no plausible tightening of the inclusion criteria changes this.

### F2. Strategic selection is worth roughly 50× the probe budget

*(presets F2a, F2b; GREASE off)*

| Strategy | n = 16 | n = 64 | n = 256 |
| --- | --- | --- | --- |
| `random` margin / rank-1 / unique | 0.1 / 0.004 / 0.0% | 0.3 / 0.044 / 1.0% | 1.3 / 0.348 / 26.4% |
| `linkage` margin / rank-1 / unique | 3.8 / 0.718 / 73.5% | 15.3 / **1.000** / 100% | 61.0 / 1.000 / 100% |

Per probe, the channel-aware attacker extracts 0.238 bits against random selection's 0.005, a
factor of 47. **Sixteen strategically chosen probes beat 256 random ones.** Random draws land
overwhelmingly in the long tail where `h(p) ≈ 0`, which is why the informal version of this
attack understates it.

### F3. The k-anonymity gate works, and 100 is past the knee

*(presets F3a, F3b; generative site mode, 60,000 sites, 2,048 probes on the gated tier, 1,500
devices analyzed, site-pinning at odds ≥ 10:1 with intersection ≤ 3)*

| Gate (serving hosts) | Devices with a site pinned | Accuracy of the pin |
| ---: | ---: | ---: |
| 5 | **20.27%** | 97.7% |
| 25 | 0.40% | 100% |
| 100 (the real value) | **0.00%** | — |
| 500 | 0.00% | — |

Composing two gated resources leaves the gate intact: requiring a shared site to explain both observations better than two separate visits is a much
higher bar than a small set intersection, and at 100 hosts essentially no device is pinned. The
knee is between 5 and 25, so the chosen value carries real margin.

Three caveats keep this from being a clean bill of health.

* **The gate governs one tier.** Probing for the smallest embedding-site sets across *all*
  sections pins a site for 0.33–0.40% of devices at 100% accuracy, **and that number does not
  move with the gate**, because the smallest site sets on the list belong to the sections the
  gate does not touch: the curated catalogs and the Hugging Face section.
* **It counts serving hosts** (§2.1), so it measures self-hosting diversity. It is
  structurally near-inert for anything behind a CDN.
* **It does nothing for goals A, B, or D.** Every other finding here is unaffected by it.

### F4. GREASE'ing's value is decided by its keying, which is unspecified

*(presets F4a–F4c; 64 probes, size exemption disabled so everything is GREASEable)*

| Keying | g | Context | Margin | rank-1 |
| --- | ---: | --- | ---: | ---: |
| none | 0 | — | 15.3 | 1.000 |
| **K2** | 0.5 | iframe | **24.6** | **1.000** |
| **K4** | 0.5 | any | **24.6** | **1.000** |
| K3, visits in one epoch | 0.5 | iframe | 24.6 | 1.000 |
| K2 | 0.5 | first-party script | 1.1 | 0.202 |
| **K3, visits in different epochs** | 0.5 | iframe | **1.1** | **0.202** |
| K1, r = 1 | 0.8 | — | 0.1 | 0.012 |
| K1, r = 2 | 0.8 | — | 0.5 | 0.072 |
| K1, r = 4 | 0.8 | — | 1.8 | 0.414 |

Three things to read off. Under K2 and K4 against an iframe, GREASE'ing at `g = 0.5` leaves the
attack at rank-1 1.000 and **raises** the margin from 15.3 to 24.6 bits, exactly as §9.2
predicts: fewer `1`s survive, and each survivor is rarer and so worth more. Under K1,
repetition buys the margin back, at `r` times the budget. Only epoch-keyed K3 with visits in
different epochs cuts the attack, and even that only raises the cost: at
`g = 0.5` it takes the attacker from 64 probes to ~1,024 for rank-1 1.000, a 16× budget
multiplier (margin 1.2 at n=64, 4.7 at n=256, 17.9 at n=1,024, 58.1 at n=4,096).

**Specifying the keying is a higher-value change than tuning the probability.**

### F5. The size exemption makes the GREASE probability stop mattering

*(preset F5a)* With the size limit at its default 10 MB and a channel-aware attacker, the
measured margin, rank-1 accuracy, and unique fraction are **identical at g = 0.5, 0.8 and
0.95** (margin 1.2, rank-1 0.034). Past `g ≈ 0.4` the attacker abandons the GREASEable
resources entirely for the exempt ones, and the defense parameter drops out of the result. The
same holds when the exempt subset is targeted directly: `greaseExempt` at `g = 0` and at
`g = 0.95` produce bit-identical output.

The resources above the threshold are also the rarest and most persistent on the list, so the
rule removes noise from exactly the subset where noise would matter most.

### F6. Threat models A and B come apart, measurably

*(preset F5b/F6)* A `rarest` probe set of 64 AI weights at `g = 0.9` scores **rank-1 0.000 and
AUC 0.503** on the population — indistinguishable from chance — while, restricted to the 33
devices in the gallery that actually carry one of those weights, each carries **12.0 bits** and
rank-1 among them is **0.121**, rising to 0.267 at `r = 2` and **0.433** at `r = 4`. A probe
set can be useless on average and effective against the people it was built for, and a metric
that only reports the average will miss it entirely.

### F7. Omitting the Hugging Face section does not reduce linking power

Running the channel-aware attacker with the HUGGING-FACE section excluded gives **exactly the
same result** as including it: margin 15.3, rank-1 1.000. The core section alone is more than
sufficient for goal A. The section's risk is concentrated in goals B and D, so the `SHOULD`/`MAY`
choice a user agent makes about that section is a decision about targeted and cohort inference,
and it has no bearing on linking.

### F8. Cohort inference is cheap and precise

Eight probes per cohort, drawn from each cohort's most prevalent members, give precision 1.000
throughout (by construction, §3.1):

| Cohort | Base rate | Recall at 8 probes |
| --- | ---: | ---: |
| runs in-browser AI | 0.029 | **0.997** |
| latin web fonts | 1.000 | 0.999 |
| non-latin font subsets (a language and region signal) | 0.355 | 0.961 |
| long-tail site assets | 1.000 | 0.834 |

Eight probes is a rounding error against any plausible budget, so "this device runs in-browser
AI models" is available essentially for free and at perfect precision. No defense in §9
addresses this; only removing resources from the list does.

### F9. Entropy overstates the attacker, sometimes by a lot

A naive 64-probe set under epoch-keyed GREASE'ing at `g = 0.5` measures `H₁ = 63.5` bits and
`H₂ = 63.1` bits, and links at **rank-1 0.002** — its actual margin is **0.1 bits**, an
overstatement of roughly 600×. The entropies count the user agent's noise as though it were the
device's state. Any assessment of this attack surface that reports "bits of identifying
information" without specifying the channel is not measuring the thing it claims to measure,
and the error runs in the alarming direction.

---

## 13. The write channel

Sections 1 through 12 model an attacker reading state the user's own browsing created. COS also
lets a site *write*: [`requestFileHandle(hash, {create: true})`](../../README.md#write-path)
supplies the bytes, they are hash-verified, and the entry is stored. A tracker can use that to
plant a chosen bit pattern on site A and recover it on site B, which turns COS into a writable,
unpartitioned, cross-site store. This is a different attack from probing, and it is the one that
most resembles the mechanism cookie partitioning was built to remove.

The simulator models it under **Channel → write**, with two presets: F10 (supercookie) and F11
(global grant). Both are calibrated against the same 438,684-entry universe as the read channel.

### 13.1 Two ways to read the write back

The [read-path grant table](../../README.md#read-path) admits two cross-site routes to a
planted bit, and the attacker picks per deployment.

* **Storing-origin readback (W1, the supercookie).** A third-party iframe `tracker.example`
  writes the bytes on site A and reads them on site B. On both sites the requesting origin is
  `tracker.example`, so it qualifies as a **storing origin**, which "always succeeds,
  independent of PHL, `origins`, or GREASE'ing". The attacker writes content it authored, so it
  can use hashes no honest user would ever hold, and the readback is a clean, noise-free channel
  bounded only by eviction and quota. It needs no PHL entry. Its one prerequisite is the
  [`cross-origin-storage` Permissions Policy](../../index.bs), whose default allowlist is
  `self`, so the embedding site must grant `allow="cross-origin-storage"` to the iframe.
* **Global-grant readback (W2).** A first-party script writes each carrier with `origins: '*'`
  on site A. A different origin on site B reads it back, qualifying through the global grant plus
  PHL membership. This is the attack in the prompt: pick 64 obscure PHL entries, write a chosen
  subset, read it back elsewhere. It requires PHL carriers and pays GREASE'ing and organic
  collision noise, and it sidesteps the Permissions-Policy opt-in that W1 needs.

### 13.2 The round-trip channel

Each carrier is one bit: written on site A (input `1`) or left alone (input `0`); read on site B
(output). Three effects sit between write and read.

* **Eviction.** A written resource survives to the readback with probability `s`, modeled as the
  tier persistence `ρ` raised to a write-to-read aging exponent. `s = ρ` at aging 1.
* **GREASE'ing** (W2 only; a storing-origin read is never GREASEd). It erases a surviving `1`
  with the same size-aware, keying-aware probability the read channel uses, so `r` read repeats
  cut it to `g^r` under per-call keying.
* **Organic collision** (W2 only). A carrier the attacker did not write can be present from the
  user's own browsing, with the carrier's population prevalence `p`. This is a genuine false
  positive on the intended `0`.

So the per-carrier channel is binary asymmetric, with

```
P(read 1 | written)      = ( s + (1 − s)·p ) · (1 − g_eff)      = a₁
P(read 1 | not written)  = p · (1 − g_eff)                       = a₀      (13.1)
```

and `g_eff = 0` for the storing-origin route. The reliable identifier length is the sum of the
per-carrier channel capacities, `Σᵢ max_π I(X;Y)` over the input prior, which an
error-correcting code approaches. The simulator also Monte-Carlos an uncoded round trip (one
carrier per bit, decode a read of `1` as a set bit) to show the naive floor.

### 13.3 Results

**F10. The storing-origin write is a supercookie: a full cross-site identifier in a quarter of a
megabyte, immune to GREASE'ing, decaying only with the cache.** Two hundred fifty-six
small carriers chosen by bits-per-byte hold **143 reliable bits in 275 KB** at aging 1
(`s = 0.75`), which distinguishes more than 10¹² devices where the whole web needs 29.9. Sweeping
the GREASE probability from 0 to 0.9 leaves the capacity at 143 bits throughout, since the
storing-origin read is never GREASEd. Capacity tracks survival and nothing else: 256 bits at
aging 0 (immediate readback), 143 at aging 1, 50 at aging 4 (`s = 0.32`), and 19 at aging 8
(`s = 0.10`), so even a heavily aged cache still carries a site's worth of identification. The
storage cost is 0.002 MB per reliable bit, and a 256-bit identifier fits in 1.7 MB.

**F11. The global-grant write plants a whole-web identifier in 48 KB, and GREASE'ing only raises
the attacker's redundancy.** The prompt's attack, 64 obscure PHL carriers by bits-per-byte,
holds **34.8 reliable bits in 48 KB** with GREASE off and **29.8 bits at `g = 0.1`**, past the
29.9-bit whole-web threshold. At `g = 0.5` under per-call keying the capacity falls to 14.2 bits,
and four read repeats restore it to 31.6 bits at four times the read budget, the same
budget-multiplier result the read channel shows in F4. The organic-collision floor is small
because the carriers are long-tail resources with `p ≈ 0.002`.

### 13.4 What bounds the write channel, and what does not

The write channel does **not** depend on population statistics for its strength. The read channel
borrows entropy from how the user's cache happens to be distributed, and its power rises and
falls with the prevalence model. The write channel manufactures its own entropy by planting a
chosen pattern, so a perfectly ubiquitous, perfectly "safe" list is a fully usable write medium.
Every result above holds at any prevalence calibration.

Four things bound it, with a fifth that looks like a bound and is weak.

* **Eviction** sets the half-life. Capacity falls with survival `s` (F10), so the identifier
  decays and the tracker refreshes it on each revisit.
* **Quota** caps the total. The per-origin storage limit bounds how many carriers fit, though the
  attack needs so little (48 KB for a whole-web identifier) that quota is a weak lever here.
* **Permissions Policy** gates the storing-origin route (W1) behind the embedder's
  `allow="cross-origin-storage"`.
* **PHL membership** is required for the global-grant route (W2), which the 293,522-entry core
  section supplies in abundance.
* **GREASE'ing** looks like a bound and mostly falls short: it is absent from W1 (F10) and coded
  around in W2 (F11).

### 13.5 Mitigations

The prompt's attack succeeds because a first-party script can unilaterally make a chosen set of
PHL resources both present and globally disclosable on site A, and a second origin can read that
exact set on site B. First, a limit that frames every option below.

**The feature and the leak are one bit.** COS's value over a partitioned HTTP cache plus
internal single-instance storage is exactly one thing: letting site B skip a download because
site A already fetched the bytes. Storage dedup needs no disclosure and no API, since a browser
can content-address its own cache internally, keep one physical blob keyed by hash, track which
top-level-site partitions may see it, and collapse a duplicate the moment B fetches the bytes on
its own. Download elision is the only added capability, and it is observable to B, whose server
sees no request when the fetch is skipped. So cross-site download elision and the cross-site
existence oracle are the same observable. Any mitigation that fully preserves the first fully
preserves the second, and any mitigation that fully removes the second removes the first. The
mitigations below are points on that tradeoff curve, and the simulator prices the cardinality
budget and the storing-origin gate.

1. **Budget the number of distinct cross-site-disclosed hashes per origin.** This is the lever
   that separates the AI use case from the tracking channel, because the two differ in
   cardinality. Serving one large model, or choosing among the handful of interchangeable
   variants a model family ships, touches O(1) to O(10) hashes; a whole-web identifier needs
   O(30) or more (F11 uses 64 carriers for ~30 bits, and the read channel needs ~33 bits in
   F1). A per-origin budget of, say, 16 distinct cross-site-disclosed hashes lets a site dedup a
   big model and pick a variant, and caps a planted or probed identifier at 16 bits, which
   distinguishes about 65,000 devices where the whole web needs 30. It is the write-path analogue
   of the read-path probe budget (F7), and it bounds the channel's bit rate at a cost only to how
   many resources a site may share cross-site.
2. **Require runtime storing-origin diversity before the global grant discloses.** Make a
   `'*'` resource cross-origin readable only after some threshold `k` of independent origins have
   stored it, a runtime echo of the PHL's own k-anonymity gate. A lone tracker writing a rare
   long-tail resource on site A is one origin, so its chosen subset stays undisclosable until
   `k` unrelated sites independently store the same bytes, which no attacker can arrange for an
   obscure resource. This preserves cross-site download elision for genuinely popular resources
   and neuters the unilateral chosen-subset write. Its cost falls on the rare-but-large model,
   the headline AI case, which reaches `k` slowly or never, so it pairs best with the budget in
   mitigation 1.
3. **Tie global disclosability to the byte-serving origin's authorization.** Extend the
   [`Cross-Origin-Storage-Allow-Origin` header](../../README.md#the-cross-origin-storage-allow-origin-header)
   from the list-scoped grant to the global one, so a `'*'` write discloses cross-origin only
   when the resource's canonical origin opts in. A tracker cannot make an arbitrary resource
   globally disclosable on its own say-so.
4. **Extend fingerprinting detection and rate limits to the write path.** The explainer already
   anticipates on-device detection of anomalous probing; a first-party script that writes PHL
   resources it never serves, especially many obscure ones, is an equally strong signal, and the
   write side is currently uncounted.
5. **Treat quota and eviction as magnitude limits.** They bound how large and how
   long-lived an identifier is (F10), and they force periodic rewriting, but on their own they
   leave a whole-web identifier comfortably within reach.

**Partitioning the existence disclosure by top-level site** is the endpoint of the curve, and it
is worth naming because it closes both routes at once, including the storing-origin supercookie
(W1) that touches neither the PHL nor the global grant. It also collapses COS's download elision
to once per top-level site, which is the partitioned HTTP cache's behavior today, so it removes
the feature along with the channel and leaves only the internal storage dedup that needs no API.
It is the right reference point for what full closure costs, and the budget of mitigation 1 is
the interior point that keeps the AI use case.

---

## 14. Comparison to traditional fingerprinting

The framing question for this whole document: measured against browser fingerprinting, with
third-party cookies already removed, is COS a better or a worse tracking vector? The models
support a two-part answer. The read channel is comparable to fingerprinting in raw power and
better positioned for defense; the write channel reintroduces the globally readable cross-site
state that partitioning removed, which is worse in kind.

### 14.1 The read channel against fingerprinting

The largest public measurement of fingerprinting, Gómez-Boix et al.'s two million fingerprints,
found **33.6% unique**, far below the 80–90% of lab studies, because a stock phone on a current
browser looks like every other stock phone.[^gb] The COS read channel reaches 100% uniqueness at
64 strategically chosen probes (F2). Three properties matter more than that headline.

* **The entropy is orthogonal.** Fingerprinting entropy comes from device and software
  configuration; COS entropy comes from browsing history. The stock phones that collapse the
  fingerprinting distribution have wildly different caches, so COS contributes near its full
  entropy on exactly the population where fingerprinting fails. A weaker signal would still be
  serious if it were this uncorrelated with the dominant one.
* **The trend is opposite.** Fingerprinting entropy shrinks as browsers freeze the user-agent
  string, remove plugins, and add canvas noise. The PHL grows: it is 45% larger than the figure
  in its own explainer, and every added entry is another probeable bit.
* **The defensive position is stronger.** Fingerprinting has no chokepoint, which is why a decade
  of countermeasures has only eroded it. COS probing has exactly one API, countable per origin,
  reading from a public auditable allowlist, behind a rate limit and GREASE'ing. The read
  channel is a problem the platform can hold in check, conditional on the keying fix (F4) and a
  probe budget in the tens (F7).

On uniqueness the read channel exceeds fingerprinting; on durability it is weaker, since the
cache decays and the user can clear it, and it is per-profile where a configuration fingerprint
travels across browsers on one device.

### 14.2 The write channel against fingerprinting

The write channel is a different comparison. It works as a cookie by another mechanism, planting
state the tracker chooses. F10 plants 143 bits of chosen, persistent, cross-site state in 275 KB, and F11
plants a whole-web identifier in 48 KB. That state is unpartitioned, survives third-party cookie
clearing, and, in the storing-origin form, is immune to GREASE'ing. Measured against
fingerprinting it is worse in kind: fingerprinting reads what the device already is, while this
writes a chosen identifier the tracker controls, which is the capability the platform spent years
removing when it partitioned storage and dropped third-party cookies.

Its saving graces are the bounds of §13.4: it decays with the cache, it sits behind a quota, and
the storing-origin route needs a Permissions-Policy grant. Full closure by partitioning the
disclosure exists, and it costs the feature, since cross-site download elision and the tracking
oracle are the same bit (§13.5); the interior fix that keeps the AI use case is a per-origin
budget on distinct cross-site-disclosed hashes.

### 14.3 Verdict

COS is **worse in kind and better in controllability**. Worse, because the write channel
reintroduces globally readable cross-site state at the moment the platform has finished removing
it, and the read channel adds a history-derived signal orthogonal to the configuration
fingerprint and strongest where that fingerprint is weakest. Better, because every part of it has
a chokepoint the rest of the fingerprinting surface lacks: one API, countable and rate-limitable,
reading from a public list, with levers the fingerprinting surface has never offered.
Fingerprinting is a surface the platform can only erode. COS gives it a dial: cross-site download
elision and cross-site tracking are the same bit, so the design chooses a point on one curve,
from full sharing with the oracle open to full partitioning with the feature gone. A per-origin
budget on distinct cross-site-disclosed hashes is the interior setting that keeps the AI use case
while holding the identifier to a handful of bits. The write channel deserves that dial set
deliberately, with the attention the read channel has already had.

[^gb]: Gómez-Boix, Laperdrix, Baudry, *Hiding in the Crowd: an Analysis of the Effectiveness of
Browser Fingerprinting at Large Scale*, WWW 2018,
<https://doi.org/10.1145/3178876.3186097>.

---

## 15. Directions worth evaluating

These follow from the models and have not been evaluated beyond them, so treat them as
candidates for discussion.

* **Specify GREASE keying** as PRF(device secret, requesting origin, hash, epoch) with a stated
  epoch length, and specify that the budget counts across all four probe surfaces. Per F4 this
  is worth more than any choice of `g`.
* **Reconsider the size exemption.** The performance argument is sound, and an alternative
  preserves it: make a large resource's disclosure *sticky per origin after the first truthful
  answer*, so the first probe answers honestly (no re-download penalty for the honest case) and
  the answer is then frozen for that origin, leaving repetition and epoch rotation with nothing
  to average. This costs no bandwidth and removes the F5 channel.
* **Gate on serving-host diversity**, so that 100 hosts under one publisher,
  one hosting provider, or one plugin do not clear a bar meant to represent 100 independent
  observations. F3 shows the count-based gate works where it applies; the question is whether
  its hosts are as independent as the count assumes.
* **Consider extending a gate to the ungated sections.** F3's residual 0.33–0.40% comes
  entirely from sections the gate does not cover.
* **Partition the disclosure decision by top-level site**, so a third-party iframe's probes are
  keyed to the embedding site. This is the one change that would make COS's privacy story match
  the rest of the platform's post-partitioning model, and it costs the shared cache nothing in
  bandwidth: the bytes stay shared, the *disclosure* becomes per-site, and the price is one
  extra miss per new site.

---

## 16. Limitations

* **Prevalence is modeled.** There is no public dataset of per-resource cache
  prevalence across real users. The parametric defaults are anchored to the list's own
  structure (§10.1), and the CSV import exists so measured data can replace them.
* **The population is homogeneous.** Real populations are stratified by locale, device class,
  and browsing volume, and stratification *increases* the attacker's power, so the models are
  conservative in that respect.
* **Eviction is a single persistence parameter per tier.** Real eviction is size-aware, LRU-ish,
  and quota-driven, and correlates with the resources the attacker cares about.
* **The site graph's co-deployment structure is a free parameter.** F3's numbers move with it,
  and no public data pins it down; the simulator exposes it as a slider for that reason.
* **Fingerprinting detection is modeled only as a hard budget.** A real classifier would catch
  some attackers, and an attacker would adapt. Neither side is modeled.
* **No timing side channels.** Probe latency may distinguish a GREASEd negative from a true
  negative, which would collapse the Z-channel back to a noiseless one and make all of §9.2
  moot. Worth measuring in a real implementation; not modeled here.
* **Independence and stationarity** are assumed in the analytic expressions; the generative
  mode exists to bound that error.
