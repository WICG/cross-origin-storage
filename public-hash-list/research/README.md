<!--
  Copyright 2026 Google LLC
  SPDX-License-Identifier: Apache-2.0
-->

# PHL privacy research

Privacy analysis of the [Public Hash List](../phl-explainer.md) as an attack surface.
Everything here is exploratory: it raises questions about the design, it proposes no changes to
the [COS specification](https://wicg.github.io/cross-origin-storage/) or to the PHL's inclusion
criteria, and no number in it is a measurement of real users.

The work is in two parts, plus the simulator behind both.

| | File | What it is |
| --- | --- | --- |
| **Part one: the problem** | [`probing-attack-model.md`](probing-attack-model.md) | The models, the calibration against the real published list, and the results. |
| **Part two: the proposed solution** | [`proposed-solution.md`](proposed-solution.md) | Four rules that bound the attack, in plain terms, with what each one costs. **Start here** for the conclusions. |
| The simulator | [`probing-simulator.html`](probing-simulator.html) | What both parts draw on. Three channels: the write attack, the read attack, and a budget model that checks whether the proposed rules hold. Open it in a browser; no build step, no dependencies, no network access. |

## The attack

COS lets a site *write*. The store is global and unpartitioned, so a tracker can plant a chosen
identifier on site A and read it back on site B, which turns COS into a cross-site store: a
supercookie that survives third-party cookie clearing. That write channel is modeled in §13, and
it is the sharper of the two concerns.

COS also answers questions. Any origin can ask whether a given hash is cached, and that answer is
a read of device-wide state the asking site never wrote. A tracker embedded on many sites can
probe the same `n` PHL hashes everywhere it runs and use the resulting bit vector as a device
identifier, with nothing to clear and nothing stored under its own name.

The analysis separates four goals that share those mechanics but have different optima: linking
two visits to one device, recognizing one known device again, inferring which sites a device
visited, and inferring what kind of user it belongs to. Treating them as one question is the
main way this analysis goes wrong, and the document keeps them apart throughout.

§14 weighs the whole surface, write and read, against traditional browser fingerprinting.

## What the simulator does

Loads a model of the 438,684-entry list calibrated from the real `public-hash-list.dat`
(section sizes, per-source counts, file types, size distributions), assigns each resource a
prevalence and a persistence, lets an attacker choose a probe set under a strategy and a probe
budget, runs a population of simulated devices through two visits, and scores what the attacker
learns: linking margin, ROC and rank-1 identification, anonymity sets, targeted
re-identification among carriers, cohort inference, and history inference.

Both defenses in the explainer are parameterized. GREASE'ing has a probability, a size limit,
and, more consequentially, a choice of what the coin is keyed on. Probe budgets cap the
attacker's probes per site, which is what makes repeated probing cost something.

Two cache models are switchable: independent tiers with fitted prevalences, for fast analytic
results, and a generative site graph that produces co-occurrence, site-level ground truth, and
a working k-anonymity gate.

Presets in the scenario dropdown reproduce each result in §12 of the model document.

## Headline results

The [Results](probing-attack-model.md#12-results) section of part one has the numbers and the
caveats.

The write channel (§13) is the sharper concern: a storing-origin write plants 143 bits of chosen,
cross-site, GREASE-immune state in 275 KB, and a global-grant write plants a whole-web identifier
in 48 KB. Cross-site download elision and the tracking oracle are the same bit, so closing the
channel fully costs the feature; a budget keyed on the top-level site is the interior fix that
keeps the AI use case.

On the read channel, the k-anonymity gate does the job it was designed for, and does it with
margin, though it governs only one tier of the list and only one of the four threat models.
Strategic probe selection is worth about 50× the probe budget over random selection, and
GREASE'ing's value depends almost entirely on a keying choice the specification does not
currently make. Composing two gated resources leaves the gate intact: at the real threshold of
100 hosts, no simulated device was pinned to a site.

## The proposal in one paragraph

A COS lookup answers yes or no, so it yields one bit, and ten lookups can never yield more than
ten bits. Picking one device out of a billion needs about 30. So metering the lookups that cross
a site boundary puts a hard ceiling on what a tracker can learn, and a site's lookups of files it
stored itself can stay free, which is what keeps the build-tool and AI cases working. Pair that
with a user gesture before a stored file becomes shareable, so a silently reloading page cannot
accumulate, and a counter that survives reloads. The budget has to belong to the page: keyed on
the requesting origin, a tracker defeats it in one page view by putting four collaborating
iframes on origins it controls. Part two works through the rules, the examples, the costs, and
what stays unsolved.

## Reproducing

Open `probing-simulator.html` in any modern browser and press "Run simulation". Nothing is
fetched and nothing leaves the page. Runs at the defaults take a few seconds; the generative
site mode and large probe counts take longer.

Optionally, the HTTP Archive publishes the per-hash origin counts and traffic-weighted scores
behind the list's own k-anonymity gate at
`https://cdn.httparchive.org/v1/static/reports/public_hash_list.csv`. The simulator accepts
that file to replace its fitted prevalences with measured ones.
