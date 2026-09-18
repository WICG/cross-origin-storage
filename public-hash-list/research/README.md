<!--
  Copyright 2026 Google LLC
  SPDX-License-Identifier: Apache-2.0
-->

# PHL privacy research

Privacy analysis of the [Public Hash List](../phl-explainer.md) as an attack surface.
Everything here is exploratory: it raises questions about the design, it proposes no changes to
the [COS specification](https://wicg.github.io/cross-origin-storage/) or to the PHL's inclusion
criteria, and no number in it is a measurement of real users.

| File | What it is |
| --- | --- |
| [`probing-attack-model.md`](probing-attack-model.md) | The models, the calibration against the real published list, and the results. Start here. |
| [`probing-simulator.html`](probing-simulator.html) | The simulator the results come from. Open it in a browser; no build step, no dependencies, no network access. |

## The attack

Any origin can ask COS whether a given hash is cached. The COS store is global and
unpartitioned, so that answer is a read of device-wide state the asking site never wrote. A
tracker embedded on many sites can probe the same `n` PHL hashes everywhere it runs and use the
resulting bit vector as a device identifier, with nothing to clear and nothing stored under its
own name.

The analysis separates four goals that share those mechanics but have different optima: linking
two visits to one device, recognizing one known device again, inferring which sites a device
visited, and inferring what kind of user it belongs to. Treating them as one question is the
main way this analysis goes wrong, and the document keeps them apart throughout.

COS also lets a site *write*, so the tracker can plant a chosen identifier on site A and read it
back on site B. That write channel, modeled in §13, turns COS into an unpartitioned cross-site
store: a supercookie that survives third-party cookie clearing. §14 weighs the whole surface,
read and write, against traditional browser fingerprinting.

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

The [Results](probing-attack-model.md#12-results) section has the numbers and the caveats.
In short: the k-anonymity gate does the job it was designed for, and does it with margin, but
it only governs one tier of the list and only one of the four threat models; strategic probe
selection is worth about 50× the probe budget over random selection; and GREASE'ing's value
depends almost entirely on a keying choice the specification does not currently make.

Composing two gated resources leaves the gate intact: at the real threshold of 100 hosts, no
simulated device was pinned to a site.

The write channel (§13) is the sharper concern: a storing-origin write plants 143 bits of
chosen, cross-site, GREASE-immune state in 275 KB, and the global-grant write of the prompt's
attack plants a whole-web identifier in 48 KB. Cross-site download elision and the tracking
oracle are the same bit, so closing the channel fully costs the feature; a per-origin budget on
distinct cross-site-disclosed hashes is the interior fix that keeps the AI use case.

## Reproducing

Open `probing-simulator.html` in any modern browser and press "Run simulation". Nothing is
fetched and nothing leaves the page. Runs at the defaults take a few seconds; the generative
site mode and large probe counts take longer.

Optionally, the HTTP Archive publishes the per-hash origin counts and traffic-weighted scores
behind the list's own k-anonymity gate at
`https://cdn.httparchive.org/v1/static/reports/public_hash_list.csv`. The simulator accepts
that file to replace its fitted prevalences with measured ones.
