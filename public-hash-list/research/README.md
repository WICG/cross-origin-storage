<!--
  Copyright 2026 Google LLC
  SPDX-License-Identifier: Apache-2.0
-->

# PHL privacy research

Privacy analysis of the [Public Hash List](../phl-explainer.md) as an attack surface. The work is in two parts, plus the simulator behind both.

## The attack

COS lets a site *write*. The store is global and unpartitioned, so a tracker can plant a chosen
identifier on site A and read it back on site B, which turns COS into a cross-site store: a
supercookie that survives third-party cookie clearing.

COS also answers questions. Any origin can ask whether a given hash is cached, and that answer is
a read of device-wide state the asking site never wrote. A tracker embedded on many sites can
probe the same `n` PHL hashes everywhere it runs and use the resulting bit vector as a device
identifier, with nothing to clear and nothing stored under its own name.

The analysis separates four goals that share those mechanics:

* linking two visits to one device
* recognizing one known device again
* inferring which sites a device visited
* inferring what kind of user it belongs to

## The simulator

Loads a model of the 438,684-entry list calibrated from the real `public-hash-list.dat`
(section sizes, per-source counts, file types, size distributions), assigns each resource a
prevalence and a persistence, lets an attacker choose a probe set under a strategy and a probe
budget, runs a population of simulated devices through two visits, and scores what the attacker
learns: linking margin, receiver operating characteristic (ROC) and rank-1 identification, anonymity sets, targeted
re-identification among carriers, cohort inference, and history inference.

Both defenses in the explainer are parameterized. GREASE'ing has a probability, a size limit,
and, more consequentially, a choice of what the coin is keyed on. Probe budgets cap the
attacker's probes per site, which is what makes repeated probing cost something.

Two cache models are switchable: independent tiers with fitted prevalences, for fast analytic
results, and a generative site graph that produces co-occurrence, site-level ground truth, and
a working k-anonymity gate.

Presets in the scenario dropdown reproduce each result in §12 of the model document.

## The proposal in one paragraph

A COS lookup answers yes or no, so it yields one bit, and ten lookups can never yield more than
ten bits. Picking one device out of a billion needs about 30. So metering the lookups that cross
a site boundary puts a hard ceiling on what a tracker can learn. Every lookup counts, found or
not, since free misses would let a sparse identifier through. Lookups of files a site stored
itself stay free, which bounds the cost to a site's first visit: the AI case spends a handful of
lookups and never feels the limit, and a build-tool site trades away some first-visit chunk
reuse. Pair that
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
