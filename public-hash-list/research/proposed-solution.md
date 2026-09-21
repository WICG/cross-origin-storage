<!--
  Copyright 2026 Google LLC
  SPDX-License-Identifier: Apache-2.0
-->

# A proposed solution: metered reads and gesture-gated writes

This is part two of the PHL privacy research. Part one,
[`probing-attack-model.md`](probing-attack-model.md), describes the problem: how a tracker can
use Cross-Origin Storage to recognize the same device on unrelated websites. This document
proposes what to do about it.

It is written to be read on its own. Everything here is a proposal for discussion, and none of it
is a change to the COS specification today.

---

## The short version

Four rules. The first two carry the weight.

1. **Count the reads that cross a site boundary**, with one budget shared by every frame on
   the page.
2. **Wait for a user gesture before a write takes effect.** The page can use the file
   immediately; only the sharing waits.
3. **Keep the count per site, per time window, and keep counting across page reloads.**
4. **Count small writes, and weigh large ones by size.**

Together these put a hard ceiling on how much a tracker can learn, while leaving the things COS
was built for working normally.

---

## Why one number decides everything

A COS lookup has exactly two possible answers: "here is the file" or "not found." That is one
yes-or-no answer, which is one bit of information.

This is the key fact, and it is worth saying plainly:

> **Ten lookups can never tell you more than ten bits. A hundred lookups can never tell you more
> than a hundred bits.** No clever encoding gets around it, because each lookup only ever returns
> one of two answers.

Now compare that to what a tracker needs. To pick one specific device out of a billion, you need
about 30 bits. Call it 32 to be safe.

So the whole problem reduces to a counting question. If a website can make 64 cross-site lookups,
it can learn up to 64 bits, which is more than enough to single out a device. If it can make 8,
it can learn at most 8 bits, which narrows a billion devices down to about four million. That is
useless for identifying anybody.

**Limiting lookups is therefore a mathematical ceiling on what a tracker can extract, with no
guesswork involved.** That is what makes it a better control than trying to detect bad behavior.

---

## Rule 1: Count the reads that cross a site boundary

Give each page a budget of cross-site lookups, per time window, in the range of 8 to 16. The
budget belongs to **the website the user is on**, and every frame on that page draws from the
same pot, whatever origin it comes from.

That last part matters more than it sounds, and getting it wrong undoes the whole rule. See
*Why the budget belongs to the page* below.

The other important detail is *which* lookups count. Only count a lookup when it could reveal
something about a **different** website. Concretely:

| Lookup | Counts against the budget? |
| --- | --- |
| A file this website itself put in the cache | No |
| A file already in the cache from this website's own earlier visits | No |
| A file that is only visible because some *other* website stored it | **Yes** |
| A file the requesting origin stored while the user was on a *different* website | **Yes** |

**Example, first visit.** `shop.example` uses a build tool that splits its JavaScript into 40
shared chunks. A user arrives for the first time, and 20 of those chunks are already cached
because other sites use the same libraries. That reuse is the whole point of COS, and it is also
what the budget meters, because those lookups ask about files other websites stored. With a
budget of 8, `shop.example` reuses 8 of the 20 and downloads the other 32.

**Example, every visit after.** Having stored all 40 chunks under its own name, `shop.example`
now looks them up for free, and the page runs at full speed.

So the carve-out does not make the build-tool case free. It bounds the cost to the first visit.

**Example, the tracker.** `tracker.example` runs on both `news.example` and `shop.example`. On
`news.example` it stored 64 small files. On `shop.example` it now looks those same files up. Every
one of those lookups asks about something a different website stored, so every one counts. It runs
out of budget after 8, and it learns 8 bits.

The carve-out still does real work. It moves the cost from every page load to the first one, and
it leaves the AI case untouched, since reusing one large model takes a single lookup and never
approaches the limit. What it cannot do is make cross-site reuse free, because reusing a file
another site fetched is the same observable as learning that another site fetched it.

### Misses have to count too

The tempting repair is to charge only the lookups that come back "found," leaving the misses free.
That would break the ceiling.

A tracker would plant a *sparse* identifier: write 8 files chosen from a pool of 1,000. On
readback it looks up all 1,000, pays for only the 8 that hit, and learns which 8 of the 1,000 are
present. That is about 64 bits of identifier for a budget of 8.

So every lookup counts, found or not. That is what keeps one lookup worth one bit, and it is why
the first-visit cost to `shop.example` above cannot be engineered away.

### Why the budget belongs to the page

Suppose the budget belonged to each requesting origin. A tracker running as first-party script
on `news.example` can create iframes pointing at origins it controls, and hand each one COS
access with `allow="cross-origin-storage"`. Each frame does its own 8 lookups on a different
slice of the file set, then reports its answers to the parent with `postMessage`.

With a budget of 8, **four such frames collect 32 bits in a single page view**, which is a
complete identifier, and the rule has achieved nothing. The origins are free: one wildcard DNS
record gives a tracker `a.tracker.example`, `b.tracker.example`, and as many more as it wants.
Independent trackers on the same page can pool their budgets the same way.

Keying the budget to the requesting *site* (the registrable domain) stops the subdomain version
of this, since all those subdomains share one budget. It still falls to a tracker that buys
sixteen cheap domains, or to sixteen trackers that agree to cooperate.

Keying the budget to the **top-level site** is what actually holds. One page view, one budget,
however many frames and whoever they belong to. The attacker cannot mint the thing the budget is
keyed to, because that thing is the website the user chose to visit.

The cost is real and worth stating: independent embeds on a page now compete for one pot. A page
carrying a map widget, a video player, and an ad frame shares 8 to 16 cross-site lookups between
them. That is the right trade, because the quantity being limited is how much cross-site
information leaves this page view, and that total is what the user's privacy depends on.

---

## Rule 2: Wait for a user gesture before a write takes effect

Before a file a website stores becomes visible to other websites, require that the user has
actually done something on the page: a click, a tap, or a key press.

The important detail is that **the page does not have to wait.** If a site fetches a file and
wants to use it, it uses it right away. Only the step that makes it shareable is held back, and
it happens quietly as soon as the user interacts.

**Example.** An AI site downloads a 4 GB model. The model loads and runs immediately, exactly as
it does today. The moment the user clicks anything at all, the model becomes shareable with other
sites. If the user reads the page and leaves without clicking, the model still worked; it just
did not join the shared cache.

**Why this matters.** Without it, a tracker can reload its own page in a loop. Each reload is a
fresh page, so any per-page limit resets, and the tracker can write as much as it likes in a few
seconds while the user sees nothing. Requiring a gesture breaks that loop, because a silent
reload produces no clicks. A tracker can only accumulate at the speed the user actually engages
with pages.

Two practical notes. Scrolling does not count as a gesture in browsers today, so the rule really
does bind on pages nobody interacts with. And one gesture unlocking the page's whole write budget
is simpler to build than demanding a separate gesture per file, with nearly the same effect.

---

## Rule 3: Count per site, per window, and keep counting across reloads

The counter has to survive page reloads and navigations. If it resets every page load, the same
reload loop that Rule 2 blocks for writes would work for reads, and reads are the step that
actually extracts the identifier.

So the counter is keyed to the website the user is on, shared by every frame as Rule 1 requires,
and it persists for a chosen window of time.

**Example.** A per-page-load budget of 8 gives a tracker 8 bits per reload. Reloading four times
takes about a second and yields 32 bits, which is a complete identifier. A budget of 8 per day
gives the same tracker 8 bits per day.

**The window length is the main dial in this whole proposal.** It sets how fast a determined
tracker can accumulate. Shorter windows are friendlier to sites that legitimately share a lot;
longer windows are stronger against tracking.

---

## Rule 4: Count small writes, weigh large ones by size

Writes deserve a limit too, and the natural one falls out of file sizes.

The files a tracker uses as carriers have to be small, because it needs many of them. Sixty-four
carriers fit in about 48 KB, roughly 750 bytes each. The files COS exists to share are the
opposite: AI model pieces run 8 to 128 MB each, and some model files reach several gigabytes.

So: **count small writes, and meter large writes by total bytes.** A site storing one big model
spends bytes and barely touches the count. A tracker storing 64 tiny files spends almost no bytes
and immediately hits the count.

This also closes the obvious dodge. A tracker that switches to large carriers to escape the count
now has to push gigabytes onto the user's device for a 32-bit identifier, which the storage quota
stops and the user's bandwidth bill notices.

---

## What the attack looks like under these rules

Same cast as before: `tracker.example` embedded on `news.example` and `shop.example`, trying to
recognize the same device on both.

1. On `news.example`, the tracker wants to store 64 small files to encode an identifier. Rule 4
   counts all 64 against a small-write budget, so most are refused. Rule 2 holds even the
   permitted ones until the user clicks something, so a silently reloading page gets nowhere.
2. Suppose the user does click, and the tracker gets its 8 writes through. It now has 8 bits
   planted.
3. On `shop.example`, the tracker looks those files up. Rule 1 counts every one of those lookups,
   because they ask about something another website stored. Rule 3 makes that count stick across
   reloads. After 8 lookups the tracker is done for the window.
4. It has 8 bits, which narrows a billion devices to about four million. It cannot identify
   anyone.

To reach a full 32-bit identifier it needs four windows on the writing side and four on the
reading side, each one requiring a real user interaction. With a window of a day, that is several
days of repeat visits to both sites.

---

## What it costs

Being straight about the downsides:

- **Sites that legitimately share a lot across origins will hit the budget on a first visit.** A
  site that wants to reuse twenty files other sites stored will get through 8 of them and
  download the rest. Rule 1's carve-out for a site's own files limits this to the first visit,
  and it does not remove it.
- **Users who never interact never contribute to the shared cache.** Their own browsing still
  works; their downloads just do not become shareable.
- **There is a tuning problem.** The budget size and the window length trade sharing against
  tracking, and picking them needs real deployment data.

---

## What is left open

**A patient tracker can still accumulate.** It is first-party script on each site, so it has
ordinary storage there. It can read 8 bits today, save that partial result, read 8 more tomorrow,
and stitch them together. The budget sets the *rate*, and a tracker willing to wait several
windows still gets there.

This is the residual risk, and it is a real one. It means the honest claim for this proposal is:

> Cross-site tracking goes from instant and free to slow, paced by the user's own engagement, and
> capped in bits per unit of time.

Drive-by identification on a first visit is gone. Tracking a user who visits both sites daily for
a week is still possible.

---

## Smaller fixes worth making alongside

These come out of the same analysis and are largely independent of the rules above.

- **Say what the GREASE'ing coin is keyed on.** The specification says a browser may occasionally
  answer "not found" for a file that is present, and leaves open what decides that. The choice
  matters far more than the probability does. Keyed to the device and the requesting origin, a
  tracker in an iframe sees the identical answer on every site, so it learns just as much. Keyed
  fresh per call, a tracker defeats it by asking a few times. Keyed to the device, the origin,
  and a rotating time window, it works.
- **Rethink the size exemption.** Large files are exempt from GREASE'ing today, for the good
  reason that a false "not found" forces an expensive re-download. That exemption hands a tracker
  a noise-free channel exactly where the most identifying files live. An alternative keeps the
  performance benefit: answer the first lookup honestly, then freeze that answer for that origin,
  so repeated asking reveals nothing new and no re-download is ever forced.
- **Look at who serves the files, and not only how many.** The list admits a file once it is
  served from at least 100 different hosts. One hundred hosts that are all the same hosting
  provider or the same plugin fall short of 100 independent observations.
- **Watch the write path too.** Detection today is aimed at unusual lookup patterns. A site
  storing files it never actually uses is an equally strong signal, and nothing counts it.

---

## Options considered and set aside

- **Partition everything by website.** Make a stored file visible only to the website that stored
  it. This closes the problem completely, and it also removes the feature: letting site B skip a
  download because site A already fetched the file is the same observable fact as telling site B
  that site A fetched it. Remove one and you remove the other, which leaves COS doing what the
  ordinary browser cache already does. Deduplicating storage on disk needs no API at all, since a
  browser can keep one copy of identical bytes internally without telling anyone.
- **Rely on storage quotas and cache eviction.** These limit how large an identifier can be and
  how long it survives with no refresh. Neither one stops it. A full 32-bit identifier fits in
  48 KB, far under any realistic quota, and a tracker rewrites it on every visit, which resets
  the clock. They bound the size and the lifetime while leaving the channel open.
- **Limit how deep `allow="cross-origin-storage"` can be delegated.** Capping delegation at one
  level stops a chain of nested frames from passing COS access down indefinitely, which is
  reasonable hygiene: a site that grants COS to one embed probably did not mean to grant it to
  whatever that embed loads next. It does not solve the budget problem, because the attacker
  does not need depth. Sixteen sibling frames at one level multiply an origin-keyed budget
  exactly as well as sixteen nested ones, and browsers have no general depth limit for
  Permissions Policy delegation to borrow.
- **Rely on detection alone.** Worth doing, and evadable. A tracker can load the files it stores
  so they look used, and can blend them into a plausible set of resources. Detection raises the
  cost and catches careless implementations, and it cannot give a guarantee.

---

## How to check these numbers

The simulator, [`probing-simulator.html`](probing-simulator.html), reproduces every figure quoted
here and in part one. Open it in a browser and press "Run simulation"; nothing is fetched and
nothing leaves the page. The `Channel` selector switches between the lookup attack and the write
attack, and the scenario dropdown has a preset for each result.
