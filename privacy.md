<!--
  Copyright 2026 Google LLC
  SPDX-License-Identifier: Apache-2.0
-->

# Privacy and Cross-Origin Storage

[Cross-Origin Storage](README.md) lets the browser keep one copy of a large file
and share it with every site that needs it. Download a four-gigabyte AI model on
one website, and a different website can use it a moment later with no download
at all. The same goes for a WebAssembly module, a popular JavaScript library, a
game engine, or a web font. For the user that means less waiting, less mobile
data, less disk space, and less battery. For the web as a whole it means the
same bytes are not shipped across the planet over and over again.

That benefit comes from one fact: the cache is shared between websites that have
nothing to do with each other. The same fact is what creates the privacy risk. A
website can ask the browser whether a file is already stored, and the answer
depends on what happened on _other_ websites. Every attack described below is
built out of that single question, asked many times.

None of this makes the feature unworkable, and none of it can be waved away
either. **Mitigations need to carefully balance between ensuring the user's
privacy and maintaining the usefulness of the feature.** A rule strict enough to
end every attack on this page would also end the sharing that makes the feature
worth having. This document describes the attacks. The mitigations that COS
proposes are covered in the
[Privacy considerations](README.md#privacy-considerations) section of the
explainer.

## How to read this document

Three things make the attacks possible, and they are worth holding in mind
throughout.

**The cache is shared, and it is not separated per site.** That is the whole
point of the feature. Ordinary browser storage, like cookies, is now kept in
separate compartments per website, so what one site stores is invisible to the
next. A shared cache deliberately crosses that line.

**Files are looked up by their contents.** COS identifies a file by its _hash_,
a short code calculated from the exact bytes of the file, similar to a
fingerprint. Any site that has a copy of a file can compute that code, so any
site can ask about any file it knows.

**Every answer is one yes or no.** A lookup either hands over the file or says
it is not there. That is a single yes-or-no answer, and a single answer tells an
attacker very little. Roughly **32 well-chosen yes-or-no answers are enough to
tell one device apart from every other device on the planet.** That number is
the budget every attack below is trying to spend.

---

## Attack 1: Planting a hidden identifier

This is the most serious one, because it does not depend on luck or statistics.
The tracker manufactures the identifier itself.

Think of a cookie as a number written on a sticky note. Browsers have learned to
keep those notes in separate drawers per website, so a tracker on one site
cannot read the note it left on another. A shared cache gives it a different
place to write: your bookshelf. The tracker picks 32 obscure little books and
puts _some_ of them on your shelf, choosing the combination so it is unique to
you. On any other website, it walks along the shelf and reads which of those 32
books are there. The pattern is your number, and it is the same number
everywhere.

In practice the "books" are small files, and "on the shelf" means stored in the
shared cache. The tracker stores a chosen handful on site A, then checks for
that same handful on site B. The combination it finds is the identifier.

There are two routes, and they differ in how much work the tracker has to do.

**Through an embedded frame.** If `tracker.example` is embedded on both sites as
a frame, and both sites have granted that frame permission to use the feature,
then the tracker is the one who stored the files. A site can always read back
what it stored itself, so the check is clean, reliable, and untouched by the
other protections described in the explainer.

**Through the public list of well-known files.** A tracker that runs as part of
the site's own code has a harder time, because what it stores belongs to the
site, and the site next door cannot read it. Its way around this is to use files
that are already public knowledge: the well-known libraries and fonts on the
[Public Hash List](public-hash-list/phl-explainer.md). It encodes your number as
"which of these 32 well-known files did I put on this device," and reads that
pattern back elsewhere. This version is noisier, because you may already have
some of those files from ordinary browsing, and because the browser deliberately
lies from time to time about whether a file is present. The tracker compensates
by storing more files than it strictly needs.

**Concrete example.** You read an article on a news site. A tracker embedded in
the page quietly stores 32 tiny files, picking the combination at random for
you. A week later you open an unrelated shopping site that runs the same
tracker. It checks for those same 32 files, finds the same combination, and now
knows the shopper and the reader are one person. You cleared your cookies in
between, and it made no difference.

---

## Attack 2: Recognizing a device by what it already has

The previous attack writes something. This one only looks. Over months of
ordinary browsing, the collection of files in your shared cache becomes
distinctive, in the same way that the books on a real bookshelf are distinctive
without anyone having planted them.

A tracker picks a list of well-known files and checks which ones you have. Some
are near universal, like the font used by half the web, and tell it nothing.
Some are held by roughly half of people, and those are the useful ones, because
each is a coin flip that splits the population in two. Enough of those, and the
pattern is yours alone.

**Concrete example.** The same analytics script runs on a recipe blog and on a
local newspaper. On both, it checks the same 60 well-known libraries and fonts.
On the recipe blog it sees a particular pattern of yes and no answers. On the
newspaper, an hour later, it sees the same pattern. It concludes that the same
person read both, links the two visits, and adds the newspaper to the profile it
keeps for the recipe reader.

This is harder than Attack 1, because the tracker has to work with whatever
happens to be on the device. It also needs no cooperation from the sites beyond
being present on them, and it leaves nothing behind to find or clear.

---

## Attack 3: Working out which sites someone has visited

Some files are used by a small, specific set of websites. If you have such a
file, you must have visited one of them.

A file used by half the web reveals nothing. A file used by two hundred sites
narrows you to those two hundred. The interesting case is what happens when a
tracker combines two of them: if one file is used by two hundred knitting blogs
and another by two hundred sites about a particular town, and you have both, the
overlap may be a single website.

**Concrete example.** A small plugin for hobby blogs ships its own stylesheet,
and about three hundred sites use it. A tracker checks for that stylesheet and
learns you have read one of those three hundred blogs. It then checks for a
second file that only appears on blogs using a particular German-language theme.
You have both, and only four sites in the world use both. The tracker has
narrowed your reading history to four candidates, without ever seeing your
address bar.

---

## Attack 4: Working out what kind of person someone is

This attack never identifies anybody, which is exactly what makes it hard to
defend against. It only sorts people into groups, and the groups can be
sensitive.

Files carry meaning. A font that covers Japanese characters suggests you read
Japanese. A game engine suggests you play games in the browser. A speech model
suggests you use dictation. An AI model that a particular mental-health chatbot
loads suggests something considerably more personal.

**Concrete example.** An advertising script checks for eight AI models that run
inside the browser. You have one of them, so it records "uses in-browser AI
tools." It also checks for the Japanese subset of a common web font and finds
it, so it records "reads Japanese." Neither answer tells it who you are, and it
does not need to know. It has two useful facts for targeting, obtained in eight
questions, and both are correct.

The uncomfortable version of this example is the model a chatbot for depression
or addiction support loads. Presence of that file is a strong hint about the
person, and the browser cannot tell the difference between asking about that
file and asking about a font.

---

## Attack 5: Finding one specific person

The attacks above are aimed at people in general. This one is aimed at you.

Common files are useless here and rare files are ideal. If a tracker knows you
personally hold an unusual file, perhaps because it watched you download it
while you were signed in, then checking for that one file elsewhere is close to
checking for your name. Very large AI models are especially good for this,
because few people have any given one, because they stay on the device for a
long time, and because browsers avoid the trick of occasionally lying about
large files, since a false answer would force a multi-gigabyte re-download.

**Concrete example.** A researcher signs in to a specialist site and downloads
an uncommon AI model for analyzing medical images. Perhaps a few thousand people
worldwide have that exact file. Later, on a public forum with no sign-in, the
same operator checks for it, gets a yes, and now has good reason to believe the
anonymous forum account belongs to the researcher who signed in earlier.

---

## Attacks aimed at the limits themselves

The explainer proposes limiting how many cross-site lookups a website may make.
The attacks in this group target the limit itself.

### Attack 6: Spreading the work across many helpers

If a limit is counted per website doing the asking, a tracker can simply become
several websites. Subdomains are free and unlimited, so one tracker can turn
itself into eight, embed each as its own frame in the page, give each a
different slice of the work, and have them report back to the parent frame.

**Concrete example.** A limit allows eight questions per website per day. The
tracker embeds four frames, each on a different subdomain it owns. Each frame
asks its own eight questions about a different set of files, then passes the
answers to the page. The tracker now has 32 answers in a single page view, which
is the whole identifier, and the limit did nothing. This is why the explainer
counts the budget per _visited site_, shared by every frame on the page.

### Attack 7: Taking more turns by reloading

A limit that resets on every page load is a limit a page can reset at will. A
page can reload itself silently, and each reload looks like a fresh start.

**Concrete example.** A tracker is allowed eight questions per page load. Its
page reloads itself four times in two seconds, invisibly. Each load spends a
fresh budget of eight on a different set of files. In the time it takes you to
glance at the screen, it has asked 32 questions. This is why the count has to
survive reloads.

### Attack 8: Going through the side doors

Looking up a file by name in a script is only one way to ask the question. COS
is also wired into ordinary page loading, so a stylesheet, an image, a module,
or a plain network request can each consult the shared cache.

These paths report no answer to the page directly. The site learns the answer
anyway, by watching its own server. If the file came from the shared cache, the
server never sees a request for it. That silence is the same yes-or-no answer.

**Concrete example.** A tracker adds 32 ordinary-looking references to files on
its page and watches which ones its own server is asked for. The eleven it is
never asked for are the ones you already had. It has its 32 answers, and its
page never called the lookup function once. This is why a limit has to count
every path to the cache.

---

## Attacks the design already rules out

Two attacks are worth describing because the design closes them deliberately,
and both would reopen if that care were lost.

### Peeking at a half-finished save

Saving a large file takes time. If the browser announced a file at the moment
someone _started_ saving it, then any site could tell the difference between "in
progress" and "never seen," and that difference is a clean yes-or-no answer
about any file, obtained without storing anything at all.

COS avoids this by adding a file to the cache only once the complete contents
have arrived and been verified. Until then it looks exactly like a file that was
never saved.

### Watching the clock

If a refusal came back faster when the file was genuinely absent, and slower
when the browser was withholding a file it actually had, the timing alone would
give the answer away, and every protection above could be bypassed by holding a
stopwatch.

COS requires a refusal to be identical whether the file is missing, out of
bounds for the asking site, or deliberately withheld, in content and in timing
alike.

---

## Why this is still a tractable problem

Every attack on this page runs through one function. A tracker that wants to
hide in timing quirks or obscure platform behavior has thousands of places to
hide. A tracker using this feature has to come to the front desk and ask a
question out loud, and the browser can count the questions, slow them down, or
refuse to answer.

That is an unusually good position to be in. It also means the protection is
only as good as the counting, which is why the attacks in the middle group, the
ones aimed at the limits themselves, deserve as much attention as the headline
attacks at the top.
