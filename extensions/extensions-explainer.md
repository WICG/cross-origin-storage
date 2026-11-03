# Issue: Browser extension integration points for Cross-Origin Storage (COS)

## Authors

- [Thomas Steiner](mailto:tomac@google.com), Google Chrome
- [Oliver Dunk](mailto:oliverdunk@google.com), Google Chrome

## Background

The [Cross-Origin Storage (COS) API](https://github.com/WICG/cross-origin-storage) ([formal spec](https://wicg.github.io/cross-origin-storage/)) is a proposed browser mechanism that lets large resources (AI models, WebAssembly modules, popular JavaScript libraries, and web fonts) be stored once and retrieved across origins, identified by their cryptographic hash.

Four independent points where the Chrome extensions platform could integrate with COS are sketched below:

1. Extensions could use COS in place of [Shared Modules](https://developer.chrome.com/docs/extensions/reference/manifest/shared-modules) to share resources between extensions.
2. Because a COS hit skips the network entirely, [`declarativeNetRequest`](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest) (DNR), which today only ever sees requests that reach the network stack, needs a way to still apply blocking policy to COS-served resources.
3. Extensions that manage a user's data, such as privacy tools, content blockers, and cleanup utilities, need to see what COS holds, remove entries, and clear COS along with other site data.
4. Extensions that explain or audit what COS shares, such as developer tools, content blockers, and privacy tools, need to know which files are on the [Public Hash List](https://wicg.github.io/cross-origin-storage/#public-hash-list) (PHL), the only files COS may disclose to every origin, and where the list says they came from.

A Chromium prototype implements points 2, 3, and 4. [Section 3](#3-api-reference-chromium-prototype) documents its API surface. It is available in the [unofficial Chromium builds](https://github.com/tomayac/Chromium/releases) with Cross-Origin Storage, started with `--enable-features=CrossOriginStorage`. [tomayac/cos-ad-blocking-demo](https://github.com/tomayac/cos-ad-blocking-demo) shows it in use: a content blocker that catches a script served from COS, and a companion page that lists, deletes, and blocks entries, clears site data, and uses the DevTools protocol.

## 1. Replacing Shared Modules

### How Shared Modules work today

Shared Modules are declared via the `"export"`/`"import"` manifest keys. An importing extension reaches a module's files through the reserved path `chrome-extension://<importing-id>/_modules/<module-id>/…`. A module can optionally restrict itself to an allowlist of importing extension IDs; otherwise any extension can import it. Install and uninstall are tied to the Chrome Web Store: a module is fetched automatically when a dependent extension needs it, and removed once the last dependent is uninstalled. Notably, the docs currently carry the caution "*The Chrome Web Store does not allow the submission of shared modules*", and the page itself was last updated in 2015, so the mechanism is documented but effectively legacy.

### Where COS fits

An extension could resolve a common resource (a bundled library, a Wasm runtime, or a font) via COS by hash, the same lookup a regular web page would perform with `getFileHandle()` or one of the host integrations, such as the `crossoriginstorage` attribute. That would replace publishing a separate Shared Module extension and importing it by extension ID. Because COS entries are keyed by hash:

- The shared resource needs no Chrome Web Store listing or ID-based allowlist of its own; trust comes from the SRI-style hash match, whoever published the bytes.
- A sufficiently common resource could be shared with the ordinary web as well as between extensions. An extension and a web page that both bundle the same widely used library could resolve it from the same COS entry if the entry was written with `origins: '*'` and its hash is on the [Public Hash List](https://wicg.github.io/cross-origin-storage/#public-hash-list).
- The `_modules/<module-id>/` path indirection goes away entirely; resources are addressed by content through COS.

### Open questions

- Which origin does an extension's COS call act as, and what does the same-site default mean for it? COS entries are shared and scoped by `origins`, and by default a stored file is readable only by same-site origins. A `chrome-extension://` origin has no registrable domain, so "same-site" reduces to the extension itself. Is that the right default for extensions, or should all extensions share one scope, closer to today's Shared Modules model?
- A list-scoped write must be authorized by a `Cross-Origin-Storage-Allow-Origin` header on the writing document's response, following the rule that whoever supplies the bytes sends the header. Extension pages are not served over HTTP, so as the spec stands they cannot use the list form at all. Would extensions need a manifest-declared equivalent of the header, and how would that interact with the cap on the number of origins a list can name?
- Extensions aren't "sites" in the usual sense and already carry elevated, manifest-declared permissions. Does that change any of COS's other cross-site-probing mitigations?
- Would extension-authored resources need their own curation path onto (or alongside) the Public Hash List, or should extension use stay restricted to same-extension or explicitly listed storage and never reach global availability?

## 2. Making COS resources blockable via `declarativeNetRequest`

### The gap

DNR rules match a request by `resourceTypes` (`main_frame`, `script`, `stylesheet`, `image`, `font`, `xmlhttprequest`, `media`, `websocket`, `webbundle`, …) and a `urlFilter`, then `block`, `redirect`, `upgradeScheme`, or `allow` it as it reaches the network. That model assumes every controlled resource is fetched over the network each time it's needed.

COS is explicitly designed to skip the network on a cache hit; that is the point of it. It also means that an ad blocker, enterprise content filter, or any other extension using DNR to block a known resource by URL today would have nothing to intercept once that resource starts resolving from COS.

The gap has two shapes:

- **Host integration lookups** (the HTML `crossoriginstorage` attribute, the `crossOriginStorage` import attribute, the CSS `cross-origin-storage()` modifier, and the `crossOriginStorage` option on `fetch()`) each start from an ordinary request that carries a URL and a resource type. COS is consulted before that request would reach the network.
- **Imperative lookups** through `getFileHandle()` carry a hash and nothing else: no URL and no resource type. A read can have no URL to offer at all, for example when an app probes for a better model variant it never intended to download. DNR's `urlFilter` and `resourceTypes` conditions have nothing to match there.

### Proposal sketch

- For host integration lookups, DNR evaluation should run against the resource's original request (its URL and resource type) *before* COS is consulted, so a matching `block` rule prevents the load whether the bytes would have come from the network or from COS. The COS lookup then happens only for a request that survives DNR.
- Because COS resources are hash-identified, a complementary matching capability that filters on the hash itself, independent of the request URL, would let extensions block a specific known resource (say, a fingerprinting script) whatever URL a page references it by. This could be a new `RuleCondition` field (e.g. `hashFilter`), separate from `urlFilter`. For imperative lookups, a hash-based condition is the only one that can match, so this capability is required to cover `getFileHandle()` at all.
- A new `ResourceType` value (e.g. `"cross-origin-storage"`) likely isn't necessary for host integration lookups, since each is triggered by an existing request that already carries a resource type. Imperative lookups have none; a hash-only rule could leave `resourceTypes` unset, or DNR could treat `getFileHandle()` reads as a dedicated type so rules can opt in to matching them.

### Open questions

- Does a COS hit through a host integration currently generate any request DNR's pipeline can see at all, or would this need a new hook so DNR isn't blind to COS-served loads?
- Should blocking a COS-resolved resource be observably different from blocking a network-resolved one? For example, could timing reveal "this would have been served from COS" even when blocked?
- How should a blocked `getFileHandle()` read surface to the page? Rejecting with `NotFoundError` would make a blocked lookup indistinguishable from a cache miss, consistent with how COS already hides gated entries.

### In the Chromium prototype

The prototype takes the hash-based half of the sketch and answers two of the open questions:

- A COS hit makes no request, so the prototype adds a hook: every COS lookup, from any host integration or from `getFileHandle()`, is checked against DNR before COS is consulted.
- The hash condition is called `crossOriginStorageHashes` and takes SRI-style hashes, as in an `integrity` attribute. A rule with it matches only COS lookups of those files, and a COS lookup matches only rules with it.
- A blocked lookup reads as a miss. A host integration then fetches from the network, where URL rules apply to the request as usual. `getFileHandle()` rejects with `NotFoundError`, indistinguishable from an absent entry.
- URL rules apply to requests, and a COS hit makes none, so URL rules do not see hits. Every file in COS was first fetched from a URL, where those rules applied, so a content blocker that wants to keep a file from being served from COS names its hash as well.
- Matches are reported through `getMatchedRules()` and `onRuleMatchedDebug` like any other.

Timing remains open. See [`RuleCondition.crossOriginStorageHashes`](#rulecondition) for the reference.

## 3. API reference (Chromium prototype)

This section documents the extension-facing surface of the Chromium prototype, following the conventions of the [Chrome extensions API reference](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest). It describes a prototype, so every part of it may change.

Hashes appear in two forms. `chrome.crossOriginStorage`, `chrome.publicHash`, and the DevTools protocol identify a file with the dictionary `getFileHandle()` takes, `{value, algorithm}`: its lowercase hexadecimal digest and its Web Crypto algorithm name. `declarativeNetRequest` takes SRI-style strings, as in an `integrity` attribute. [`chrome.publicHash.parseIntegrity()`](#parseintegrity) converts SRI strings to the first form, and this converts back:

```js
// {value: '<hex>', algorithm: 'SHA-256'} to 'sha256-<base64>'.
function toSri({ value, algorithm }) {
  const bytes = value.match(/../g).map((pair) => parseInt(pair, 16));
  return `${algorithm.replace('-', '').toLowerCase()}-${btoa(String.fromCharCode(...bytes))}`;
}
```

### `chrome.crossOriginStorage`

#### Description

Use the `chrome.crossOriginStorage` API to list and remove the files that sites keep in [Cross-Origin Storage](https://wicg.github.io/cross-origin-storage/), a browser-wide store of files shared across origins and identified by their hash.

#### Permissions

`crossOriginStorage`

#### Availability

Chromium prototype, behind the `CrossOriginStorage` feature. Manifest V3 and later. Privileged extension contexts only: the service worker and extension pages, which content scripts cannot reach.

#### Concepts and usage

**Entries.** An entry is a file in COS, identified by its algorithm and hash. It records which origins stored it, which origins it was shared with, and which origins have read it. One entry can serve many sites, so removing it removes it for every origin that stored it.

**Paging.** `getEntries()` returns one page at a time, ordered by algorithm and hash. COS is shared by every site in the profile, so a full store can hold thousands of entries, from AI model shards to small scripts, fonts, and images, each with its lists of origins. Paging keeps each response small enough to transfer and render quickly. A page token names the last entry of the previous page, so listing stays consistent while entries are stored or removed between calls. To list every entry, pass each page's `nextPageToken` as the next call's `pageToken` until a page comes back without one.

**Changes.** `onChanged` fires after entries are stored, read, or removed. It carries no details, and bursts of changes are coalesced into one event, so re-read the entries when it fires.

#### Examples

List every entry:

```js
async function getAllEntries() {
  const entries = [];
  let pageToken;
  do {
    const page = await chrome.crossOriginStorage.getEntries({ pageToken });
    entries.push(...page.entries);
    pageToken = page.nextPageToken;
  } while (pageToken);
  return entries;
}
```

Remove an entry, and keep a view current:

```js
await chrome.crossOriginStorage.removeEntry({
  value: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
  algorithm: 'SHA-256',
});

chrome.crossOriginStorage.onChanged.addListener(async () => {
  render(await getAllEntries());
});
```

#### Types

##### `Entry`

A file in Cross-Origin Storage, identified by the hash of its bytes.

**Properties**

- `algorithm`
  `string`
  The hash algorithm, for example `"SHA-256"`.
- `creationTime`
  `number`
  When the entry was first stored, in milliseconds since the epoch.
- `globallyDisclosable`
  `boolean`
  Whether a write asked for global (`"*"`) availability. Only this grant is gated on the Public Hash List.
- `lastReadTime`
  `number`
  When the entry was last read by any origin, in milliseconds since the epoch, or `0` if it has never been read.
- `mimeType`
  `string`
  The content type sniffed from the leading bytes. Entries store bytes only, so this is a guess.
- `onPublicHashList`
  `boolean`
  Whether the hash is on the Public Hash List.
- `readers`
  [`Reader`](#reader)`[]`
  Origins that have been served the bytes.
- `sharedWithOrigins`
  `string[]`
  Origins a write named explicitly. Origins same-site with a storing origin can always read the entry.
- `size`
  `number`
  The size in bytes.
- `storingOrigins`
  `string[]`
  Origins that stored the bytes.
- `value`
  `string`
  The lowercase hexadecimal digest of the bytes.

##### `EntryKey`

Identifies an entry.

**Properties**

- `algorithm`
  `string`
  The hash algorithm, for example `"SHA-256"`.
- `value`
  `string`
  The lowercase hexadecimal digest of the bytes.

##### `GetEntriesOptions`

**Properties**

- `pageSize`
  `number` optional
  The maximum number of entries to return, from 1 to 1000. Defaults to 100.
- `pageToken`
  `string` optional
  The `nextPageToken` of the previous page.

##### `GetEntriesResult`

**Properties**

- `entries`
  [`Entry`](#entry)`[]`
  The entries on this page, ordered by algorithm and hash.
- `nextPageToken`
  `string` optional
  Present when there are more entries. Pass it as `pageToken` to get the next page.

##### `Reader`

An origin that has been served an entry.

**Properties**

- `count`
  `number`
  How many times the origin has been served the entry.
- `lastReadTime`
  `number`
  When the origin was last served the entry, in milliseconds since the epoch.
- `origin`
  `string`
  The serialized origin.

#### Methods

##### `getEntries()`

```ts
chrome.crossOriginStorage.getEntries(
  options?: GetEntriesOptions,
): Promise<GetEntriesResult>
```

Lists entries, one page at a time.

**Parameters**

- `options`
  [`GetEntriesOptions`](#getentriesoptions) optional
  The page to get.

**Returns**

- `Promise<`[`GetEntriesResult`](#getentriesresult)`>`
  Resolves with the page. Rejects with `"pageSize must be from 1 to 1000."` or `"Invalid pageToken."` for invalid options.

##### `removeEntry()`

```ts
chrome.crossOriginStorage.removeEntry(
  key: EntryKey,
): Promise<void>
```

Removes an entry for every origin that stored it.

**Parameters**

- `key`
  [`EntryKey`](#entrykey)
  The entry to remove.

**Returns**

- `Promise<void>`
  Resolves once the entry is gone. Rejects with `"No entry with this hash."` if there is no such entry, and with `"Invalid algorithm or hash."` for a malformed key.

#### Events

##### `onChanged`

```ts
chrome.crossOriginStorage.onChanged.addListener(
  callback: function,
)
```

Fired after entries are stored, read, or removed. Bursts of changes are coalesced into one event, which fires about half a second after the last change, so re-read the entries when it fires.

**Parameters**

- `callback`
  `function`
  The `callback` parameter looks like:
  `() => void`

### `chrome.publicHash`

#### Description

Use the `chrome.publicHash` API to query the browser's [Public Hash List](https://wicg.github.io/cross-origin-storage/#public-hash-list) (PHL), the list of widely used files that Cross-Origin Storage may make available to any origin. It is modeled on [`chrome.publicSuffix`](https://developer.chrome.com/docs/extensions/reference/api/publicSuffix), which answers the same kind of question for the Public Suffix List.

#### Permissions

`publicHash`

The list is public data, and a lookup reveals nothing about the user, so the permission shows no warning at install time, as for `publicSuffix`.

#### Availability

Chromium prototype, behind the `CrossOriginStorage` feature. Manifest V3 and later. Privileged extension contexts only: the service worker and extension pages, which content scripts cannot reach.

#### Concepts and usage

**The list ships with the browser.** The browser carries a copy of the PHL and updates it with the browser, so the answers describe that copy. [`getListInfo()`](#getlistinfo) reports its version. Every profile, including Incognito, sees the same list, so a lookup does not depend on what any site has stored. To see whether a file is actually in Cross-Origin Storage, use [`chrome.crossOriginStorage`](#chromecrossoriginstorage).

**SHA-256 only.** The PHL lists SHA-256 digests. `integrity` attributes often use SHA-384 or SHA-512, which cannot be looked up: to check such a file, fetch it and hash it with `crypto.subtle.digest('SHA-256', …)`. [`parseIntegrity()`](#parseintegrity) picks the SHA-256 hashes out of an `integrity` value.

**Sections.** The PHL is split into sections. The core `SHA-256` section and the `SHA-256 MANUAL` section of hand-reviewed additions are mandatory: every browser that implements Cross-Origin Storage must honor them. The `SHA-256 HUGGING-FACE` model-hub section is recommended, so a browser may omit it. [`Entry.mandatory`](#entry-1) and [`Section.mandatory`](#section) say which kind a section is.

**Provenance.** For each digest, the PHL records what corroborated it, such as the HTTP Archive, a CDN, or the Hugging Face Hub, and a URL its maintainers saw the bytes at. The list pins bytes and not addresses, so that URL may serve different bytes today. Provenance ships in a separate data file. If the browser cannot load it, lookups still answer whether a hash is listed, and [`ListInfo.provenanceAvailable`](#listinfo) is `false`.

**Promises.** Every method returns a promise. `chrome.publicSuffix` answers synchronously because the Public Suffix List is compiled into the browser. The PHL is a data file of about 19 MB, which the browser process maps and searches, so each lookup is a call into the browser.

#### Examples

Check whether a script's bytes are on the list:

```js
const response = await fetch('https://cdn.example/lib.min.js');
const digest = await crypto.subtle.digest('SHA-256', await response.arrayBuffer());
const hash = [...new Uint8Array(digest)]
  .map((byte) => byte.toString(16).padStart(2, '0'))
  .join('');
if (await chrome.publicHash.isListed({ value: hash, algorithm: 'SHA-256' })) {
  console.log('Any site may be served this file from Cross-Origin Storage.');
}
```

Explain where a listed file came from:

```js
const entry = await chrome.publicHash.getEntry({ value: hash, algorithm: 'SHA-256' });
if (entry) {
  console.log(`${entry.section} (${entry.mandatory ? 'mandatory' : 'recommended'})`);
  console.log(`Corroborated by ${entry.source}, seen at ${entry.url}`);
}
```

Check every `integrity` attribute on a page at once. Content scripts cannot call the API, so a content script collects the values and the service worker looks them up:

```js
// content.js
chrome.runtime.sendMessage({
  integrity: [...document.querySelectorAll('[integrity]')].map((el) => el.integrity),
});

// service-worker.js
chrome.runtime.onMessage.addListener(async ({ integrity }) => {
  const hashes = (
    await Promise.all(integrity.map((value) => chrome.publicHash.parseIntegrity(value)))
  ).flat();
  for (const { value, entry } of await chrome.publicHash.getEntries(hashes)) {
    console.log(value, entry ? entry.source : 'not listed');
  }
});
```

Describe the list:

```js
const info = await chrome.publicHash.getListInfo();
console.log(`Public Hash List ${info.version}: ${info.hashCount} files`);
for (const section of info.sections) {
  console.log(`  ${section.name}: ${section.hashCount}`);
}
```

#### Types

##### `Entry`

A digest on the Public Hash List, and where it came from.

**Properties**

- `algorithm`
  `string`
  The hash algorithm, for example `"SHA-256"`.
- `mandatory`
  `boolean` optional
  Whether every browser that implements Cross-Origin Storage must honor the section. The core and manual sections are mandatory, and the Hugging Face model-hub section is recommended. Absent with `section`.
- `section`
  `string` optional
  The list section the digest is in, for example `"SHA-256"`, `"SHA-256 MANUAL"`, or `"SHA-256 HUGGING-FACE"`. Absent when the browser could not load the list's provenance data.
- `source`
  `string` optional
  What corroborated the digest, for example `"HTTP Archive"` or `"Hugging Face Hub"`. Absent with `section`.
- `url`
  `string` optional
  A URL the list's maintainers saw these bytes at when they added them. The list pins bytes and not addresses, so the URL may serve different bytes today. Absent when no URL was recorded.
- `value`
  `string`
  The lowercase hexadecimal digest.

##### `Hash`

Identifies a file by the hash of its bytes.

**Properties**

- `algorithm`
  `string`
  The hash algorithm, for example `"SHA-256"`. The Public Hash List only lists SHA-256 digests.
- `value`
  `string`
  The hexadecimal digest of the bytes. Either case is accepted, and results are lowercase.

##### `ListInfo`

What the browser's copy of the Public Hash List holds.

**Properties**

- `algorithms`
  `string[]`
  The hash algorithms the list uses: `["SHA-256"]`.
- `hashCount`
  `number`
  How many digests are listed.
- `provenanceAvailable`
  `boolean`
  Whether the provenance data loaded. Without it, the sections are not known, `sections` is empty, and entries carry no `section`, `source`, or `url`.
- `sections`
  [`Section`](#section)`[]`
  The list's sections, in upstream order.
- `version`
  `string`
  The upstream version, for example `"2026-11-02T11:04:56Z"`. The list ships with the browser, so it changes when the browser updates.

##### `LookupResult`

The result of looking up one hash.

**Properties**

- `algorithm`
  `string`
  The hash algorithm, as passed in.
- `entry`
  [`Entry`](#entry-1) optional
  The entry, when the hash is on the list.
- `value`
  `string`
  The digest, lowercased.

##### `Section`

A section of the Public Hash List.

**Properties**

- `hashCount`
  `number`
  How many digests the section lists.
- `mandatory`
  `boolean`
  Whether every browser that implements Cross-Origin Storage must honor it.
- `name`
  `string`
  The section name, for example `"SHA-256"`.

#### Methods

##### `getEntries()`

```ts
chrome.publicHash.getEntries(
  hashes: Hash[],
): Promise<LookupResult[]>
```

Looks up several hashes at once, for example every subresource of a page.

**Parameters**

- `hashes`
  [`Hash`](#hash)`[]`
  Up to 1000 hashes.

**Returns**

- `Promise<`[`LookupResult`](#lookupresult)`[]>`
  Resolves with one result per hash, in the same order. Rejects with `"Invalid algorithm or hash."` if any hash is malformed or uses an algorithm Cross-Origin Storage does not support, and with `"At most 1000 hashes per call."` if there are more.

##### `getEntry()`

```ts
chrome.publicHash.getEntry(
  hash: Hash,
): Promise<Entry | undefined>
```

Gets the Public Hash List entry for a hash, if any.

**Parameters**

- `hash`
  [`Hash`](#hash)
  The hash to look up.

**Returns**

- `Promise<`[`Entry`](#entry-1)` | undefined>`
  Resolves with the entry, or with `undefined` if the hash is not listed. Rejects with `"Invalid algorithm or hash."` if the hash is malformed or uses an algorithm Cross-Origin Storage does not support.

##### `getListInfo()`

```ts
chrome.publicHash.getListInfo(): Promise<ListInfo>
```

Describes the browser's copy of the Public Hash List.

**Returns**

- `Promise<`[`ListInfo`](#listinfo)`>`
  Resolves with the version, size, and sections of the list.

##### `isListed()`

```ts
chrome.publicHash.isListed(
  hash: Hash,
): Promise<boolean>
```

Determines whether a hash is on the Public Hash List.

**Parameters**

- `hash`
  [`Hash`](#hash)
  The hash to look up.

**Returns**

- `Promise<boolean>`
  Resolves with whether the hash is listed. Rejects with `"Invalid algorithm or hash."` if the hash is malformed or uses an algorithm Cross-Origin Storage does not support.

##### `parseIntegrity()`

```ts
chrome.publicHash.parseIntegrity(
  integrity: string,
): Promise<Hash[]>
```

Extracts the SHA-256 hashes from the value of an `integrity` attribute or a `RequestInit.integrity` member, which use the [Subresource Integrity](https://www.w3.org/TR/SRI/) format, for example `"sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="`. Both base64 and base64url digests are accepted, and options after `?` are ignored. Other algorithms are skipped, since the list only lists SHA-256 digests, and so are malformed tokens.

**Parameters**

- `integrity`
  `string`
  The integrity metadata.

**Returns**

- `Promise<`[`Hash`](#hash)`[]>`
  Resolves with the SHA-256 hashes, in the order they appear.

### `chrome.declarativeNetRequest` additions

#### Permissions

`declarativeNetRequest` or `declarativeNetRequestWithHostAccess`, as for any rule. `declarativeNetRequestFeedback` to read matches with `getMatchedRules()` and `onRuleMatchedDebug`.

#### Concepts and usage

**Matching lookups.** A COS lookup is checked against DNR before COS is consulted, whether it comes from a host integration (the HTML `crossoriginstorage` attribute, the CSS `cross-origin-storage()` modifier, the `crossOriginStorage` member of `fetch()`, or the `crossOriginStorage` import attribute) or from `getFileHandle()`. A lookup matches only rules with a `crossOriginStorageHashes` condition naming its hash, and such a rule matches only lookups, never an ordinary request.

**Other conditions.** A rule's other conditions still narrow it. They are matched against the lookup's URL, resource type, initiator, and tab. For a host integration, these are the URL and resource type of the request that triggered the lookup. A `getFileHandle()` lookup serves no request, so its URL is the document's, and its resource type is `"other"`. A rule that leaves `resourceTypes` unset matches lookups of every kind.

**Actions.** A `block`, `redirect`, or `upgradeScheme` action keeps the file from being served from COS; none of them redirects or upgrades anything. The lookup reads as a miss, so a host integration fetches from the network, where rules without the condition apply as usual, and `getFileHandle()` rejects with `NotFoundError`. Rules are evaluated by priority as for any request, so a higher-priority `allow` rule naming the same hash lets the lookup through.

**URL rules and COS hits.** A COS hit makes no request, so URL rules and `webRequest` listeners do not see it. Every file in COS was first fetched from a URL, where those rules applied, so a content blocker that wants to keep a file from being served from COS names its hash as well.

**Feedback.** Matches are recorded like any other, for `getMatchedRules()` and `onRuleMatchedDebug`.

#### Examples

Keep a script from being served from COS, by any integration and by `getFileHandle()`:

```json
{
  "id": 1,
  "priority": 1,
  "action": { "type": "block" },
  "condition": {
    "crossOriginStorageHashes": [
      "sha384-WgFFnswl8NnogiwWkApVoAWEF6vl/rKrK8DMtjvkMjZPsTzppXV9c1ddCRki5jAJ"
    ]
  }
}
```

Block the same file on the network too, by URL, with a second, ordinary rule:

```json
{
  "id": 2,
  "priority": 1,
  "action": { "type": "block" },
  "condition": {
    "urlFilter": "||cdn.jsdelivr.net/npm/prebid.js",
    "resourceTypes": ["script"]
  }
}
```

#### Types

##### `RuleCondition`

**Properties** (addition)

- `crossOriginStorageHashes`
  `string[]` optional
  Hashes of files in Cross-Origin Storage, in the form `"sha256-<base64>"` (also `sha384` and `sha512`), as in an `integrity` attribute. The rule then matches only lookups of these files in Cross-Origin Storage, and a `block`, `redirect`, or `upgradeScheme` action keeps the file from being served from there. Such a lookup reads as a miss, so a fetch goes to the network, where rules without this condition apply to the request as usual. A lookup served from Cross-Origin Storage makes no request, so those rules do not apply to it. An empty list is not allowed, and a rule with a malformed hash fails to load with `Rule with id <id> must specify hashes of the form "sha256-<base64>", "sha384-<base64>", or "sha512-<base64>" for "condition.crossOriginStorageHashes" key.`

### `chrome.browsingData` additions

#### Permissions

`browsingData`

#### Concepts and usage

Removing `crossOriginStorage` data for an origin takes that origin's share of COS: the origin is removed from the storing origins of every entry it stored, entries that no other origin stores are deleted, and the origin's read records are dropped. Entries other origins also store stay, and those origins keep reading them. Without an `origins` filter, every site's share is removed. `settings()` reports `crossOriginStorage` with the same selection as cookies and other site data.

#### Examples

```js
await chrome.browsingData.remove(
  { origins: ['https://example.com'] },
  { crossOriginStorage: true },
);
```

#### Types

##### `DataTypeSet`

**Properties** (addition)

- `crossOriginStorage`
  `boolean` optional
  The sites' share of Cross-Origin Storage: each site is removed from the files it stored, and files that no other site stores are deleted.

### DevTools protocol through `chrome.debugger`

#### Permissions

`debugger`

#### Concepts and usage

An extension attached to a tab with `chrome.debugger` can send the experimental Cross-Origin Storage commands of the [`Storage` domain](https://chromedevtools.github.io/devtools-protocol/tot/Storage/). The protocol has its own entry type, `Storage.CrossOriginStorageEntry`, which also carries the Public Hash List provenance of a listed file. It identifies an entry by `value` and `algorithm`, as [`Entry`](#entry) does, and a `Network.Response` served from Cross-Origin Storage names its entry in `crossOriginStorageHash`, as `{value, algorithm}`.

| Command or event | Purpose |
| --- | --- |
| `Storage.getCrossOriginStorageEntries` | Every entry, one page at a time (`pageSize` from 1 to 1000, default 100; `pageToken`; returns `entries` and `nextPageToken`). Also works on the browser target, with an optional `browserContextId`. |
| `Storage.getCrossOriginStorageEntriesForOrigin` | The entries an origin has stored or been served. |
| `Storage.getCrossOriginStorageEntryContent` | An entry's bytes, base64-encoded, with the sniffed `mimeType`. |
| `Storage.getCrossOriginStorageUsage` | Profile-wide figures: bytes used, unique resources and origins, and bytes saved by deduplication. |
| `Storage.deleteCrossOriginStorageEntry` | Deletes an entry by `value` and `algorithm`. Also works on the browser target. |
| `Storage.clearDataForOrigin` | Takes the `cross_origin_storage` storage type, which removes the origin's share of COS as `chrome.browsingData` does. |
| `Storage.setCrossOriginStorageTracking` | Turns on the `crossOriginStorageEntryStored`, `crossOriginStorageEntryRead`, and `crossOriginStorageEntryRemoved` events. |

#### Examples

```js
const target = { tabId: tab.id };
await chrome.debugger.attach(target, '1.3');
try {
  let pageToken;
  do {
    const page = await chrome.debugger.sendCommand(
      target,
      'Storage.getCrossOriginStorageEntries',
      { pageSize: 100, pageToken },
    );
    for (const entry of page.entries) console.log(entry.algorithm, entry.value);
    pageToken = page.nextPageToken;
  } while (pageToken);
} finally {
  await chrome.debugger.detach(target);
}
```
