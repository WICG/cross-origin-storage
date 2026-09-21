# Issue: Browser extension integration points for Cross-Origin Storage (COS)

## Authors

- [Thomas Steiner](mailto:tomac@google.com), Google Chrome
- [Oliver Dunk](mailto:oliverdunk@google.com), Google Chrome

## Background

The [Cross-Origin Storage (COS) API](https://github.com/WICG/cross-origin-storage) ([formal spec](https://wicg.github.io/cross-origin-storage/)) is a proposed browser mechanism that lets large resources (AI models, WebAssembly modules, popular JavaScript libraries, and web fonts) be stored once and retrieved across origins, identified by their cryptographic hash.

Two independent points where the Chrome extensions platform could integrate with COS are sketched below:

1. Extensions could use COS in place of [Shared Modules](https://developer.chrome.com/docs/extensions/reference/manifest/shared-modules) to share resources between extensions.
2. Because a COS hit skips the network entirely, [`declarativeNetRequest`](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest) (DNR), which today only ever sees requests that reach the network stack, needs a way to still apply blocking policy to COS-served resources.

## 1. Replacing Shared Modules

### How Shared Modules work today

Shared Modules are declared via the `"export"`/`"import"` manifest keys. An importing extension reaches a module's files through the reserved path `chrome-extension://<importing-id>/_modules/<module-id>/…`. A module can optionally restrict itself to an allowlist of importing extension IDs; otherwise any extension can import it. Install and uninstall are tied to the Chrome Web Store: a module is fetched automatically when a dependent extension needs it, and removed once the last dependent is uninstalled. Notably, the docs currently carry the caution "*The Chrome Web Store does not allow the submission of shared modules*", and the page itself was last updated in 2015, so the mechanism is documented but effectively legacy.

### Where COS fits

An extension could resolve a common resource (a bundled library, a Wasm runtime, or a font) via COS by hash, the same lookup a regular web page would perform with `requestFileHandle()` or one of the host integrations, such as the `crossoriginstorage` attribute. That would replace publishing a separate Shared Module extension and importing it by extension ID. Because COS entries are keyed by hash:

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
- **Imperative lookups** through `requestFileHandle()` carry a hash and nothing else: no URL and no resource type. A read can have no URL to offer at all, for example when an app probes for a better model variant it never intended to download. DNR's `urlFilter` and `resourceTypes` conditions have nothing to match there.

### Proposal sketch

- For host integration lookups, DNR evaluation should run against the resource's original request (its URL and resource type) *before* COS is consulted, so a matching `block` rule prevents the load whether the bytes would have come from the network or from COS. The COS lookup then happens only for a request that survives DNR.
- Because COS resources are hash-identified, a complementary matching capability that filters on the hash itself, independent of the request URL, would let extensions block a specific known resource (say, a fingerprinting script) whatever URL a page references it by. This could be a new `RuleCondition` field (e.g. `hashFilter`), separate from `urlFilter`. For imperative lookups, a hash-based condition is the only one that can match, so this capability is required to cover `requestFileHandle()` at all.
- A new `ResourceType` value (e.g. `"cross-origin-storage"`) likely isn't necessary for host integration lookups, since each is triggered by an existing request that already carries a resource type. Imperative lookups have none; a hash-only rule could leave `resourceTypes` unset, or DNR could treat `requestFileHandle()` reads as a dedicated type so rules can opt in to matching them.

### Open questions

- Does a COS hit through a host integration currently generate any request DNR's pipeline can see at all, or would this need a new hook so DNR isn't blind to COS-served loads?
- Should blocking a COS-resolved resource be observably different from blocking a network-resolved one? For example, could timing reveal "this would have been served from COS" even when blocked?
- How should a blocked `requestFileHandle()` read surface to the page? Rejecting with `NotFoundError` would make a blocked lookup indistinguishable from a cache miss, consistent with how COS already hides gated entries.
