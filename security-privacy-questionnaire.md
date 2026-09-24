# [Self-Review Questionnaire: Security and Privacy](https://w3ctag.github.io/security-questionnaire/)

## 01. What information does this feature expose, and for what purposes?

The COS API exposes the availability of files identified by their hash across different origins. The purpose is to enable efficient sharing of common files (for example, AI models, highly popular JavaScript libraries, Wasm modules, and large web fonts) to reduce redundant downloads and storage.

## 02. Do features in your specification expose the minimum amount of information necessary to implement the intended functionality?

Yes, the API exposes only the existence of a file with a known hash and provides read access to it. By default, a stored file is readable only by same-site origins. No additional metadata is exposed. A COS entry deliberately stores bytes only, with no MIME type, status, or response headers, so the host integrations cannot expose more than the imperative API does either. In particular, a `Response` served from COS by the `fetch()` integration carries the stored bytes and cannot carry response headers from a network fetch that never happened. Write access is not gated by a permission prompt (analogously to how pages may freely store data until their quota is exhausted in mechanisms such as the Origin Private File System, IndexedDB, or the Cache API), but it can be denied via Permissions Policy, in which case the user agent throws a `NotAllowedError` `DOMException`. The optional `origins` field allows developers to further minimize exposure by restricting resource access to a trusted set of origins. When that field names a specific list of origins, the declaration must additionally be authorized by a `Cross-Origin-Storage-Allow-Origin` response header from the origin whose bytes are disclosed, so that content injected into a page (for example via XSS) cannot use COS to disclose that origin's data to an attacker-controlled origin without leaving any network trace at the time of compromise. Global sharing of resources is strictly an opt-in operation. In browsers that support third-party cookies, COS lets a tracker link a user's visits across sites no better than a third-party cookie already can. Browsers that block third-party cookies can offer COS as well, provided they bound cross-site disclosure with the mitigations described in the explainer's [privacy considerations](README.md#privacy-considerations), such as a small budget of cross-site lookups per top-level site and sharing of written files only after a user gesture.

## 03. Do the features in your specification expose personal information, personally-identifiable information (PII), or information derived from either?

Possibly. If a COS file is only used on a couple of websites, a site can discover that the user visited those sites by checking for the file's presence. The attacker site would need to probe hashes of resources it's interested in by calling `requestFileHandle()` for each hash; each such call can be considered a probe. For resources shared with every origin (`origins: '*'`), user agents may return a false negative for any probe. One such attack could be checking for the presence of a specific niche JavaScript library only used on certain sites. The `origins` field specifically addresses this by allowing resources to be hidden from any origin not explicitly listed by the storer, reducing the attack surface.

Probing is not limited to the imperative API. Each of the host integrations (the `crossoriginstorage` attribute, the `crossOriginStorage` import attribute, the CSS `cross-origin-storage()` modifier, and the `crossOriginStorage` request option on `fetch()`) also consults COS before falling back to the network. An attacker learns the outcome of such a lookup by observing whether its own server receives the fallback request, which yields the same single bit that a `requestFileHandle()` call yields. No integration discloses more than the imperative API does, and all of them are subject to the same `origins` scoping, availability gating, and GREASE'ing. User agents that limit the number of probes per site must therefore count lookups from all of these surfaces together with imperative calls, since the `fetch()` integration in particular is as scriptable in a loop as `requestFileHandle()` is.

A tracker could also use writes: store a chosen subset of files on one site and read the pattern back on another, which links the user's visits the way a third-party cookie would. The explainer's section on [cross-site tracking through writes](README.md#cross-site-tracking-through-writes) describes both the iframe and the directly loaded script variant, and the mitigations that bound them.

As a further mitigation, user agents are expected to implement an availability gating mechanism using a **Public Hash List (PHL)**, a shared, vendor-neutral allowlist that governs resources shared with every origin (`origins: '*'`). A hash is admitted to the PHL once, offline, after independent evidence shows the resource is widespread (for example, byte-identical copies on a large number of independently crawled origins), which makes its presence in a cache uninformative about any individual user. When a `'*'`-scoped resource's hash is not on the PHL, an origin that reaches it only through that global grant receives a `NotFoundError` `DOMException` regardless of whether the file is present in COS, making the COS storage state indistinguishable from absence. The PHL is never consulted for the origins that stored a file, their same-site origins, or origins on an explicit `origins` list: those can always read it.

User agents may additionally apply **GREASE'ing** ([Generate Random Extensions And Sustain Extensibility](https://tools.ietf.org/html/draft-ietf-tls-grease)) to `'*'`-scoped resources: occasionally returning a `NotFoundError` `DOMException` even when a file's hash is on the PHL, introducing noise that makes probing unreliable. It never applies to storing origins, their same-site origins, or listed origins. This technique is used similarly in [UA Client Hints](https://wicg.github.io/ua-client-hints/#grease). User agents must not GREASE responses for very large files (such as gigabyte-scale AI model weights) where a spurious false negative would force the caller to perform a full re-download, imposing a significant bandwidth cost on the user.

## 04. How do the features in your specification deal with sensitive information?

The API does not allow arbitrary file discovery.

## 05. Does data exposed by your specification carry related but distinct information that may not be obvious to users?

No.

## 06. Do the features in your specification introduce state that persists across browsing sessions?

Yes. Files stored in COS persist across sessions. User agents may manage eviction policies to maintain control over this state and offer manual management options.

## 07. Do the features in your specification expose information about the underlying platform to origins?

No.

## 08. Does this specification allow an origin to send data to the underlying platform?

No.

## 09. Do features in this specification enable access to device sensors?

No.

## 10. Do features in this specification enable new script execution/loading mechanisms?

No. The HTML (`crossoriginstorage` attribute on `<link>`/`<script>`), JavaScript (`crossOriginStorage` import attribute), and `fetch()` (`crossOriginStorage` request option) integrations do not introduce a new script execution or loading mechanism. They reuse the existing `<link>`, `<script>`, module-import, and `fetch()` loading paths, with COS only acting as an alternate source for content that must already match a developer-declared `integrity` hash before it is used. This matters most for the `fetch()` integration, whose response may be passed to a code-loading consumer such as `WebAssembly.instantiateStreaming()`: the bytes were hash-verified when they were written to COS and are matched against the caller's `integrity` value on retrieval, so the integration cannot substitute content that the same `integrity` value would not already have admitted from the network.

## 11. Do features in this specification allow an origin to access other devices?

No.

## 12. Do features in this specification allow an origin some measure of control over a user agent's native UI?

No.

## 13. What temporary identifiers do the features in this specification create or expose to the web?

None.

## 14. How does this specification distinguish between behavior in first-party and third-party contexts?

By default, a file stored in COS is readable only by the origin that stored it and by other same-site origins. The optional `origins` field controls access by restricting it to specific trusted origins or expanding it to all origins, providing an additional layer of control over third-party access. Global sharing of resources is strictly an opt-in operation. The budget of cross-site lookups belongs to the top-level site, so every third-party frame on a page draws from the same small budget and cannot multiply it by adding origins.

Additionally, the availability gating mechanism ensures that a globally available resource is disclosed to other origins only if its hash is on the Public Hash List, which admits only resources shown to be widespread across many independent origins. A resource that is unique to, or concentrated among, a few origins therefore stays hidden from third-party requestors, further reducing the risk of cross-site state inference in third-party contexts.

## 15. How do the features in this specification work in the context of a browser’s Private Browsing or Incognito mode?

Files previously stored in COS are not accessible in Private Browsing or Incognito mode. User agents may allow COS to work during an Incognito session, but the data would not be retained. Alternatively, user agents may disable COS entirely or always report files as absent.

## 16. Does this specification have both "Security Considerations" and "Privacy Considerations" sections?

Yes. The specification includes detailed sections addressing [security considerations](README.md#security-considerations) and [privacy implications](README.md#privacy-considerations).

## 17. Do features in your specification enable origins to downgrade default security protections?

Yes. This is an explicit opt-in operation; user agents are encouraged to surface a console warning when a resource is stored with reduced visibility restrictions.

## 18. What happens when a document that uses your feature is kept alive in BFCache?

The BFCache behavior is aligned with that of the File System Standard ([whatwg/fs#17](https://github.com/whatwg/fs/issues/17)).

## 19. What happens when a document that uses your feature gets disconnected?

The file access operation will terminate, and any pending storage or retrieval will fail gracefully with appropriate errors.

## 20. Does your spec define when and how new kinds of errors should be raised?

Yes. The specification defines specific use cases for `NotAllowedError` and `NotFoundError` `DOMException`s.

## 21. Does your feature allow sites to learn about the user's use of assistive technology?

No.

## 22. What should this questionnaire have asked?

N/A
