# Explainer for the Cross-Origin Storage (COS) API

<img src="https://raw.githubusercontent.com/WICG/cross-origin-storage/refs/heads/main/logo-cos.svg" alt="Cross-Origin Storage (COS) logo, consisting of a folder icon with a crossing person." width="100">

This proposal outlines the design of the **Cross-Origin Storage (COS)** API, a **content-addressable cache** that allows web applications to store and retrieve files across different origins. Building on the **File System Living Standard** defined by the WHATWG, the COS API facilitates secure cross-origin file storage and retrieval for large assets, such as AI models, WebAssembly (Wasm) modules, and highly popular JavaScript libraries. Taking inspiration from **Cache Digests for HTTP/2**, the API identifies files by their content hashes instead of their URL, making it a true content-addressable storage system.

> [!TIP]
> **Try the proposed API with an extension**
>
> While this API is not yet natively implemented in browsers, you can experiment with the proposed surface today.
> Install the [Cross-Origin Storage extension](https://chromewebstore.google.com/detail/cross-origin-storage/denpnpcgjgikjpoglpjefakmdcbmlgih) to inject the `navigator.crossOriginStorage` polyfill on all pages and test the complete flow. See the [source code of the extension](https://github.com/web-ai-community/cross-origin-storage-extension) and read the [instructions](https://github.com/web-ai-community/cross-origin-storage-extension?tab=readme-ov-file#usage) for how to test it.

> [!TIP]
> **Test with your Vite project**
>
> If you are building with Vite, you can experiment with COS integration using the experimental [vite-plugin-cross-origin-storage](https://github.com/tomayac/vite-plugin-cross-origin-storage) plugin. Install it with `npm install vite-plugin-cross-origin-storage --save-dev` and add it to your `vite.config.ts`. The plugin automatically rewrites static imports to load vendor chunks and other assets from COS, stores newly fetched assets in COS for future use, and falls back gracefully to standard network requests when COS is unavailable or the asset is not yet cached.

## Authors

- [Thomas Steiner](mailto:tomac@google.com), Google Chrome
- [Christian Liebel](mailto:christian@liebel.org), Thinktecture AG
- [François Beaufort](mailto:fbeaufort@google.com), Google Chrome

## Participate

- [Spec](https://wicg.github.io/cross-origin-storage/) ([source](index.bs))
- [Public Hash List explainer](public-hash-list/phl-explainer.md)
- [Issues](https://github.com/WICG/cross-origin-storage/issues)
- [PRs](https://github.com/WICG/cross-origin-storage/pulls)
- Support this proposal: https://github.com/WICG/cross-origin-storage/labels/expression%20of%20support

## Table of Contents

<!-- Table of Contents -->

- [Introduction](#introduction)
- [Goals](#goals)
- [Non-goals](#non-goals)
- [User research](#user-research)
  - [User needs example: Hugging Face](#user-needs-example-hugging-face)
  - [User needs example: Web Machine Learning Working Group](#user-needs-example-web-machine-learning-working-group)
- [Use cases](#use-cases)
  - [Use case 1: Large AI models](#use-case-1-large-ai-models)
  - [Use case 2: Large Wasm modules](#use-case-2-large-wasm-modules)
  - [Use case 3: Highly popular JavaScript libraries and frameworks](#use-case-3-highly-popular-javascript-libraries-and-frameworks)
  - [Use case 4: Game engines](#use-case-4-game-engines)
  - [Use case 5: Large web fonts](#use-case-5-large-web-fonts)
- [Potential solution](#potential-solution)
  - [The imperative API](#the-imperative-api)
    - [COS entry](#cos-entry)
    - [Storing files](#storing-files)
    - [Resource visibility upgrades](#resource-visibility-upgrades)
    - [Retrieving files](#retrieving-files)
    - [Transferring a handle](#transferring-a-handle)
  - [Additional integration surfaces](#additional-integration-surfaces)
    - [HTML integration](#html-integration)
    - [JavaScript import attribute integration](#javascript-import-attribute-integration)
    - [CSS integration](#css-integration)
    - [Fetch integration](#fetch-integration)
    - [Processing flow common to all four integrations](#processing-flow-common-to-all-four-integrations)
- [Detailed design discussion](#detailed-design-discussion)
  - [Hashing](#hashing)
  - [Concurrent writes](#concurrent-writes)
  - [What a COS handle can and cannot do](#what-a-cos-handle-can-and-cannot-do)
  - [Workers and origin inheritance](#workers-and-origin-inheritance)
  - [Eviction](#eviction)
  - [Web sustainability](#web-sustainability)
- [Considered alternatives](#considered-alternatives)
  - [Adding a description for each file apart from the hash](#adding-a-description-for-each-file-apart-from-the-hash)
  - [Storing the original URL as part of a COS entry](#storing-the-original-url-as-part-of-a-cos-entry)
  - [Storing files without hashing](#storing-files-without-hashing)
  - [Requiring a minimum file size](#requiring-a-minimum-file-size)
  - [Manually accessing files from a local disk](#manually-accessing-files-from-a-local-disk)
  - [Replacing the imperative API with a `fetch()` integration](#replacing-the-imperative-api-with-a-fetch-integration)
  - [Integrating cross-origin storage in the Cache API](#integrating-cross-origin-storage-in-the-cache-api)
  - [Solving the problem only for AI models](#solving-the-problem-only-for-ai-models)
- [Security and privacy considerations](#security-and-privacy-considerations)
  - [Security considerations](#security-considerations)
    - [Resource integrity check through hashes](#resource-integrity-check-through-hashes)
    - [User controls](#user-controls)
    - [Cache flooding](#cache-flooding)
    - [The `Cross-Origin-Storage-Allow-Origin` header](#the-cross-origin-storage-allow-origin-header)
  - [Privacy considerations](#privacy-considerations)
    - [Cross-site probing](#cross-site-probing)
    - [Availability gating](#availability-gating)
    - [GREASE'ing](#greaseing)
    - [API response reference](#api-response-reference)
    - [Fingerprinting detection](#fingerprinting-detection)
- [Stakeholder feedback / opposition](#stakeholder-feedback--opposition)
- [References](#references)
- [Acknowledgments](#acknowledgments)
- [Appendices](#appendices)
  - [Appendix&nbsp;A: Full IDL](#appendixa-full-idl)
  - [Appendix&nbsp;B: Blob hash with the Web Crypto API](#appendixb-blob-hash-with-the-web-crypto-api)
  - [Appendix&nbsp;C: Frequently asked questions (FAQ)](#appendixc-frequently-asked-questions-faq)

<!-- /Table of Contents -->

## Introduction

The **Cross-Origin Storage (COS)** API provides a secure, **content-addressable cache** for web applications to store and retrieve large files across different origins. This allows applications to share common assets, such as AI models, Wasm modules, and popular JavaScript libraries, without redundant downloads. Resources are identified by their cryptographic hashes, which is what makes the cache content-addressable: the same bytes at two different URLs are a single cache entry, and the hash guarantees integrity. The API reuses concepts like `FileSystemFileHandle` from the **File System Living Standard**, specifically tailored for cross-origin scenarios. The following example demonstrates the basic flow for retrieving a file:

```js
// The hash of the desired file.
const hash = {
  algorithm: 'SHA-256',
  value: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
};
try {
  const handle = await navigator.crossOriginStorage.requestFileHandle(hash);
  // The file exists in Cross-Origin Storage.
  const fileBlob = await handle.getFile();
  // Do something with the blob.
} catch (err) {
  if (err.name === 'NotAllowedError') {
    // Permissions Policy blocks COS in this context.
    console.log('Cross-Origin Storage is blocked by Permissions Policy.');
  } else if (err.name === 'NotFoundError') {
    console.log('The file was not found in Cross-Origin Storage.');
  }
  return;
}
```

## Goals

COS aims to:

- Provide a cross-origin storage mechanism for web applications to store and retrieve large files such as AI models, Wasm modules, and highly popular JavaScript libraries.
- Guarantee data integrity and consistency for file identification (see [Appendix&nbsp;B](#appendixb-blob-hash-with-the-web-crypto-api)).
- Make the web more sustainable and ethical by reducing redundant downloads of large resources the user agent may already have stored locally.

## Non-goals

COS does _not_ aim to:

- Replace existing storage solutions such as the **Origin Private File System**, the **Cache API**, **IndexedDB**, or **Web Storage**.
- Replace content delivery networks (CDNs).
- Allow cross-origin file access _without_ the possibility for the user agent to intervene.
- Modify or supersede the same-origin policy.
- Manage downloads. COS stores complete files or shards that the developer reassembles after retrieval, so resuming a failed download stays the job of the [Background Fetch API](https://wicg.github.io/background-fetch/) or `fetch()` requests with `Range` headers.

## User research

Feedback from developers working with large AI models, Wasm modules, and highly popular JavaScript libraries has highlighted the need for an efficient way to store and retrieve such large files across web applications on different origins. These developers are looking for a standardized solution that allows files to be stored once and accessed by multiple applications, without needing to download and store the files redundantly. COS ensures this is possible while maintaining privacy and security.

### User needs example: Hugging Face

[Joshua Lochner](https://huggingface.co/Xenova) (aka. Xenova) from Hugging Face had the following to say in his [talk at the 2024 Chrome Web AI Summit](https://youtu.be/n18Lrbo8VU8?t=1040):

> _"One can imagine a browser-based web store for models similar to the Chrome Web Store for extensions. From the user's perspective, they could search for web-compatible models on the Hugging Face hub, install it with a single click, and then access it across multiple domains. Currently, Transformers.js is limited in this regard, since models are cached on a per site or per extension basis."_

### User needs example: Web Machine Learning Working Group

Participants of the Web Machine Learning Working Group at the W3C in their meeting on September 21, 2023, discussed [Storage APIs for caching large models](https://www.w3.org/2023/09/21-webmachinelearning-minutes.html#t03). A proposal named [Hybrid AI Explorations](https://github.com/webmachinelearning/proposals/issues/5) listed the following open issues:

> _"If the model runs on the client, large models need to be downloaded, possibly multiple times in different contexts. This incurs a startup latency."_
>
> _"Models are large and can consume significant storage on the client, which needs to be managed."_

This led to the creation of a dedicated [Hybrid AI explainer](https://github.com/webmachinelearning/hybrid-ai/blob/main/explainer.md), which in its introduction states:

> _"For example, ML models are large. This creates network cost, transfer time, and storage problems. As mentioned, client capabilities can vary. This creates adaptation, partitioning, and versioning problems. We would like to discuss potential solutions to these problems, such as shared caches, progressive model updates, and capability/requirements negotiation."_

## Use cases

### Use case 1: Large AI models

Developers working with large AI models can store these models once and access them across multiple web applications. By using the COS API, models can be stored and retrieved based on their hashes, minimizing repeated downloads and storage, while ensuring file integrity. For examples of web-runnable models, see the [WebLLM Chat](https://chat.webllm.ai/) app.

### Use case 2: Large Wasm modules

Web applications that utilize large Wasm modules can store these modules using COS and access them across different origins. This enables efficient sharing of files between applications, reducing redundant downloading and improving performance. A notable example is Google's Flutter framework, which uses several Wasm files that are requested millions of times daily across thousands of hosts:

| Request (`https://gstatic.com/flutter-canvaskit/`)                                                                                                                           | Size   | Hosts | Requests |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | ----- | -------- |
| [`36335019a8eab588c3c2ea783c618d90505be233/chromium/canvaskit.wasm`](https://gstatic.com/flutter-canvaskit/36335019a8eab588c3c2ea783c618d90505be233/chromium/canvaskit.wasm) | 5.1 MB | 1,938 | 596,900  |
| [`a18df97ca57a249df5d8d68cd0820600223ce262/chromium/canvaskit.wasm`](https://gstatic.com/flutter-canvaskit/a18df97ca57a249df5d8d68cd0820600223ce262/chromium/canvaskit.wasm) | 5.1 MB | 1,586 | 579,380  |
| [`36335019a8eab588c3c2ea783c618d90505be233/canvaskit.wasm`](https://gstatic.com/flutter-canvaskit/36335019a8eab588c3c2ea783c618d90505be233/canvaskit.wasm)                   | 6.4 MB | 1,142 | 597,240  |
| [`a18df97ca57a249df5d8d68cd0820600223ce262/canvaskit.wasm`](https://gstatic.com/flutter-canvaskit/a18df97ca57a249df5d8d68cd0820600223ce262/canvaskit.wasm)                   | 6.4 MB | 1,014 | 288,800  |

(**Source:** Google-internal data from the Flutter team: "Flutter engine assets by unique hosts - one day - Dec 10, 2024".)

### Use case 3: Highly popular JavaScript libraries and frameworks

Traditionally, bundlers have combined vendor code and user code, leading to low cache hit rates even _before_ the regular HTTP cache was isolated. By bundling vendor code separately and in its entirety (for example, the complete, untreeshaken React library), developers can ensure a higher cache hit rate. Storing such files once with the COS API allows multiple web apps to share the same highly popular libraries.

### Use case 4: Game engines

Web games built with game engines that have browser support such as [Godot](https://godotengine.org/) or [Unity](https://unity.com/) can store the core game engine code in COS and only load game-specific assets such as textures and game logic from the network. Web gaming portals such as [WebGamer](https://webgamer.io/) that host plenty of casual games with a short path to gameplay on different cross-origin iframes can benefit greatly from this.

### Use case 5: Large web fonts

Web fonts (especially large icon fonts, emoji fonts, and fonts with extensive Unicode coverage) are downloaded across an enormous number of pages daily. Popular fonts served by services like [Google Fonts](https://fonts.google.com/) (for example, [Noto Color Emoji](https://fonts.google.com/noto/specimen/Noto+Color+Emoji) or [Material Symbols](https://fonts.google.com/icons)) are requested by thousands of different sites. If these fonts were stored once in COS, any site using the same font could load it from the user's device and skip the CDN download, benefiting both performance and sustainability.

## Potential solution

### The imperative API

The **COS** API will be available through the `navigator.crossOriginStorage` interface. Files will be stored and retrieved based on their hashes, ensuring that each file is uniquely identified.

Who may read an entry depends on how it was shared. An entry is always available to the origins that stored it and to their same-site origins, which is the default. A write can widen that to a list of named origins, or to every origin (`'*'`). Same-site and list sharing work for any file. Sharing with every origin carries one more condition: an origin outside the other grants only learns that the file is present if its hash is on the **Public Hash List (PHL)**. The PHL is a vendor-neutral list of resources so widespread on the web that having one of them cached reveals nothing about which sites the user visited. Even for a hash on the PHL, the user agent may occasionally answer such an origin as if the file were absent, a technique called [GREASE'ing](#greaseing). [Availability gating](#availability-gating) describes the rules in full, and the [Public Hash List explainer](public-hash-list/phl-explainer.md) covers how hashes get onto the list.

#### COS entry

Each resource stored in COS is conceptually represented as an entry with the following fields:

- **`hash`**: the content identifier, consisting of an `algorithm` (a string naming a hash algorithm recognized by the [Web Crypto API](https://w3c.github.io/webcrypto/), e.g. `"SHA-256"`) and a `value` (a 64-character lowercase hex string in the case of `"SHA-256"`). Entries are keyed by hash: two files with identical bytes and the same hash algorithm are the same entry, regardless of how many origins stored them or from how many URLs they were fetched.
- **`bytes`**: the raw file contents. The user agent verifies at write time that hashing `bytes` with `hash.algorithm` produces `hash.value`; a mismatch throws a `DataError`.
- **`origins`**: the declared sharing scope, stored as two independent, additive grants: an **explicit origins list** and a **globally disclosable** flag, set by a `'*'` write. A write requests `'*'`, a list of origins, or nothing (same-site only), and the request is merged into these grants (see [Resource visibility upgrades](#resource-visibility-upgrades)). A list is capped in length and bounded by the [`Cross-Origin-Storage-Allow-Origin`](#the-cross-origin-storage-allow-origin-header) header.
- **`storing origins`**: the origins that have successfully written this entry. It is persisted across page loads and only ever grows.

[Availability gating](#availability-gating) describes who may read an entry through each grant.

#### Storing files

1. Hash the contents of the file using SHA-256 (or an equivalent secure algorithm, see [Appendix&nbsp;B](#appendixb-blob-hash-with-the-web-crypto-api)). The hash algorithm used is communicated as a string naming a hash algorithm recognized by the [Web Crypto API](https://w3c.github.io/webcrypto/).
1. Request a `FileSystemFileHandle` object for the file, specifying the file's hash.
1. Write the file's data to the `FileSystemFileHandle` object and store it in Cross-Origin Storage. Data can be written with one or more `write()` calls, or streamed in with `sourceStream.pipeTo(writableStream)`. By default, `pipeTo()` closes `writableStream` automatically once `sourceStream` is exhausted, unless called with `preventClose: true` (see [Streaming a file into COS while using it](#example-streaming-a-file-into-cos-while-using-it) for the recommended pattern on large resources). Whenever the stream closes, whether via an explicit `writableStream.close()` call or implicitly through `pipeTo()`, the user agent must verify that the hash of the complete written bytes matches the declared hash, using the algorithm specified in `hash.algorithm`. If the hashes do not match, the user agent must reject the closing operation's promise with a `DataError` `DOMException` and must not store the data in COS.

> [!NOTE]
> A hash-mismatched write leaves no placeholder behind; see [Concurrent writes](#concurrent-writes).

> [!NOTE]
> If `hash.value` is not a valid lowercase hexadecimal string of length 64, or `hash.algorithm` is not a hash algorithm name recognized by the [Web Crypto API](https://w3c.github.io/webcrypto/), the user agent must throw a `TypeError`.

> [!NOTE]
> If the [Permissions Policy](https://www.w3.org/TR/permissions-policy/) for the current context does not allow Cross-Origin Storage, the user agent must throw a `NotAllowedError` `DOMException`.

> [!NOTE]
> If `origins` is a list longer than an implementation-defined maximum length, the user agent must throw a `TypeError`; see [Cross-site probing](#cross-site-probing) for why.

> [!NOTE]
> If storing the file would cause the requesting origin to exceed its implementation-defined storage limit, the user agent must reject the closing operation's promise with a `QuotaExceededError` `DOMException` and should log a warning to the console. Each origin can only store a limited amount of data in COS, which prevents any one site from flooding the cache in an attempt to evict other sites' resources; see [Cache flooding](#cache-flooding).

##### Example: Storing a single file

```js
/**
 * Example usage to store a single file.
 */

// The hash of the desired file.
const hash = {
  algorithm: 'SHA-256',
  value: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
};

// First, check if the file is already in COS.
try {
  const handle = await navigator.crossOriginStorage.requestFileHandle(hash);
  // The file exists in COS.
  const fileBlob = await handle.getFile();
  // Do something with the blob.
  console.log('Retrieved', fileBlob);
  return;
} catch (err) {
  // If the file wasn't in COS, load it from the network and store it in COS.
  if (err.name === 'NotFoundError') {
    // Load the file from the network.
    const fileBlob = await loadFileFromNetwork();
    try {
      const handle = await navigator.crossOriginStorage.requestFileHandle(
        hash,
        {
          create: true,
          // Optional: Only allow these origins to read the file.
          origins: ['https://example.com', 'https://example.org'],
        },
      );
      const writableStream = await handle.createWritable();
      await writableStream.write(fileBlob);
      await writableStream.close();
    } catch (err) {
      // The `write()` failed.
    }
    return;
  }
  // 'NotAllowedError': Permissions Policy blocks COS in this context.
  console.log('Cross-Origin Storage is blocked by Permissions Policy.');
}
```

##### Example: Streaming a file into COS while using it

The example above waits for the whole file to arrive before writing it, which is fine for small resources but throws away the download/consume overlap that streaming APIs such as `WebAssembly.instantiateStreaming()` provide. For large resources, the recommended pattern on a cache miss is to `tee()` the network response body: one branch is consumed immediately, the other is piped into COS in the background. Because `pipeTo()` closes the writable stream when the source is exhausted, and the user agent verifies the hash on close, no explicit `write()` or `close()` call is needed. On a cache hit, `File.stream()` gives the same streaming shape from the stored bytes.

```js
/**
 * Example usage to stream a Wasm module into COS while compiling it.
 */

const hash = {
  algorithm: 'SHA-256',
  value: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
};
const wasmHeaders = { headers: { 'Content-Type': 'application/wasm' } };

try {
  // Cache hit: stream from the stored file. The bytes were hash-verified when
  // they were written, so a fixed MIME type is safe.
  const handle = await navigator.crossOriginStorage.requestFileHandle(hash);
  const file = await handle.getFile();
  const { instance } = await WebAssembly.instantiateStreaming(
    new Response(file.stream(), wasmHeaders),
    imports,
  );
  return instance;
} catch (err) {
  if (err.name !== 'NotFoundError') {
    throw err;
  }
}

// Cache miss: split the body so compilation and storage proceed in parallel.
const response = await fetch('/model.wasm');
if (!response.ok) {
  throw new Error(`HTTP ${response.status}`);
}
const [compileStream, storeStream] = response.body.tee();

// Fire-and-forget store; never block on the write.
(async () => {
  try {
    const handle = await navigator.crossOriginStorage.requestFileHandle(hash, {
      create: true,
      origins: '*',
    });
    const writableStream = await handle.createWritable();
    // Closes `writableStream` on completion; rejects with a `DataError` if the
    // bytes don't match `hash`.
    await storeStream.pipeTo(writableStream);
  } catch (err) {
    // Release the unconsumed branch so the body isn't buffered indefinitely.
    storeStream.cancel().catch(() => {});
  }
})();

const { instance } = await WebAssembly.instantiateStreaming(
  new Response(compileStream, wasmHeaders),
  imports,
);
return instance;
```

The same shape works for any consumer that accepts a `ReadableStream`, for example a model loader that parses safetensors headers as bytes arrive, or `new Response(stream).blob()` if the consumer ultimately needs a `Blob`. Note that a `tee()`'d stream buffers whatever the slower branch has not yet read, so a store branch that never consumes must be canceled, as shown above.

> [!NOTE]
> The [fetch integration](#fetch-integration) collapses the entire example into a single `fetch()` call and leaves the stream splitting to the user agent.

##### Example: Choosing who can read a file

The `origins` option decides who can read a file once it is stored:

- **Omitted:** only same-site origins can read it. This fits resources shared across subdomains of one site, such as a company's proprietary AI model.
- **A list of origins:** only the listed origins (plus the same-site default) can read it. **This option is recommended for proprietary resources or resources for which global COS cache hits are not anticipated.** For example, if a company has two related sites, `write.example` and `calculate.example`, that both use the same AI model for proofreading, they can restrict the model to just these two origins.
- **`'*'`:** any origin can read it, subject to [availability gating](#availability-gating). **This option is appropriate for widely used resources that many sites are likely to share, such as popular AI models, Wasm modules, or JavaScript libraries.** It is an explicit opt-in, so developers cannot make a resource globally available by accident.

```js
// Same-site only.
await navigator.crossOriginStorage.requestFileHandle(hash, { create: true });

// Only `calculate.example` and `write.example`. Any other origin gets a
// `NotFoundError`, even if the file is stored in COS.
await navigator.crossOriginStorage.requestFileHandle(hash, {
  create: true,
  origins: ['https://calculate.example', 'https://write.example'],
});

// Any origin, if the hash is on the Public Hash List.
await navigator.crossOriginStorage.requestFileHandle(hash, {
  create: true,
  origins: '*',
});

// Then write the file through the returned handle.
```

> [!NOTE]
> For this restricted sharing to take effect, a `Cross-Origin-Storage-Allow-Origin` response header must authorize the listed origins. Whoever supplies the bytes sends the header, and with the imperative API the page's own script supplies them, so `write.example` sends `Cross-Origin-Storage-Allow-Origin: https://calculate.example, https://write.example` on the response for the document making the write. The header is the ceiling; the `origins` array can only narrow it. Any listed origin the header does not authorize is dropped, which stops content injected into the page from redirecting the disclosure to an origin the operator never approved. See [The `Cross-Origin-Storage-Allow-Origin` header](#the-cross-origin-storage-allow-origin-header).

#### Resource visibility upgrades

The visibility of a resource in COS can be upgraded but never downgraded:

- **Adding access**: any site that supplies the full bytes can widen an entry's scope with another `create: true` request. A `'*'` write sets the global grant, and a list write merges its origins into the existing list; origins that already had access keep it. Requiring the full bytes keeps a write from revealing whether the entry already existed.
- **No removal**: a write never removes access. If origin A stores a file restricted to `['https://a.example']` and origin B later writes the same hash with `'*'`, the entry becomes globally disclosable and keeps its list, so `https://a.example` still reads it without the hash being on the PHL. A narrower request only adds its origins to the list, and the user agent should log a console warning that the write cannot restrict the resource.
- **Origins list capacity**: the [maximum list length](#storing-files) also caps the merged list. Once separate writes have filled it, later writes still succeed, the excess origins are dropped, and the user agent should log a console warning.

#### Retrieving files

To retrieve a file, call `requestFileHandle()` with its hash and no `create` option, as shown in the [Introduction](#introduction). To work with several files, call `requestFileHandle()` once per file and combine the calls with `Promise.all()`; the [FAQ entry on why the API is singular](#appendixc-frequently-asked-questions-faq) explains why there is no batched form.

> [!NOTE]
> A `NotFoundError` `DOMException` does not necessarily mean the file is absent from COS. User agents may suppress availability of a file for privacy reasons (see [Availability gating](#availability-gating)). Callers should handle `NotFoundError` by falling back to a network fetch, regardless of the cause.

##### Example: Choosing among interchangeable resources

Sometimes the hashes a caller holds are *alternatives*, and the caller wants whichever one the user already has. This is the everyday situation for AI models, which are published as families of interchangeable variants that differ in size and quality but expose the same interface. An app may be built around `whisper-tiny` because that is the smallest download it can justify, but it would rather transcribe with `whisper-large-v3` if the user already downloaded that one on some other site. Downloading the small model while a better one already sits on the device is the worst of both worlds: the user pays for bytes and gets worse transcriptions.

Expressing this means asking COS a question before committing to any download: *which of these do you already have?*

```js
/**
 * Example usage to pick the best locally available variant of a model.
 */

// The only variant the app ever downloads, so the only one with a URL.
const download = {
  name: 'whisper-tiny',
  url: 'https://cdn.example/models/whisper-tiny.bin',
  hash: {
    algorithm: 'SHA-256',
    value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  },
};

// Better variants, most capable first. These are only probed: the app uses
// one if the user already has it, and never downloads it.
const upgrades = [
  {
    name: 'whisper-large-v3',
    hash: {
      algorithm: 'SHA-256',
      value:
        '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
    },
  },
  {
    name: 'whisper-medium',
    hash: {
      algorithm: 'SHA-256',
      value:
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    },
  },
];

// Probe the upgrades first, then the download itself, which the user may also
// already have from another site.
for (const candidate of [...upgrades, download]) {
  try {
    const handle = await navigator.crossOriginStorage.requestFileHandle(
      candidate.hash
    );
    // Found one, so nothing needs to be downloaded at all.
    console.log('Using locally available model', candidate.name);
    return { name: candidate.name, file: await handle.getFile() };
  } catch (err) {
    if (err.name !== 'NotFoundError') {
      // 'NotAllowedError': Permissions Policy blocks COS in this context.
      throw err;
    }
    // Not available, so try the next candidate.
  }
}

// None of them is available, so download the one variant the app ships with.
const fileBlob = await fetch(download.url).then((response) => response.blob());
console.log('Obtained model from network', download.name);
```

Only `whisper-tiny` carries a URL, because it is the only variant the app will ever download. Every probe is a read with no URL attached: the app has no download URL to offer for `whisper-large-v3`, since it never intended to fetch that variant, and the whole point of asking is to avoid a network request. A [fetch integration](#fetch-integration) cannot express this, which is one of the reasons it complements the imperative API (see [Replacing the imperative API with a `fetch()` integration](#replacing-the-imperative-api-with-a-fetch-integration)).

> [!NOTE]
> Each `requestFileHandle()` call counts as a probe against the user agent's [cross-site probing](#cross-site-probing) safeguards, so candidate lists are expected to be short, in the order of the handful of variants a model family actually ships.

#### Transferring a handle

A `FileSystemFileHandle` is serializable, so a handle for a COS entry can be passed to another context with `postMessage()`, a `MessagePort`, or a `BroadcastChannel`, the same way any other file handle can. This is a second way to obtain a handle, so the same disclosure rules apply to it:

- **Same-origin only.** Deserializing a COS handle in a context whose origin differs from the one that obtained it throws a `DataCloneError`. A readable handle cleared [availability gating](#availability-gating) for *the origin that asked*; passing it to another origin would hand over the bytes without `origins`, the Public Hash List, or [GREASE'ing](#greaseing) ever being evaluated for that origin. Transferring between a page and its own worker, or between same-origin documents, works normally.
- **Readability travels with the handle.** A handle from a `create: true` request that has not been written through is still not readable after being transferred: `getFile()` keeps rejecting until that handle's own write completes. Conversely, a handle from a successful read stays readable without being re-checked, so transferring a handle can't be used to re-roll GREASE'ing or otherwise re-probe availability.

```js
// Same-origin: fine. The worker gets a handle it can read from.
const handle = await navigator.crossOriginStorage.requestFileHandle(hash);
worker.postMessage(handle);

// Cross-origin: throws `DataCloneError` on the receiving side.
otherOriginFrame.postMessage(handle, 'https://other.example');
```

### Additional integration surfaces

The imperative JavaScript API in the previous section covers the general case, but a large share of real-world resource loading already happens through constructs that carry a URL and, increasingly, an [`integrity`](https://w3c.github.io/webappsec-subresource-integrity/) hash. Routing those through `requestFileHandle()` means hand-writing a cache check, a fallback fetch, and a store, which is boilerplate the user agent can just as well perform itself. COS is therefore designed to be reachable from four host integrations:

| Surface | Opt-in | Reaches |
| --- | --- | --- |
| [HTML](#html-integration) | `crossoriginstorage` attribute | `<link>` and `<script>` subresources |
| [JavaScript imports](#javascript-import-attribute-integration) | `crossOriginStorage` import attribute | static and dynamic module imports |
| [CSS](#css-integration) | `cross-origin-storage()` URL modifier | CSS-referenced assets such as web fonts |
| [Fetch](#fetch-integration) | `crossOriginStorage` request option | imperative fetches of a known URL |

In all four, the `integrity` hash identifies the file in COS, and the COS option takes the same values as the `origins` option of `requestFileHandle()`: omitted or empty for same-site only, a list of origins for a specific set of origins, or `*` for global availability. Each is defined in its own host specification.

As with the imperative API, the list form is bounded by a response header so that injected markup cannot widen the sharing scope. Only the list form needs this header: a resource shared with every origin (`*`) or left at the same-site default (value omitted or empty) needs no `Cross-Origin-Storage-Allow-Origin` header. Whoever supplies the bytes sends the header, and for these integrations that is the server of the fetched resource, such as the origin serving a font or a library. That origin is the one entitled to decide that those particular bytes may be shared, and the referencing page can only narrow that; the embedding document's own header plays no part. The effective scope is the intersection of the declared value and what the resource's `Cross-Origin-Storage-Allow-Origin` header permits. See [The `Cross-Origin-Storage-Allow-Origin` header](#the-cross-origin-storage-allow-origin-header).

What the four have in common is that the caller holds both a URL and a hash, and wants the bytes. The imperative API remains the surface for everything that does not fit that shape: writes whose bytes did not come from a single `fetch()`, reads that have no URL to offer at all, and lookups across a set of interchangeable candidates (see [Choosing among interchangeable resources](#example-choosing-among-interchangeable-resources)). See [Replacing the imperative API with a `fetch()` integration](#replacing-the-imperative-api-with-a-fetch-integration) for why the last row of the table does not subsume `requestFileHandle()`.

#### HTML integration

`<link>` and `<script>` elements that already carry [`integrity`](https://w3c.github.io/webappsec-subresource-integrity/#integrity-metadata) can opt in to COS with a new `crossoriginstorage` attribute, proposed to the WHATWG in [whatwg/html#12770](https://github.com/whatwg/html/issues/12770).

##### Example: Opting stylesheets and scripts into COS

A valueless `crossoriginstorage` attribute means same-site only, `*` makes the resource globally available, and a space-separated list of origins restricts it to those origins:

```html
<!-- Same-site only. -->
<link
  rel="stylesheet"
  href="https://static.acme-inc.example/same-site-css-framework.css"
  integrity="sha256-abc123..."
  crossoriginstorage
/>

<!-- Globally available. -->
<script
  src="https://cdn.example/popular-js-framework.js"
  integrity="sha256-def456..."
  crossoriginstorage="*"
></script>

<!--
  Restricted to specific origins. `https://acme-cdn.example` serves this
  script, so its response must carry
  `Cross-Origin-Storage-Allow-Origin: https://acme-inc.example, https://acme-cdn.example`.
-->
<script
  src="https://acme-cdn.example/acme-inc-corporate.js"
  integrity="sha256-def456..."
  crossoriginstorage="https://acme-inc.example https://acme-cdn.example"
></script>
```

Omitting `crossoriginstorage` entirely while keeping `integrity` preserves today's behavior: the resource is fetched and verified, and COS plays no part.

> [!NOTE]
> `crossoriginstorage` is unrelated to the existing [`crossorigin`](https://html.spec.whatwg.org/multipage/urls-and-fetching.html#cors-settings-attributes) attribute despite the similar name. The `crossorigin` attribute controls the CORS request mode for the element's fetch, which is an orthogonal concern.

#### JavaScript import attribute integration

[Import attributes](https://github.com/tc39/proposal-import-attributes) provide a way to reach COS from module imports and dynamic `import()`, without going through `navigator.crossOriginStorage` directly, proposed to the WHATWG in [whatwg/html#12771](https://github.com/whatwg/html/issues/12771).

> [!NOTE]
> The `with { … }` syntax is defined by TC39, but `crossOriginStorage` is a **host-defined attribute key**. Like `integrity`, it requires no TC39 involvement and will be defined in the HTML Standard.

##### Example: Opting modules into COS

An empty string means same-site only, `"*"` makes the module globally available, and a space-separated list of origins restricts it to those origins:

```js
// Same-site only.
import sameSite from "https://static.acme-inc.example/same-site-resource.js" with {
  integrity: "sha256-abc123...",
  crossOriginStorage: "",
};

// Globally available.
import popular from "https://cdn.example/popular-resource.js" with {
  integrity: "sha256-abc123...",
  crossOriginStorage: "*",
};

// Restricted to specific origins. `https://acme-cdn.example` serves this
// module, so its response must carry
// `Cross-Origin-Storage-Allow-Origin: https://acme-inc.example, https://acme-cdn.example`.
import corporate from "https://acme-cdn.example/acme-inc-corporate.js" with {
  integrity: "sha256-def456...",
  crossOriginStorage: "https://acme-inc.example https://acme-cdn.example",
};
```

The same attributes work with dynamic `import()`:

```js
const module = await import("https://cdn.example/popular-resource.js", {
  with: {
    integrity: "sha256-abc123...",
    crossOriginStorage: "*",
  },
});
```

#### CSS integration

In addition to the imperative JavaScript API, COS can be accessed from CSS via a new [`<request-url-modifier>`](https://drafts.csswg.org/css-values-5/#typedef-request-url-modifier) called `cross-origin-storage()`, proposed to the CSS Working Group in [w3c/csswg-drafts#14056](https://github.com/w3c/csswg-drafts/issues/14056). This is especially valuable for resources referenced in CSS, such as large web fonts, where the imperative JavaScript API is hard to apply.

The modifier is used alongside the existing [`integrity()`](https://drafts.csswg.org/css-values-5/#typedef-request-url-modifier-integrity-modifier) modifier.

```
cross-origin-storage() = cross-origin-storage( [ '*' | <string># ]? )
```

##### Example: Opting fonts into COS

No arguments means same-site only, `*` makes the font globally available, and a list of origins restricts it to those origins; all other origins still fetch the font from the network URL:

```css
/* Same-site only. */
@font-face {
  font-family: "Same-Site Corporate Font";
  src: url(
    "https://static.acme-inc.example/same-site-corporate.woff2"
    integrity("sha256-abc123...")
    cross-origin-storage()
  );
}

/* Globally available. */
@font-face {
  font-family: "Popular Emoji Font";
  src: url(
    "https://cdn.example/popular-emoji.woff2"
    integrity("sha256-xyz789...")
    cross-origin-storage(*)
  );
}

/*
  Restricted to specific origins. `https://acme-cdn.example` serves this font,
  so its response must carry
  `Cross-Origin-Storage-Allow-Origin: https://acme-inc.example, https://acme-cdn.example, https://acme-marketing.example`.
*/
@font-face {
  font-family: "ACME Inc Corporate Font";
  src: url(
    "https://acme-cdn.example/acme-inc-corporate.woff2"
    integrity("sha256-abc123...")
    cross-origin-storage("https://acme-inc.example", "https://acme-cdn.example", "https://acme-marketing.example")
  );
}
```

> [!NOTE]
> `cross-origin-storage()` is unrelated to the CSS [`cross-origin()`](https://drafts.csswg.org/css-values-5/#typedef-request-url-modifier-cross-origin-modifier) modifier despite the similar name. The `cross-origin()` modifier controls the CORS request mode, which is an orthogonal concern.

#### Fetch integration

The three integrations above cover resources referenced from markup, from module graphs, and from stylesheets. The remaining case is the imperative one: a script that already knows the URL and the hash of a resource and fetches it itself. That is how most Wasm modules, asset bundles, and other large binaries are loaded today, and it is currently the case that costs the most code to move onto COS.

A `crossOriginStorage` option on [`RequestInit`](https://fetch.spec.whatwg.org/#requestinit), used alongside the existing [`integrity`](https://fetch.spec.whatwg.org/#dom-requestinit-integrity) option, closes that gap. This is proposed to the WHATWG in [whatwg/fetch#1954](https://github.com/whatwg/fetch/issues/1954), where it would be defined as:

```webidl
dictionary CrossOriginStorageRequestOptions {
  (DOMString or sequence<DOMString>) origins;
  DOMString contentType;
};

partial dictionary RequestInit {
  (DOMString or sequence<DOMString> or CrossOriginStorageRequestOptions) crossOriginStorage;
};
```

The string and array forms are shorthands for `{ origins }`. The dictionary form additionally lets the caller declare a `contentType`, a proposed answer to the first of the [open design questions](#open-design-questions) below.

##### Example: Fetching through COS

An empty string opts the resource into COS for same-site access only, `*` makes it globally available, and an array of origins restricts it to those origins:

```js
// Same-site only.
const sameSite = await fetch('https://static.acme-inc.example/same-site-resource.wasm', {
  integrity: 'sha256-abc123...',
  crossOriginStorage: '',
});

// Globally available.
const global = await fetch('https://cdn.example/popular-resource.wasm', {
  integrity: 'sha256-abc123...',
  crossOriginStorage: '*',
});

// Restricted to specific origins. `https://acme-cdn.example` serves this
// resource, so its response must carry
// `Cross-Origin-Storage-Allow-Origin: https://acme-inc.example, https://acme-cdn.example`.
const restricted = await fetch('https://acme-cdn.example/acme-inc-corporate.wasm', {
  integrity: 'sha256-def456...',
  crossOriginStorage: [
    'https://acme-inc.example',
    'https://acme-cdn.example',
  ],
});
```

Omitting `crossOriginStorage` while keeping `integrity` preserves today's behavior: the response is fetched and verified, and COS plays no part. This is why same-site scope is spelled as an empty string: `fetch()` has no `create: true` to carry the opt-in separately, so the member's presence is what opts the request into COS and its value is what scopes the result. The imperative API, which has `create: true`, expresses the same scope by omitting `origins`.

> [!NOTE]
> The list form is an array here, whereas the HTML attribute and the import attribute use a space-separated string and the CSS modifier a comma-separated list of `<string>`s. This is deliberate because a `RequestInit` member is an ordinary JavaScript value, so a `sequence<DOMString>` is the idiomatic spelling, and it matches the imperative `origins` option exactly, down to the IDL type. The three other surfaces have no such choice to make: HTML content attribute values are text, import attribute values are [currently restricted to strings by TC39](https://github.com/tc39/proposal-import-attributes#should-more-than-just-strings-be-supported-as-attribute-values), and CSS has no array type, so each takes the closest list syntax its host already provides. All four resolve to the same `origins` value space.

##### Example: The streaming example, without the plumbing

The [streaming example](#example-streaming-a-file-into-cos-while-using-it) above is the recommended way to write a cache-miss path by hand today, and it is around 30 lines of `tee()`, `pipeTo()`, and cancellation for what is conceptually a single fetch. The common case is easy to get wrong, and getting it wrong silently costs the download and compile overlap that `WebAssembly.instantiateStreaming()` exists to provide. With the fetch integration, the whole example collapses to:

```js
const { instance } = await WebAssembly.instantiateStreaming(
  fetch('https://cdn.example/module.wasm', {
    integrity: 'sha256-abc123...',
    crossOriginStorage: { origins: '*', contentType: 'application/wasm' },
  }),
  imports,
);
```

The user agent performs the COS lookup, serves the bytes from storage on a hit, fetches and stores them on a miss, and does the stream splitting internally.

> [!NOTE]
> The `contentType` member is a proposed answer to [Response fidelity on a cache hit](#open-design-questions). Without it, this example works on a cache miss, where the network response carries `Content-Type: application/wasm`, and fails on a hit, where the stored bytes carry no type and `WebAssembly.instantiateStreaming()` rejects them.

> [!NOTE]
> Server runtimes such as Node.js, Deno, and Bun implement `fetch()` but have no cross-origin boundary and no user to protect, so COS does not exist there. They ignore `crossOriginStorage` the way they ignore other browser-specific request options, and isomorphic code keeps working unchanged.

##### Open design questions

Two questions are specific to this integration and need answers in the [Fetch Standard discussion](https://github.com/whatwg/fetch/issues/1954):

- **Response fidelity on a cache hit.** A COS entry stores bytes only (see [Storing the original URL as part of a COS entry](#storing-the-original-url-as-part-of-a-cos-entry)), so a `Response` served from a hit has no `Content-Type`. The three other integrations take the type from the element, the module type, or the CSS property; a plain `fetch()` has no destination to take it from. `WebAssembly.instantiateStreaming()` requires `application/wasm`, so without a declared type the collapsed example above works on a cold cache and fails on a warm one. The proposed answer is a caller-declared `contentType` in the option's dictionary form, applied on hits and misses alike, so both return the same `Content-Type`.
- **Header stripping.** A `Response` served from COS cannot carry the headers of a fetch that never happened. This discloses no more than `requestFileHandle()` does: hits are timing-observable anyway, and the read is gated by `origins`, the [Public Hash List](#availability-gating), and [GREASE'ing](#greaseing). A declared `contentType` settles `Content-Type`; which `status`, `Content-Length`, and `type` a hit reports is open.

#### Processing flow common to all four integrations

1. The user agent looks the `integrity` hash up in COS. If the requesting origin may read the entry (see [Availability gating](#availability-gating)), the resource is served from COS and no network request is made.
2. Otherwise, the resource is fetched as usual. If it matches the `integrity` hash, the user agent stores it in COS with the declared scope; if not, it fails per existing `integrity` behavior and nothing is stored.

A lookup that doesn't succeed is indistinguishable from a cache miss, exactly as `requestFileHandle()`'s `NotFoundError` is.

> [!NOTE]
> The hash format differs between these four integrations and the imperative form. The `integrity` attribute, the `integrity` import attribute, the `integrity()` CSS modifier, and the `integrity` request option follow the [Subresource Integrity](https://w3c.github.io/webappsec-subresource-integrity/) convention and express hashes as base64-encoded strings (e.g., `sha256-abc123…`). The imperative `requestFileHandle()` API uses lowercase hexadecimal strings (e.g., `8f434346…`), which matches the format AI model hubs such as [Hugging Face](https://huggingface.co/) use for model checksums. The user agent normalizes both representations internally; they identify the same bytes.

## Detailed design discussion

### Hashing

The current hashing algorithm is [SHA-256](https://w3c.github.io/webcrypto/#alg-sha-256), implemented by the **Web Crypto API**. If hashing best practices should change, COS will reflect the [implementers' recommendation](https://w3c.github.io/webcrypto/#algorithm-recommendations-implementers) in the Web Crypto API.

The hashing algorithm used is encoded in the hash object's `algorithm` field as a plain string naming a hash algorithm recognized by the [Web Crypto API](https://w3c.github.io/webcrypto/), e.g. `"SHA-256"`. This flexible design allows changing the hashing algorithm in the future. The hash string must be a valid lowercase hexadecimal string of length 64 (for SHA-256).

Note that `algorithm` is typed as a plain `DOMString`, even though its value space is exactly the set of names a [`HashAlgorithmIdentifier`](https://w3c.github.io/webcrypto/#dom-hashalgorithmidentifier) accepts. `HashAlgorithmIdentifier` is `(object or DOMString)`, and the `object` branch exists so parameterized algorithms like HMAC can carry extra fields (e.g. `{name: "HMAC", hash: "SHA-256"}`). Hash algorithms take no such parameters, and `algorithm` is stored, compared, and round-tripped as part of a content-addressable key, so admitting arbitrary objects here would add no capability while complicating equality and serialization.

```js
const hash = {
  algorithm: 'SHA-256',
  value: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
};
```

### Concurrent writes

Two tabs can find the same hash absent and start writing it at the same time. The user agent stores the file once; this proposal does not coordinate the two downloads.

- **While an entry is unwritten,** every `requestFileHandle()` call for its hash, from any origin including the writer, rejects with `NotAllowedError` (see the "Created, not yet written" row of the [read path table](#read-path)). The distinct error tells a reader that a write is in progress, so it does not start another download of a file that may already be gigabytes along.
- **A handle from a `create: true` request** rejects `getFile()` with the same `NotAllowedError` until that handle's own write has completed, even for the origin that requested it.
- **When a write fails,** for example because its bytes don't match the hash, the user agent removes the entry once no other write for that hash is outstanding, and later lookups get `NotFoundError`. Waiting for the other writes keeps one tab's failure from disturbing another tab's write for the same hash, and an entry some origin has already written is never removed by a failed write.

### What a COS handle can and cannot do

`requestFileHandle()` returns an ordinary `FileSystemFileHandle`. A COS entry has no name, no containing directory, and no identity beyond its hash, so the handle's operations behave as follows:

- **`name`** is the entry's hash. The File System Standard defines `name` as the last component of the handle's locator path, and a COS locator path is the hash.
- **`isSameEntry()`** reports whether the two handles' hashes match, since the registry holds at most one entry per hash. It rejects when the other handle belongs to a different file system or was not obtained by the calling origin, because the caller may not inspect that handle.
- **`move()` and `remove()`** reject with `NotAllowedError`, the error `removeEntry()` uses when readwrite access is not granted. An entry is shared by every origin that stored it, so deletion is left to eviction and the user's storage controls, and a rename has nothing to act on. Neither method is standardized yet ([WICG/file-system-access#214](https://github.com/WICG/file-system-access/issues/214)).
- **Permission queries** never return `prompt`, since handles are pre-authorized. For write access, they return `denied` on any handle not obtained from a create request, because only such a handle can call `createWritable()`. Requesting permission returns the same result.
- **`createSyncAccessHandle()`** rejects with `InvalidStateError`, as the File System Standard specifies for any handle outside a bucket file system. This also prevents a writable file descriptor from changing an entry's bytes after verification, bytes every origin the entry is disclosed to would then read.
- **`createWritable({ keepExistingData: true })`** starts empty. Seeding the stream with an existing entry's bytes would let a caller close it without writing anything and become a storing origin for bytes it never supplied, gaining read access without `origins`, the Public Hash List, or GREASE'ing being consulted. A writable closed without any write therefore holds zero bytes and fails verification with `DataError`, like any other mismatch.

### Workers and origin inheritance

A `CrossOriginStorageManager` uses the origin of its context. For a worker, that is the origin of the worker's environment settings object, independent of its script URL:

- **Workers created from a `blob:` URL** have the origin of the context that created them and share that page's COS view: each reads what the other stored, and the worker's writes count as the page's own. Revoking the `blob:` URL does not change this.
- **Workers created from a `data:` URL** have an opaque origin, which has no stable identity to key storing origins or same-site checks on. This proposal does not yet define what `requestFileHandle()` does for an opaque calling origin; the opaque-origin rule in "validate a COS request" covers only the origins a caller names in `origins`. Implementations should at minimum reject such calls promptly, so the returned promise never stays pending.
- **Service workers** cannot use COS for now; see below.

The Permissions Policy check applies to the calling global. A dedicated or shared worker may use COS only if every document in its owner set may, resolved transitively through any intervening workers, so `Permissions-Policy: cross-origin-storage=()` also covers calls moved into `new Worker(URL.createObjectURL(blob))`. A service worker has no owner set: its registration persists, and the browser starts it in response to events, often with no client open. Supporting service workers needs a policy captured from their own script response, most plausibly a `Permissions-Policy` header, which is work for the Permissions Policy and Service Workers specifications.

### Eviction

Under critical storage pressure, user agents could offer a dialog that invites the user to manually free up storage. The user agent could also delete files automatically based on, for example, a least recently used approach.

User agents are further expected to provide settings UI through which users can inspect which files are stored in COS and which origins have most or least recently accessed each file. Users may then choose to delete files from COS through this UI. This UI could also let users add manually downloaded files, such as large AI models already on disk, to COS directly.

When the user clears site data, all usage information associated with the origin should be removed from files in COS. If a file in COS, after the removal of usage information, is deemed unused, the user agent may delete it from COS.

### Web sustainability

Minimizing redundant downloads and storage is inherently beneficial for sustainability. The [Ethical Web Principles](https://w3ctag.github.io/ethical-web-principles/) state that the Web [_"is an environmentally sustainable platform"_](https://w3ctag.github.io/ethical-web-principles/#sustainable) and suggest _"lowering carbon emissions by minimizing data storage and processing requirements"_, which is what COS does for large files the user may already have on their device.

## Considered alternatives

### Adding a description for each file apart from the hash

To facilitate manual COS management, one approach would be to allow developers to store a human-readable description alongside the resource. Apps could reference to the same file identified by a unique hash using different descriptions. For example, an English site could refer to the [`g-2b-it-gpu-int4.bin`](https://storage.googleapis.com/jmstore/kaggleweb/grader/g-2b-it-gpu-int4.bin) AI model as "Gemma AI model from Google", whereas another Spanish site could refer to it as "modelo de IA grande de Google". Instead, we envision user agents to enrich COS management UI based on the hashes. For example, a user agent could know that a file identified by a given hash is a well-known AI model and optionally surface this information to the user in the user agent settings UI.

### Storing the original URL as part of a COS entry

Recording the URL each file was fetched from would make a multi-gigabyte blob legible in the browser's storage UI and help a developer debug a `requestFileHandle()` miss. COS entries do not store it, for three reasons:

- **The URL belongs to one writer's fetch.** An entry is shared by every origin that stores its bytes, and ten origins may fetch the same file from ten different URLs. No single URL represents the entry: the first storer has no special standing, and a set of URLs would grow without bound and accept additions from any origin that writes the bytes.
- **It can't be verified.** The hash verifies the bytes; a URL is only the writer's claim, and an unverified label inside an otherwise verified structure would read as provenance.
- **It leaks more than an origin does.** COS's disclosure limits (`origins`, [availability gating](https://wicg.github.io/cross-origin-storage/#availability-gating), and the Public Hash List) are calibrated for origin-level information. A full URL can carry paths, query parameters, tokens, and user identifiers (`https://cdn.example/models/user-1234/weights.bin`).

Other uses of a stored URL are covered elsewhere. After eviction, the calling origin already knows its own URL and can fetch it again, and a re-fetch by the user agent would send a request to a third party's URL with ambient authority. Permission UI already has the requesting origin at prompt time. Popularity corroboration happens during [Public Hash List](public-hash-list/phl-explainer.md) admission, offline and once for everyone.

For debugging and storage inspection, a user agent may keep an **implementation-private provenance record**, such as the URL each storing origin fetched the bytes from, and when, as browser state kept outside the entry (see [Provenance metadata](https://wicg.github.io/cross-origin-storage/#provenance-metadata) in the spec):

- No COS API exposes it to script, and an origin cannot observe a record it did not produce.
- Only trusted surfaces show it: the browser's settings and storage inspection UI, developer tools, and extension APIs behind an explicit, user-granted permission, on the same footing as other APIs that expose browsing history (see [Browser extension integration points for COS](extensions/extensions-explainer.md)).
- It is presented as the writing origin's unverified claim. Only the hash guarantees the content, and two origins may record different URLs for the same entry.
- It is discarded with the entry, and per origin when that origin leaves the entry's storing origins, including when the user clears that origin's site data.

Content cannot detect whether a user agent keeps such a record, so keeping one is an implementation choice.

### Storing files without hashing

Storing files by their names would risk name collisions, especially in a cross-origin environment. The use of hashes guarantees unique identification of each file, ensuring that the contents are consistently recognized and retrieved. Storing files based on their URLs would work if apps reference the same URLs, for example, on the same CDN, but wouldn't work if apps reference the same file stored at different locations.

### Requiring a minimum file size

One approach would be to require a minimum file size for a resource to be eligible for COS. No minimum file size is proposed. It would be trivial to inflate a file's size to meet any such threshold, for example by appending padding bytes or comments.

### Manually accessing files from a local disk

Different origins can manually open the same file on disk, either using the File System Access API's `showOpenFilePicker()` method or using the classic `<input type="file">` approach. This requires the file to be stored once, and access to the file can then be shared as explained in [Cache AI models in the browser](https://developer.chrome.com/docs/ai/cache-models#special_case_use_a_model_on_a_hard_disk). While this works, it's manual and error-prone, as it requires the user to know what file to choose from their hard drive in the file picker.

### Replacing the imperative API with a `fetch()` integration

COS is reachable from `fetch()` (see [Fetch integration](#fetch-integration)), and `requestFileHandle()` remains alongside it: a fetch couples naming a resource to downloading it, and the imperative API keeps the two separate. Three things depend on that separation:

- **Bytes from sources other than a single `fetch()`.** Download management is a [non-goal](#non-goals), and stored bytes may come from a [Background Fetch](https://wicg.github.io/background-fetch/), from `Range` requests for a sharded resource the site reassembles itself, from a file the user picked from disk, or from another storage API. A shard has no URL that serves it, so a fetch integration cannot store it.
- **Reads with no URL.** A lookup may only ask whether COS holds a hash, with nothing to download if it doesn't, for example when an app probes for a better model variant it never intended to fetch (see [Choosing among interchangeable resources](#example-choosing-among-interchangeable-resources)). A fetch-shaped probe would have to name a URL the app does not want to request.
- **Handles.** A `FileSystemFileHandle` can be [transferred to another context](#transferring-a-handle), read several times, and written through with the File System Standard machinery developers already use for [OPFS](https://fs.spec.whatwg.org/#sandboxed-filesystem). A `Response` is a single, one-shot body, and a store-only write has no request to make.

The imperative API is the general surface, and the four [host integrations](#additional-integration-surfaces) are shortcuts for the common case where a URL and a hash are both known up front and the bytes are wanted immediately.

### Integrating cross-origin storage in the Cache API

The Cache API is fundamentally modeled around the concepts of `Request` or URL strings, and `Response`, for example, `Cache.match()` or `Cache.put()`. In contrast, what makes COS unique is that it uses file hashes as the keys to files to avoid duplicates.

### Solving the problem only for AI models

AI models are admittedly the biggest motivation for working on COS, so one alternative would be to solve the problem exclusively for AI models. A question that arises in the context is how it would be enforced that files actually be AI models? Given this question, this approach does not seem like a good fit, and the non-AI [use cases](#use-cases) are well worth addressing, too.

Additionally, common AI inference solutions like [Transformers.js](https://github.com/huggingface/transformers.js) rely on [WebAssembly in the underlying ONNX Runtime](https://onnxruntime.ai/docs/build/web.html#build-instructions), which is true independent of the backend, WebGPU or Wasm. The same applies to [MediaPipe](https://github.com/google-ai-edge/mediapipe), which requires Wasm files as so-called [`WasmFileset`](https://developers.google.com/edge/api/mediapipe/js/tasks-text.filesetresolver) objects for its various MediaPipe Tasks APIs.

## Security and privacy considerations

See the complete [questionnaire](security-privacy-questionnaire.md) for details.

### Security considerations

#### Resource integrity check through hashes

Access is scoped to individual files, [each identified by its hash](#hashing): a site can request only a file whose hash it already knows, and cannot list what COS contains. The user agent verifies every file against its hash (for example, SHA-256) when it is written, so a site reading from COS gets exactly the bytes it would have downloaded itself. User agents can additionally check hashes against malware databases such as [VirusTotal](https://www.virustotal.com/gui/home/search), or consult in-browser protections such as [Safe Browsing](https://safebrowsing.google.com/), before storing a file.

#### User controls

Users can inspect, evict, and clear COS files through the user agent's settings UI; see [Eviction](#eviction).

#### Cache flooding

A per-origin storage limit keeps any one site from flooding the cache to evict other sites' resources; see the `QuotaExceededError` note under [Storing files](#storing-files).

#### The `Cross-Origin-Storage-Allow-Origin` header

The `origins` list form discloses a writer's bytes to origins it does not control. Script (the `origins` option) and markup (the `crossoriginstorage` attribute and its siblings) declare that list, so an attacker who can inject either on the writing origin could write data the compromised page can read into a list-scoped entry naming an attacker-controlled origin, and read it back later from that origin. The write produces **no network egress at the moment of compromise**, so egress monitoring, a `connect-src` allowlist, or a CSP report endpoint sees a clean page load. CSP does not contain exfiltration in general either, since a top-level navigation to an attacker URL also leaves the page.

A list therefore needs authorization from a response header that injected content cannot forge. Whoever supplies the bytes sends the header:

- **Imperative API:** the bytes may be generated in script, so the header comes from the **writing document's** response.
- **Host integrations:** the bytes come from a fetched resource, so the header comes from that **resource's** response. This also keeps a site from declaring another site's asset shareable with origins of its choosing.

The declared list is intersected with the origins the header names. Unnamed origins are dropped, and if no cross-origin recipient remains, the write still succeeds with the same-site default. The check applies per writer, so a later writer can add only origins its own response authorizes and cannot change an earlier writer's scope.

Only the list form needs the header. A `'*'`-scoped resource reaches a non-storing origin only if its hash is on the [Public Hash List](#availability-gating), which a per-user secret never is, and the same-site default names no cross-origin recipient.

The header bounds disclosure to the origins the operator authorized. If a site legitimately shares data with `https://partner.example` and is then compromised, injected script can still reach that partner. This matches the guarantee `connect-src` gives: the attack surface shrinks from any origin on the web to the operator's declared partners.

### Privacy considerations

In browsers that still support third-party cookies, user agents are expected to make this API available only in contexts where third-party cookies are enabled.

#### Cross-site probing

If a file is only used on certain kinds of websites, an attacker can discover that the user visited those sites by checking for the file's presence. For example, if someone has a game engine stored in COS, they probably play games on the web, which an attacker might exploit, for example, for targeted advertising. The attacker site would need to probe hashes of resources it's interested in. The `origins` field mitigates this risk by allowing origins to restrict resource access to a specific set of trusted origins, ensuring the resource is not globally "probeable". Sites are expected to use this field for proprietary resources or when global COS cache hits are not expected.

This mitigation only holds if a list stays meaningfully smaller than the web. A caller could otherwise enumerate a very large number of origins (for example, a public top-sites ranking) and approximate global disclosure without the explicit `'*'` opt-in. `origins` lists therefore have an implementation-defined maximum length that fits a handful of related origins under common control, and the [`Cross-Origin-Storage-Allow-Origin`](#the-cross-origin-storage-allow-origin-header) header bounds which origins a list may name.

User agents are expected to implement safeguards against such attacks, for example, by limiting the number of probes, or by returning false negatives when a site known to be malicious is probing. Each call to `requestFileHandle()` can be considered a probe, and user agents can limit the number of probes per site or even block probes from sites known to be malicious.

A lookup performed by one of the [host integrations](#additional-integration-surfaces) counts as a probe on the same terms. Such a lookup returns no error to the page, but a site learns its outcome anyway by observing whether its own server receives the fallback request, which is the same single bit a `NotFoundError` carries. This discloses nothing the imperative API would not, and the same `origins` scoping, availability gating, and GREASE'ing apply. It does mean a probe limit must count all four surfaces: the [fetch integration](#fetch-integration) in particular is as scriptable in a loop as `requestFileHandle()` is, so counting only imperative calls would leave the limit trivially avoidable.

#### Availability gating

Whether a `requestFileHandle()` call returns a handle depends on the grants an entry carries. Grants are set at write time, add up, and are never removed (see [Resource visibility upgrades](#resource-visibility-upgrades)):

- **Storing origins** can always read the entry, mirroring the Cache API, where an origin can always read what it stored.
- **Same-site origins of a storing origin** can read it. This is the default scope.
- **Origins on the explicit `origins` list** can read it, whether or not the hash is on the PHL.
- **Any other origin** can read it only through the global grant (`origins: '*'`), and only if the hash is on the **Public Hash List (PHL)**, a shared, vendor-neutral allowlist all browser vendors are expected to respect. [GREASE'ing](#greaseing) may still withhold it.

An origin that qualifies under none of these, or relies on the global grant for a hash not on the PHL, receives a `NotFoundError` `DOMException` that is identical in content and timing to the file being absent. A requester that qualifies through the first three grants never consults the PHL, even if the entry is also globally disclosable. The PHL gates only the global grant because the other grants already reflect a bounded disclosure decision by the storing origin; requiring public curation for them would block ordinary restricted sharing of proprietary resources (see [Choosing who can read a file](#example-choosing-who-can-read-a-file)).

The PHL covers well-known resources, such as popular open-source libraries, widely used Wasm modules, web fonts served by major font CDNs, and AI model weights published by recognized model hubs. These are unconditionally eligible for cross-origin availability disclosure because independent, corroborated evidence of their ubiquity (for example, appearing byte-identical across a large number of independently crawled origins) makes cache presence uninformative about any individual user, a form of **k-anonymity** where _k_ is that minimum corroborating-origin count. This ubiquity check happens once, offline, as part of how a hash is admitted to the PHL, so the user agent never repeats it at query time.

The full design of the PHL (its data format, admission criteria, sourcing, and cross-vendor governance) is specified in the [Public Hash List explainer](public-hash-list/phl-explainer.md). In short, it proposes: governance by the WHATWG, modeled directly on the [Public Suffix List](https://publicsuffix.org/)'s cross-vendor, rolling-release precedent; a compact, algorithm-sectioned flat-text format of bare hex digests, with provenance kept in human-readable comments; and a separate, optional section for hashes hand-curated from a recognized AI model hub, to unlock the AI use case that objective popularity signals alone cannot cover. An early, non-normative code prototype of the list itself lives in this repository for now, at [`public-hash-list/implementation/`](public-hash-list/implementation/). The [Governance](public-hash-list/phl-explainer.md#governance) section of the PHL explainer describes the target end state, a dedicated, cross-vendor repository.

Developers must NOT treat a `NotFoundError` as proof that a file is absent from COS: the requesting origin may be out of scope, or the user agent may be withholding a `'*'`-scoped file for privacy reasons. The fallback is always a network fetch.

#### GREASE'ing

As an additional privacy mitigation, user agents may employ **GREASE'ing** ([Generate Random Extensions And Sustain Extensibility](https://tools.ietf.org/html/draft-ietf-tls-grease)): occasionally returning a `NotFoundError` `DOMException` even when a file is present in COS. This introduces noise that makes it harder for sites to distinguish a true absence from a privacy-motivated false negative. A similar technique is applied in [UA Client Hints](https://wicg.github.io/ua-client-hints/#grease).

GREASE'ing applies only to origins that reach an entry through `origins: '*'`, the same case the PHL gates. Storing origins, their same-site origins, and origins on an explicit `origins` list are never GREASEd: same-site origins are one trust unit, and a listed origin was named on purpose by the storing site and authorized by its `Cross-Origin-Storage-Allow-Origin` header, so withholding the file from them would only cost a re-download.

However, user agents must exercise size-proportionate judgment when applying GREASE'ing. For small files, where a fallback to a network fetch is inexpensive, occasional false negatives are a reasonable privacy trade-off. For very large files, such as gigabyte-scale AI model weights, a false negative would force the caller to perform a full re-download, imposing a significant and observable bandwidth and latency cost on the user. User agents must NOT GREASE responses for files whose size makes a spurious re-download clearly disproportionate to the privacy benefit.

#### API response reference

The following tables summarize the response a user agent must return for every combination of inputs.

##### Read path

The rows are keyed by how the requesting origin qualifies (see [Availability gating](#availability-gating)). A "—" means the column does not apply to that row.

| Requester qualifies via | On PHL? | GREASEd? | Response |
| -- | -- | -- | -- |
| (entry created, not yet written) | — | — | `NotAllowedError` |
| Storing origin | — | — | Success |
| Same-site of a storing origin | — | — | Success |
| On the explicit `origins` list | — | — | Success |
| Global grant only (`origins: '*'`) | Yes | No | Success |
| Global grant only (`origins: '*'`) | Yes | Yes | `NotFoundError` |
| Global grant only (`origins: '*'`) | No | — | `NotFoundError` |
| No qualifying grant (out of scope) | — | — | `NotFoundError` |
| Not in COS | — | — | `NotFoundError` |

The "Created, not yet written" row also covers `getFile()` on a handle from a still-pending `create: true` request; see [Concurrent writes](#concurrent-writes).

`getFile()` is gated per handle, so a handle obtained from a `create: true` request also rejects with `NotAllowedError` when some other origin has *already* written the entry and this handle has not been written through. Otherwise a create request would be a read: any origin could ask for a handle and immediately call `getFile()`, learning an entry's contents without satisfying `origins`, the PHL, or GREASE'ing, all of which are enforced on the read path only.

##### Write path

| Condition | Written with | Response |
| -- | -- | -- |
| `hash.value` or `hash.algorithm` is malformed | Any | `TypeError` |
| `origins` is a list longer than the implementation-defined maximum length | Any | `TypeError` |
| Permissions Policy blocks COS | Any | `NotAllowedError` |
| Valid hash, declared hash matches computed hash | Any | Success |
| Valid hash, declared hash matches computed hash, but exceeds the requesting origin's storage limit | Any | `QuotaExceededError` |
| Valid hash, declared hash does not match computed hash | Any | `DataError` |
| Merging `origins` into an existing list-scoped entry would exceed the implementation-defined maximum length | List | Success (excess origins silently dropped) |
| A listed origin is not permitted by the writer's `Cross-Origin-Storage-Allow-Origin` header | List | Success (unauthorized origins dropped; falls back to same-site if none remain) |

##### Transfer path

| Condition | Response |
| -- | -- |
| Deserializing a handle in a context same-origin with the one that obtained it | Success, preserving whether it was readable |
| Deserializing a handle in any other origin | `DataCloneError` |

#### Fingerprinting detection

User agents are also expected to use (on-device) machine learning to identify possible fingerprinting attempts. For example, if a site crafts unique hashes for each user (which hints at fingerprinting), user agents can detect this and block the COS probing attempt. Some user agents have [successfully applied this technique](https://blog.google/products/chrome/building-a-more-helpful-browser-with-machine-learning/#:~:text=More%20peace%20of%20mind%2C%20less%20annoying%20prompts) to silence notification spam.

## Stakeholder feedback / opposition

- **Web Developers**: [Expressed support](#user-research) for enabling sharing of large files without redundant downloads and storage, particularly large AI models, large Wasm modules, and highly popular JavaScript libraries.

## References

- [Public Hash List explainer](public-hash-list/phl-explainer.md)
- [File System Living Standard](https://fs.spec.whatwg.org/)
- [Web Cryptography API](https://w3c.github.io/webcrypto/)
- [Subresource Integrity](https://w3c.github.io/webappsec-subresource-integrity/)
- [Import Attributes](https://github.com/tc39/proposal-import-attributes)
- [CSS Values and Units Module Level 5](https://drafts.csswg.org/css-values-5/)
- [Fetch Living Standard](https://fetch.spec.whatwg.org/)
- [Cache Digests for HTTP/2](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-cache-digest)
- [Web Sustainability Guidelines (WSG)](https://w3c.github.io/sustainableweb-wsg/)
- [Ethical Web Principles](https://w3ctag.github.io/ethical-web-principles/)

## Acknowledgments

Many thanks for valuable feedback from:

- **Tab Atkins-Bittner**, Google Chrome
- **Yash Raj Bharti**, Google Cloud
- **Joshua Lochner**, Hugging Face
- **Patrick Meenan**, Google Chrome

Many thanks for valuable inspiration or ideas from:

- **Kenji Baheux**, Google Chrome
- **Kevin Moore**, Google Chrome

## Appendices

### Appendix&nbsp;A: Full IDL

Copied from the [formal spec](https://wicg.github.io/cross-origin-storage/) on every commit.

<!-- IDL -->

```webidl
[Exposed=(Window,Worker), SecureContext]
interface CrossOriginStorageManager {
  Promise<FileSystemFileHandle> requestFileHandle(
      CrossOriginStorageRequestFileHandleHash hash,
      optional CrossOriginStorageRequestFileHandleOptions options = {});
};

dictionary CrossOriginStorageRequestFileHandleHash {
  required DOMString value;
  required DOMString algorithm;
};

dictionary CrossOriginStorageRequestFileHandleOptions {
  boolean create = false;
  (DOMString or sequence<DOMString>) origins;
};

interface mixin NavigatorCrossOriginStorage {
  [SameObject, SecureContext] readonly attribute CrossOriginStorageManager crossOriginStorage;
};
Navigator includes NavigatorCrossOriginStorage;
WorkerNavigator includes NavigatorCrossOriginStorage;
```

<!-- /IDL -->

### Appendix&nbsp;B: Blob hash with the Web Crypto API

```js
async function getBlobHash(blob) {
  const hashAlgorithmIdentifier = 'SHA-256';

  // Get the contents of the blob as binary data contained in an ArrayBuffer.
  const arrayBuffer = await blob.arrayBuffer();

  // Hash the arrayBuffer using SHA-256.
  const hashBuffer = await crypto.subtle.digest(
    hashAlgorithmIdentifier,
    arrayBuffer,
  );

  // Convert the ArrayBuffer to a hex string.
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');

  return {
    algorithm: hashAlgorithmIdentifier,
    value: hashHex,
  };
}

// Example usage:
const fileBlob = await fetch('https://example.com/ai-model.bin').then(
  (response) => response.blob(),
);
getBlobHash(fileBlob).then((hash) => {
  console.log('Hash:', hash);
});
```

### Appendix&nbsp;C: Frequently asked questions (FAQ)

<details>
  <summary>
    <strong>Question:</strong> Would the first site that added a file be seen as the authority?
  </summary>
  <p>
    <strong>Answer:</strong> No, each site has the same powers. If the user stops using the first site that has put a given file into COS, but continues using another site that depends on the same file, the file would stay around. Only if no site depends on the file anymore, the user agent may consider the file for manual or automatic removal from COS if it's under storage pressure or based on regular storage house keeping.
  </p>
</details>

<details>
  <summary>
    <strong>Question:</strong> Why does the API use <code>requestFileHandle()</code> (singular) rather than <code>requestFileHandles()</code> (plural)?
  </summary>
  <p>
    <strong>Answer:</strong> Early drafts of the API exposed <code>requestFileHandles(hashes, options)</code>, which accepted an array of hashes and returned an array of <code>FileSystemFileHandle</code> objects. A <a href="https://github.com/WICG/cross-origin-storage/issues/61">survey of every known real-world implementation</a> (Hugging Face Transformers.js, wllama, Flutter, Apache TVM, MLC WebLLM, Emscripten, and others) found that <strong>every single call site passed a single-element array and immediately destructured the result to a single handle</strong>. No implementation ever passed more than one hash in a single call.
  </p>
  <p>
    The plural form was therefore pure ergonomic friction: callers had to wrap a value in an array only to unwrap it again (<code>const [handle] = await ...requestFileHandles([hash])</code>). The singular form <code>requestFileHandle(hash, options)</code>, modeled directly on the File System Standard's <a href="https://fs.spec.whatwg.org/#api-filesystemdirectoryhandle-getfilehandle"><code>FileSystemDirectoryHandle.getFileHandle()</code></a>, makes the common case clean and readable. Where <code>getFileHandle()</code> takes a <code>name</code>, <code>requestFileHandle()</code> takes a <code>hash</code> object that identifies the file, and the options follow the same model: without <code>create: true</code>, the user agent returns a handle for an existing file, and with it, a handle that can be written to. On a create request, <code>origins</code> restricts who can later read the file or makes it globally available. For the rare case where multiple files are needed concurrently, the idiomatic JavaScript pattern <code>Promise.all(hashes.map(hash =&gt; navigator.crossOriginStorage.requestFileHandle(hash)))</code> gives better per-file error granularity than a batched call would anyway.
  </p>
</details>
