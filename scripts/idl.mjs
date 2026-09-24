// SPDX-FileCopyrightText: 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

// Copies the WebIDL from the spec's `<xmp class="idl">` blocks into a
// Markdown file, between the `<!-- IDL -->` and `<!-- /IDL -->` markers, so
// the explainer never drifts from the spec.
//
// Usage: node scripts/idl.mjs [markdown] [spec]
// Defaults to README.md and index.bs. Pass `-` as the spec to read it from
// stdin, which lets the pre-commit hook use the staged version.

import { readFileSync, writeFileSync } from 'node:fs';

const START = '<!-- IDL -->';
const END = '<!-- /IDL -->';

const [markdownPath = 'README.md', specPath = 'index.bs'] =
  process.argv.slice(2);

const spec = readFileSync(specPath === '-' ? 0 : specPath, 'utf8');
const blocks = [
  ...spec.matchAll(/<xmp class=["']?idl["']?>\n([\s\S]*?)<\/xmp>/g),
].map((match) => match[1].trimEnd());
if (!blocks.length) {
  console.error(`${specPath}: no <xmp class="idl"> blocks found.`);
  process.exit(1);
}

const source = readFileSync(markdownPath, 'utf8');
const startIndex = source.indexOf(START);
const endIndex = source.indexOf(END, startIndex);
if (startIndex === -1 || endIndex === -1) {
  console.warn(`${markdownPath}: no "${START}" … "${END}" markers, skipping.`);
  process.exit(0);
}

const updated = `${source.slice(0, startIndex + START.length)}

\`\`\`webidl
${blocks.join('\n\n')}
\`\`\`

${source.slice(endIndex)}`;
if (updated !== source) {
  writeFileSync(markdownPath, updated);
  console.log(`${markdownPath}: IDL updated from ${specPath}.`);
}
