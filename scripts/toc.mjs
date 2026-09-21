// SPDX-FileCopyrightText: 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

// Generates a table of contents for a Markdown file between the
// `<!-- Table of Contents -->` and `<!-- /Table of Contents -->` markers.
// Only headings that follow the start marker are listed. If the end marker is
// missing, it gets added right after the start marker.
//
// Usage: node scripts/toc.mjs [file ...]   (defaults to README.md)

import { readFileSync, writeFileSync } from 'node:fs';

const START = '<!-- Table of Contents -->';
const END = '<!-- /Table of Contents -->';
const MIN_LEVEL = 2;
const MAX_LEVEL = 4;

// Drops links and images, keeping their text, for the ToC entry.
const toLabel = (heading) =>
  heading.replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1').trim();

// Reduces a ToC entry to the plain text GitHub derives the anchor from.
const toText = (label) =>
  label
    .replace(/`([^`]*)`/g, '$1')
    .replace(/(\*\*|__|\*|_)(.+?)\1/g, '$2')
    .replace(/&nbsp;/g, '\u00a0')
    .replace(
      /&(amp|lt|gt|quot);/g,
      (_, name) => ({ amp: '&', lt: '<', gt: '>', quot: '"' })[name],
    );

// Mirrors GitHub's anchor algorithm: lowercase, drop punctuation, and turn
// spaces into hyphens.
const toSlug = (text) =>
  text
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\p{M}\p{Pc} -]/gu, '')
    .replace(/ /g, '-');

// Headings before the ToC are not listed, but still count toward duplicate
// slugs, so both parts are scanned.
const buildToc = (before, after) => {
  const slugCounts = new Map();
  const items = [];
  const listFrom = before.split('\n').length;
  let fence = null;
  for (const [index, line] of `${before}${after}`.split('\n').entries()) {
    const fenceMatch = line.match(/^\s*(`{3,}|~{3,})/);
    if (fenceMatch) {
      if (!fence) {
        fence = fenceMatch[1];
      } else if (
        fenceMatch[1][0] === fence[0] &&
        fenceMatch[1].length >= fence.length
      ) {
        fence = null;
      }
      continue;
    }
    if (fence) {
      continue;
    }
    const headingMatch = line.match(/^(#{1,6})\s+(.+?)\s*#*\s*$/);
    if (!headingMatch) {
      continue;
    }
    const level = headingMatch[1].length;
    const label = toLabel(headingMatch[2]);
    // Every heading takes up a slug, even when it is not listed.
    const base = toSlug(toText(label));
    const count = slugCounts.get(base) ?? 0;
    slugCounts.set(base, count + 1);
    if (index < listFrom || level < MIN_LEVEL || level > MAX_LEVEL) {
      continue;
    }
    const slug = count ? `${base}-${count}` : base;
    const indent = '  '.repeat(level - MIN_LEVEL);
    items.push(`${indent}- [${label}](#${slug})`);
  }
  return items.join('\n');
};

const updateFile = (path) => {
  const source = readFileSync(path, 'utf8');
  const startIndex = source.indexOf(START);
  if (startIndex === -1) {
    console.warn(`${path}: no "${START}" marker, skipping.`);
    return;
  }
  const contentStart = startIndex + START.length;
  const endIndex = source.indexOf(END, contentStart);
  const before = source.slice(0, contentStart);
  const after =
    endIndex === -1
      ? source.slice(contentStart)
      : source.slice(endIndex + END.length);
  const toc = buildToc(before, after);
  const updated = `${before}\n\n${toc}\n\n${END}${after}`;
  if (updated !== source) {
    writeFileSync(path, updated);
    console.log(`${path}: table of contents updated.`);
  }
};

const files = process.argv.slice(2);
for (const file of files.length ? files : ['README.md']) {
  updateFile(file);
}
