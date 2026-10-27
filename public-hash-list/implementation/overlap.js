// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

// Overlap summary for the landing page (index.html).
//
// Scans every `data/*.csv` with a `sha256` column, so a new source shows up on
// the page as soon as its CSV lands in `data/`, with no change here. Each
// digest is assigned the set of sources that vouch for it, and digests with
// the same set are counted together. Those exclusive regions are all the page
// needs: the size of any intersection of any selection of sources is the sum
// of the regions that contain it.
//
// The CSVs are stored with Git LFS, which GitHub Pages serves as pointer files,
// so the page cannot read them directly. `overlap.json` lives outside `data/`
// for the same reason.

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { sourceLabel } from './shared.js';

const DATA_DIR = 'data';
export const OUTPUT_JSON = 'overlap.json';
const SHA256 = /^[0-9a-f]{64}$/;

// The digest never needs CSV unquoting, but the URL can (see `csvField()`).
function parseUrl(field) {
  return field.startsWith('"') ? field.slice(1, -1).replaceAll('""', '"') : field;
}

function readSource(file) {
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  if (!lines[0].startsWith('sha256,')) return null;
  const rows = [];
  for (const line of lines.slice(1)) {
    const sha256 = line.slice(0, 64);
    if (SHA256.test(sha256)) rows.push([sha256, parseUrl(line.slice(65))]);
  }
  return rows;
}

export function writeOverlap() {
  const files = fs
    .readdirSync(DATA_DIR)
    .filter((f) => f.endsWith('.csv'))
    .sort();

  const sources = [];
  const byHash = new Map(); // sha256 → { set: number[], url }
  for (const file of files) {
    const rows = readSource(path.join(DATA_DIR, file));
    if (!rows) continue;
    const key = file.replace(/(-hashes)?\.csv$/, '');
    const index = sources.length;
    const seen = new Set();
    for (const [sha256, url] of rows) {
      if (seen.has(sha256)) continue;
      seen.add(sha256);
      let entry = byHash.get(sha256);
      if (!entry) {
        entry = { set: [], url };
        byHash.set(sha256, entry);
      } else if (url.length < entry.url.length) {
        entry.url = url;
      }
      entry.set.push(index);
    }
    sources.push({ key, label: sourceLabel(key), size: seen.size });
  }

  // Keep the shortest URL of each region as an example, the same rule the PHL
  // uses for its representative URL.
  const regions = new Map();
  for (const { set, url } of byHash.values()) {
    const id = set.join(',');
    const region = regions.get(id);
    if (!region) regions.set(id, { sets: set, size: 1, example: url });
    else {
      region.size++;
      if (url.length < region.example.length) region.example = url;
    }
  }

  const summary = {
    generated: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
    total: byHash.size,
    sources,
    regions: [...regions.values()].sort((a, b) => b.size - a.size),
  };
  fs.writeFileSync(OUTPUT_JSON, JSON.stringify(summary) + '\n', 'utf8');
  console.log(
    `Overlap of ${sources.length} sources (${byHash.size} distinct digests, ` +
      `${regions.size} regions) written to '${OUTPUT_JSON}'.`
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) writeOverlap();
