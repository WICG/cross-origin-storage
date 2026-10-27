// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

// Load .env if present — native Node.js 20.12+, no package required.
try { process.loadEnvFile(); } catch {}

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { execSync } from 'child_process';
import { parse } from 'csv-parse/sync';
import { groupRecords, formatHashList } from './shared.js';
import { run as runChromium, OUTPUT_CSV as csvChromium } from './chromium-pervasive.js';
import { run as runCdnjs, OUTPUT_CSV as csvCdnjs } from './cdnjs.js';
import { run as runGoogle, OUTPUT_CSV as csvGoogle } from './google-hosted-libraries.js';
import { run as runGoogleMaps, OUTPUT_CSV as csvGoogleMaps } from './google-maps.js';
import { run as runJsdelivr, OUTPUT_CSV as csvJsdelivr } from './jsdelivr.js';
import { run as runMicrosoft, OUTPUT_CSV as csvMicrosoft } from './microsoft-ajax.js';
import { run as runNpmPopular, OUTPUT_CSV as csvNpmPopular } from './npm-popular.js';
import { run as runYouTube, OUTPUT_CSV as csvYouTube } from './youtube-player.js';
import { run as runGoogleFonts, OUTPUT_CSV as csvGoogleFonts } from './google-fonts.js';
import { run as runHuggingFace, OUTPUT_CSV as csvHuggingFace } from './huggingface.js';
import { run as runHttpArchive, OUTPUT_CSV as csvHttpArchive } from './http-archive.js';
import { run as runNuxtCos, OUTPUT_CSV as csvNuxtCos } from './nuxt-cos.js';
import { run as runManual, OUTPUT_CSV as csvManual } from './manual.js';
import { writeOverlap } from './overlap.js';

const OUTPUT_DAT = 'data/public-hash-list.dat'; // canonical PHL output
const OUTPUT_SHA256 = 'data/public-hash-list.dat.sha256'; // integrity file for the above

// Core (objective, popularity-based) sources and the optional model-hub source.
const CORE_SOURCES = [
  ['google-hosted-libraries', runGoogle, csvGoogle],
  ['microsoft-ajax', runMicrosoft, csvMicrosoft],
  ['cdnjs', runCdnjs, csvCdnjs],
  ['jsdelivr', runJsdelivr, csvJsdelivr],
  ['npm-popular', runNpmPopular, csvNpmPopular],
  ['chromium-pervasive', runChromium, csvChromium],
  ['youtube-player', runYouTube, csvYouTube],
  ['google-maps', runGoogleMaps, csvGoogleMaps],
  ['google-fonts', runGoogleFonts, csvGoogleFonts],
  ['http-archive', runHttpArchive, csvHttpArchive],
  ['nuxt-cos', runNuxtCos, csvNuxtCos],
];
const HUGGING_FACE_SOURCE = ['huggingface', runHuggingFace, csvHuggingFace];
const MANUAL_SOURCE = ['manual', runManual, csvManual];

// A source that comes back empty was skipped (a missing API key, a registry or
// network failure) and has left its CSV from the previous run in place. Read
// that back, so one failed fetch does not drop the source from the list. A
// source that throws is treated the same way, so it cannot abort the others.
async function collect([source, run, csv]) {
  let records;
  try {
    records = await run();
  } catch (err) {
    console.log(`[${source}] FAILED: ${err.message}`);
    records = [];
  }
  if (!records.length && fs.existsSync(csv)) {
    records = parse(fs.readFileSync(csv), { columns: true, skip_empty_lines: true });
    console.log(`[${source}] Keeping ${records.length} records from the previous '${csv}'.`);
  }
  return records.map((r) => ({ ...r, source }));
}

function commitId() {
  try {
    return execSync('git rev-parse --short HEAD').toString().trim();
  } catch {
    return 'uncommitted';
  }
}

async function main() {
  // Each source overwrites its own CSV, so `data/` is kept between runs. Only
  // files no current source writes are removed.
  const sources = [...CORE_SOURCES, HUGGING_FACE_SOURCE, MANUAL_SOURCE];
  const keep = new Set([OUTPUT_DAT, OUTPUT_SHA256, ...sources.map(([, , csv]) => csv)]);
  fs.mkdirSync('data', { recursive: true });
  for (const file of fs.readdirSync('data')) {
    if (!keep.has(`data/${file}`)) fs.rmSync(path.join('data', file), { recursive: true, force: true });
  }

  const coreTagged = (await Promise.all(CORE_SOURCES.map(collect))).flat();
  const hfTagged = await collect(HUGGING_FACE_SOURCE);
  const manualTagged = await collect(MANUAL_SOURCE);

  const core = groupRecords(coreTagged);
  const huggingface = groupRecords(hfTagged);
  const manual = groupRecords(manualTagged);

  const version = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const commit = commitId();

  // Canonical PHL flat file (the sole combined output).
  const datContent = formatHashList({ core, huggingface, manual, version, commit });
  fs.writeFileSync(OUTPUT_DAT, datContent, 'utf8');

  // Integrity file: SHA-256 of the canonical .dat, in standard shasum format.
  const datHash = crypto.createHash('sha256').update(datContent, 'utf8').digest('hex');
  fs.writeFileSync(OUTPUT_SHA256, `${datHash}  ${path.basename(OUTPUT_DAT)}\n`, 'utf8');

  console.log(
    `\nPHL written to '${OUTPUT_DAT}': ${core.length} core entries, ` +
      `${huggingface.length} model-hub entries, ${manual.length} manual entries.`
  );
  console.log(`SHA-256 integrity file written to '${OUTPUT_SHA256}'.`);

  // Overlap summary for the landing page, read back from the CSVs just written.
  writeOverlap();
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
