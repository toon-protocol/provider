#!/usr/bin/env node
// A thin driver over `blob.mjs`'s `planBlobRecord`, so the paging decision
// (TOON_Network #73; spec §8.2, §11 item 2) can be watched from OUTSIDE this
// process — a wire fixture, or another implementation's reader run as a
// subprocess against it (the pattern `tests/gateway_handover.rs` already
// uses for `tools/grant/seal.mjs`).
//
//   node blob-cli.mjs plan <file> [--part-size N] [--data-item-max N] [--parts-per-page N]
//
// Prints one JSON plan on stdout: `digest`, `size`, `part_size`, `parts` or
// `pages` (exactly one is non-null), and `uploads` — every part, then (paged
// only) every page, each carrying `bytes_hex` since JSON has no byte type.
// Nothing is uploaded or signed: see `blob.mjs`'s own doc comment for why.

import { readFileSync } from 'node:fs';
import { planBlobRecord } from './blob.mjs';

function usage(message) {
  if (message) console.error(`blob-cli.mjs: ${message}`);
  console.error(
    'usage: node blob-cli.mjs plan <file> [--part-size N] [--data-item-max N] [--parts-per-page N]',
  );
  process.exit(2);
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const key = arg
        .slice(2)
        .replace(/-([a-z])/g, (_, c) => c.toUpperCase());
      const value = argv[i + 1];
      if (value === undefined) usage(`--${arg.slice(2)} needs a value`);
      args[key] = value;
      i += 1;
    } else {
      args._.push(arg);
    }
  }
  return args;
}

function numberOrUndefined(value) {
  if (value === undefined) return undefined;
  const n = Number(value);
  if (!Number.isFinite(n)) usage(`not a number: ${value}`);
  return n;
}

function main() {
  const [command, ...rest] = process.argv.slice(2);
  if (command !== 'plan') usage(command ? `unknown command ${command}` : 'a command is required');
  const args = parseArgs(rest);
  const file = args._[0];
  if (!file) usage('a file to plan is required');

  const bytes = readFileSync(file);
  const plan = planBlobRecord({
    bytes,
    partSize: numberOrUndefined(args.partSize),
    dataItemMax: numberOrUndefined(args.dataItemMax),
    partsPerPage: numberOrUndefined(args.partsPerPage),
  });

  process.stdout.write(
    JSON.stringify({
      ...plan,
      uploads: plan.uploads.map((upload) => ({
        kind: upload.kind,
        txid: upload.txid,
        bytes_hex: upload.bytes.toString('hex'),
      })),
    }),
  );
}

main();
