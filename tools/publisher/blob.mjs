// Deciding a Blob Record's shape (TOON_Network #73; spec §8.2, §11 item 2).
//
// A Blob Record's content carries EXACTLY ONE of `parts` (today's shape) or
// `pages`: an ordered array of `{ txid, sha256, parts }`, each naming ONE
// store upload of its own whose bytes are the JSON array of that page's
// part objects, in exactly `parts`' own shape. A record over roughly 700
// parts (~70 MB at the sandbox's 100 KiB part size) does not fit one TOON
// store data item as `parts`, so it pages instead.
//
// This module is the pure half of publishing a blob: bytes in, a plan out —
// which shape the record gets, the parts either way, and the exact bytes
// every upload (a part, or a page) would carry. It holds no identity and
// touches no network: signing the record and uploading these bytes to a
// real store is the caller's job (the sandbox's
// `infra/sandbox/scripts/publisher`, which IMPORTS this module for the
// decision rather than restating it, or any other deployment), exactly as
// `publish.mjs` in this same directory holds the money for a relay write
// and never the provider's signing key. `blob-cli.mjs` in this directory is
// a thin driver over it, so the choice this module makes can be watched
// from outside — a wire fixture, or another implementation's own reader.

import { createHash } from 'node:crypto';

export const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');
export const digestOf = (bytes) => `sha256:${sha256Hex(bytes)}`;

// The store's free-tier data item ceiling and the sandbox's part size
// (the same as `infra/sandbox/scripts/publisher/blob.mjs`'s, which is what
// actually uploads in the sandbox, planned here — this module only plans). The store
// measures the ceiling on the signed item it receives: for a part or a page
// that is the bytes themselves, wrapped in the store's own ~256-byte
// envelope; for the record it is the SIGNED event, which is what
// `signedRecordBytes` estimates below.
export const DATA_ITEM_MAX_BYTES = 107_520;
export const DATA_ITEM_ENVELOPE_BYTES = 256;
export const DEFAULT_PART_SIZE = 102_400;

/** The largest raw upload `dataItemMax` admits once the store's envelope is added. */
export const maxPartSize = (dataItemMax = DATA_ITEM_MAX_BYTES) => dataItemMax - DATA_ITEM_ENVELOPE_BYTES;

/** `bytes` cut into `partSize` pieces, the last one shorter. An empty blob has no parts. */
export function splitParts(bytes, partSize) {
  const parts = [];
  for (let offset = 0; offset < bytes.length; offset += partSize) {
    parts.push(bytes.subarray(offset, Math.min(offset + partSize, bytes.length)));
  }
  return parts;
}

/**
 * A placeholder part object of `size` bytes, with a real Arweave txid's and
 * a real sha256's LENGTH but not their value — enough to measure how many
 * bytes a real one would take without uploading anything.
 */
const ARWEAVE_TXID_LEN = 43;
const templatePart = (size) => ({ txid: 'T'.repeat(ARWEAVE_TXID_LEN), sha256: 'h'.repeat(64), size });

// A Blob Record's kind (spec §8.2) and the label every toon.network event
// carries: the record is measured as the event it will be, tags and all.
const K_BLOB = 30435;
const TOON_LABEL = 'toon.network';
// Any ten-digit `created_at`: every moment from 2001 to 2286 is ten digits.
const CREATED_AT_PLACEHOLDER = 1_700_000_000;

/**
 * How many bytes the SIGNED record JSON would be, over `parts` (real txids
 * and hashes; only their lengths matter here) — the WHOLE event, measured as
 * the store will receive it: `kind`, `created_at`, the `d`/`x`/`L` tags, and
 * `content` as the escaped JSON string it is inside the event, where every
 * quote of the part list costs two bytes. Measuring the content alone would
 * keep a record inline that the store then refuses.
 */
function signedRecordBytes({ digest, size, partSize, parts }) {
  const content = JSON.stringify({
    digest,
    size,
    part_size: partSize,
    parts: parts.map((p) => templatePart(p.size)),
  });
  const hex = digest.slice('sha256:'.length);
  const unsigned = JSON.stringify({
    kind: K_BLOB,
    created_at: CREATED_AT_PLACEHOLDER,
    tags: [['d', digest], ['x', hex], ['L', TOON_LABEL]],
    content,
  });
  // A signed event is that plus `id` (64 hex), `pubkey` (64 hex) and `sig`
  // (128 hex): the JSON grows by exactly these three fields, however the
  // caller ends up sealing them in (spec §8.2's Blob Record is signed by
  // whoever uploaded the parts — never this tool, which has no key).
  const eventOverhead = JSON.stringify({ id: 'a'.repeat(64), pubkey: 'b'.repeat(64), sig: 'c'.repeat(128) }).length - 1;
  return unsigned.length + eventOverhead;
}

/** How many part objects fit one page's own upload (no event envelope: a page is raw bytes, not a signed event). */
function partsPerPageFor({ partSize, dataItemMax }) {
  const cap = maxPartSize(dataItemMax);
  const perPart = JSON.stringify(templatePart(partSize)).length + 1; // +1 for the array's separating comma
  return Math.max(1, Math.floor((cap - 2) / perPart)); // -2 for the array's own brackets
}

/** A deterministic, storage-free txid: enough to round-trip through a fake store in a test. Real storage supplies the real one. */
const defaultTxidOf = (bytes, kind, index) => `${kind}${index}-${sha256Hex(bytes).slice(0, 32)}`;

/**
 * Plan a Blob Record for `bytes`: `parts` inline when the SIGNED record
 * would fit one store data item, `pages` otherwise (spec §8.2, §11 item 2).
 * The switch point is this tool's own choice, not the protocol's — moved by
 * `dataItemMax` and `partSize`, never by blob size alone.
 *
 * Resolves to
 *   { digest, size, part_size,
 *     parts: [{ txid, sha256, size }] | null,
 *     pages: [{ txid, sha256, parts }] | null,
 *     uploads: [{ kind: 'part' | 'page', txid, bytes: Buffer }] }
 * — `uploads` in the order a real storer would pay for them: every part,
 * then (paged only) every page, each page's bytes the JSON array of the
 * part objects it covers, in exactly `parts`' own shape.
 *
 * `txidOf(bytes, kind, index)` names each upload; a caller with a real
 * store supplies the real txid it got back from uploading `bytes` FIRST,
 * then re-plans with it (a part's own hash and size do not depend on
 * where it landed). Left at its default, this function touches no network
 * and is fully deterministic — which is what lets `blob.test.mjs` cover
 * both shapes with no store at all.
 */
export function planBlobRecord({
  bytes,
  partSize = DEFAULT_PART_SIZE,
  dataItemMax = DATA_ITEM_MAX_BYTES,
  partsPerPage,
  txidOf = defaultTxidOf,
}) {
  if (!Number.isInteger(partSize) || partSize <= 0) {
    throw new Error(`part size must be a positive integer, got ${partSize}`);
  }
  const digestHex = sha256Hex(bytes);
  const digest = `sha256:${digestHex}`;
  const size = bytes.length;
  const pieces = splitParts(bytes, partSize);
  const parts = pieces.map((piece, i) => ({
    txid: txidOf(piece, 'part', i),
    sha256: sha256Hex(piece),
    size: piece.length,
  }));
  const partUploads = parts.map((p, i) => ({ kind: 'part', txid: p.txid, bytes: pieces[i] }));

  if (signedRecordBytes({ digest, size, partSize, parts }) <= dataItemMax) {
    return { digest, size, part_size: partSize, parts, pages: null, uploads: partUploads };
  }

  const perPage = partsPerPage ?? partsPerPageFor({ partSize, dataItemMax });
  const groups = [];
  for (let i = 0; i < parts.length; i += perPage) groups.push(parts.slice(i, i + perPage));
  const pageBytes = groups.map((group) => Buffer.from(JSON.stringify(group), 'utf8'));
  const pages = pageBytes.map((buf, i) => ({
    txid: txidOf(buf, 'page', i),
    sha256: sha256Hex(buf),
    parts: groups[i].length,
  }));
  const pageUploads = pages.map((page, i) => ({ kind: 'page', txid: page.txid, bytes: pageBytes[i] }));

  return {
    digest,
    size,
    part_size: partSize,
    parts: null,
    pages,
    uploads: [...partUploads, ...pageUploads],
  };
}
