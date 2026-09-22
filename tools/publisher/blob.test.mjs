// `blob.mjs`'s paging decision (TOON_Network #73; spec §8.2, §11 item 2):
// inline below its threshold, pages above it, and either way the parts
// reassemble to the original bytes. `node --test` (no network, no store).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { planBlobRecord, splitParts, sha256Hex, digestOf } from './blob.mjs';

function bytesOf(text, times = 1) {
  return Buffer.from(text.repeat(times), 'utf8');
}

function partsFromUploads(uploads) {
  const pages = uploads.filter((u) => u.kind === 'page');
  if (pages.length === 0) return null;
  return pages.flatMap((page) => JSON.parse(page.bytes.toString('utf8')));
}

test('a small blob stays inline, below the threshold', () => {
  const bytes = bytesOf('hello world ', 10);
  const plan = planBlobRecord({ bytes, partSize: 16, dataItemMax: 100_000 });

  assert.ok(plan.parts, 'inline: parts is present');
  assert.equal(plan.pages, null, 'inline: pages is absent');
  assert.equal(plan.digest, digestOf(bytes));
  assert.equal(plan.size, bytes.length);
  assert.equal(
    plan.parts.length,
    splitParts(bytes, 16).length,
    'the same split a reader would check part_size against',
  );

  // The uploads reassemble to the original bytes, part by part, in order.
  const rebuilt = Buffer.concat(plan.uploads.filter((u) => u.kind === 'part').map((u) => u.bytes));
  assert.deepEqual(rebuilt, bytes);
});

test('a large blob pages, above a tight threshold', () => {
  const bytes = bytesOf('x', 5000);
  const plan = planBlobRecord({ bytes, partSize: 8, dataItemMax: 300 });

  assert.equal(plan.parts, null, 'paged: parts is absent');
  assert.ok(plan.pages, 'paged: pages is present');
  assert.ok(plan.pages.length > 1, 'more than one page, so page order is really exercised');

  // Every page's own digest matches the bytes it uploads, and its `parts`
  // count matches what parsing that upload actually finds — exactly what a
  // reader checks before trusting a part from it (spec §8.2).
  const pageUploads = plan.uploads.filter((u) => u.kind === 'page');
  assert.equal(pageUploads.length, plan.pages.length);
  for (const [i, page] of plan.pages.entries()) {
    assert.equal(page.sha256, sha256Hex(pageUploads[i].bytes));
    const parsed = JSON.parse(pageUploads[i].bytes.toString('utf8'));
    assert.equal(page.parts, parsed.length);
  }

  // Concatenating every page's own part list, in page order, gives EXACTLY
  // the ordered part list an inline record over the same bytes would have
  // listed — pages change nothing about the parts themselves.
  const inline = planBlobRecord({ bytes, partSize: 8, dataItemMax: 1_000_000 });
  assert.ok(inline.parts, 'the comparison inline plan really is inline');
  assert.deepEqual(partsFromUploads(plan.uploads), inline.parts);
});

test('both shapes name the same digest, size and part_size for the same bytes', () => {
  const bytes = bytesOf('same bytes, different threshold ', 50);
  const inline = planBlobRecord({ bytes, partSize: 37, dataItemMax: 1_000_000 });
  const paged = planBlobRecord({ bytes, partSize: 37, dataItemMax: 300 });

  assert.equal(inline.digest, paged.digest);
  assert.equal(inline.size, paged.size);
  assert.equal(inline.part_size, paged.part_size);
  assert.ok(inline.parts && !inline.pages);
  assert.ok(paged.pages && !paged.parts);
});

test('every part, whichever shape lists it, reassembles to the exact original bytes', () => {
  const bytes = Buffer.from(Array.from({ length: 5000 }, (_, i) => i % 251));
  for (const dataItemMax of [1_000_000, 300]) {
    const plan = planBlobRecord({ bytes, partSize: 37, dataItemMax });
    const parts = plan.parts ?? partsFromUploads(plan.uploads);
    const byTxid = new Map(plan.uploads.filter((u) => u.kind === 'part').map((u) => [u.txid, u.bytes]));
    const rebuilt = Buffer.concat(parts.map((p) => byTxid.get(p.txid)));
    assert.deepEqual(rebuilt, bytes, `dataItemMax=${dataItemMax}`);
    assert.equal(`sha256:${sha256Hex(rebuilt)}`, plan.digest, `dataItemMax=${dataItemMax}`);
  }
});

test('an empty blob stays inline with no parts at all', () => {
  const plan = planBlobRecord({ bytes: Buffer.alloc(0), partSize: 16 });
  assert.deepEqual(plan.parts, []);
  assert.equal(plan.pages, null);
  assert.equal(plan.size, 0);
});

test('a non-positive part size is refused', () => {
  assert.throws(() => planBlobRecord({ bytes: bytesOf('x'), partSize: 0 }), /positive integer/);
  assert.throws(() => planBlobRecord({ bytes: bytesOf('x'), partSize: -1 }), /positive integer/);
});

test('the threshold is the SIGNED event: at the sandbox part size 689 parts stay inline and the 690th pages', () => {
  // The same boundary infra/sandbox/scripts/publisher/blob.mjs measures on
  // the whole signed event — tags, `created_at`, and the part list escaped
  // inside `content`. Measured on the content alone, a record of ~780 parts
  // would stay inline and be refused by the store it was planned for.
  const partSize = 102_400;
  const at = (n) => planBlobRecord({ bytes: Buffer.alloc(n * partSize), partSize });
  assert.ok(at(689).parts, '689 parts fit one data item inline');
  assert.ok(at(690).pages, '690 parts do not, and page');
});
