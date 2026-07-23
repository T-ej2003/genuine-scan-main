const assert = require("node:assert/strict");
const test = require("node:test");

const { visitQrCodePages } = require("../dist/rls-waves/session-c/c01/qrSystemRepository");

test("QR export pagination returns every row in stable page order", async () => {
  const source = Array.from({ length: 25_001 }, (_, id) => ({ id }));
  const offsets = [];
  const exported = [];
  const total = await visitQrCodePages(async (limit, offset) => {
    offsets.push(offset);
    return { qrCodes: source.slice(offset, offset + limit), total: source.length };
  },(rows)=>exported.push(...rows),10_000);
  assert.deepEqual(offsets, [0, 10_000, 20_000]);
  assert.equal(total,source.length);
  assert.deepEqual(exported, source);
  assert.equal(new Set(exported.map(({ id }) => id)).size, source.length);
});

test("QR export pagination crosses the former 500,000-row ceiling", async () => {
  const total = 500_001;
  let exported=0;
  const result = await visitQrCodePages(async (limit, offset) => ({
    qrCodes: Array.from({ length: Math.min(limit, total - offset) }, (_, index) => offset + index),
    total,
  }),(rows)=>{exported+=rows.length;},100_000);
  assert.equal(result,total);
  assert.equal(exported,total);
});

test("QR export pagination rejects an incomplete successful-looking result", async () => {
  await assert.rejects(
    visitQrCodePages(async (_limit, offset) => ({
      qrCodes: offset === 0 ? [1, 2] : [],
      total: 3,
    }),()=>{},2),
    /QR_EXPORT_INCOMPLETE/
  );
});
