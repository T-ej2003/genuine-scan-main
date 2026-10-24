const assert = require('node:assert/strict');
const http = require('node:http');
const { gzipSync } = require('node:zlib');
const express = require('express');
const { z } = require('zod');

async function main() {
  const oversized = z.array(z.string().uuid()).max(2000).safeParse(Array(5000).fill('invalid'));
  assert.equal(oversized.success, false);
  assert.deepEqual(oversized.error.issues.map(({ code }) => code), ['too_big']);

  const app = express();
  app.use(express.json({ limit: '1mb' }));
  app.post('/', (_req, res) => res.json({ ok: true }));
  app.use((_error, _req, res, _next) => res.status(400).end());
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const request = (body, headers = {}) => new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: server.address().port, path: '/', method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': body.length, ...headers }, timeout: 3000 }, (res) => {
      res.resume(); res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject); req.on('timeout', () => req.destroy(new Error('request timeout'))); req.end(body);
  });
  try {
    const compressed = Buffer.concat([gzipSync(Buffer.from('{"ok":true}')), Buffer.from('trailing-invalid-bytes')]);
    assert.ok([200, 400].includes(await request(compressed, { 'content-encoding': 'gzip' })));
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(await request(Buffer.from('{"ok":true}')), 200, 'Malformed compressed body terminated the server');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
  console.log('patched request parsers remain bounded and available');
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
