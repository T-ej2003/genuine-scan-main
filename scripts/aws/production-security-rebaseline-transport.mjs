import assert from "node:assert/strict";
import crypto from "node:crypto";
import { gzipSync, gunzipSync } from "node:zlib";

const CHUNK_BYTES = 128 * 1024;
const MAX_CHUNKS = 64;
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

export function createSecurityCatalogueTransportKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 3072 });
  return Object.freeze({ publicKeyPem: publicKey.export({ type: "spki", format: "pem" }), privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }) });
}

export function encryptSecurityCatalogueTransport(value, publicKeyPem, binding) {
  assert.ok(typeof publicKeyPem === "string" && publicKeyPem.includes("BEGIN PUBLIC KEY"));
  assert.deepEqual(Object.keys(binding || {}).sort(), ["candidateSourceSha", "requirementsSha256", "sourceSha"].sort());
  assert.match(binding.sourceSha || "", /^[a-f0-9]{40}$/); assert.match(binding.candidateSourceSha || "", /^[a-f0-9]{40}$/); assert.match(binding.requirementsSha256 || "", /^[a-f0-9]{64}$/);
  const plaintext = Buffer.from(JSON.stringify(value)); assert.ok(plaintext.length > 0 && plaintext.length <= 4 * 1024 * 1024);
  const compressed = gzipSync(plaintext, { level: 9 }), key = crypto.randomBytes(32), iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv); cipher.setAAD(Buffer.from(JSON.stringify(binding)));
  const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final()]), tag = cipher.getAuthTag();
  const encryptedKey = crypto.publicEncrypt({ key: publicKeyPem, oaepHash: "sha256", padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, key);
  const envelope = { schemaVersion: 1, kind: "PRODUCTION_SECURITY_CATALOGUE_TRANSPORT", binding, plaintextSha256: sha256(plaintext),
    key: encryptedKey.toString("base64"), iv: iv.toString("base64"), tag: tag.toString("base64"), ciphertext: ciphertext.toString("base64") };
  const encoded = Buffer.from(JSON.stringify(envelope)).toString("base64"), count = Math.ceil(encoded.length / CHUNK_BYTES);
  assert.ok(count > 0 && count <= MAX_CHUNKS, "Security catalogue transport exceeds bounded chunk count");
  const transportSha256 = sha256(encoded);
  return Array.from({ length: count }, (_, index) => JSON.stringify({ schemaVersion: 1, kind: "PRODUCTION_SECURITY_CATALOGUE_CHUNK", transportSha256, index, count, data: encoded.slice(index * CHUNK_BYTES, (index + 1) * CHUNK_BYTES) }));
}

export function decryptSecurityCatalogueTransport(messages, privateKeyPem, expectedBinding) {
  assert.ok(Array.isArray(messages) && messages.length > 0 && messages.length <= MAX_CHUNKS);
  const chunks = messages.map((message) => { assert.ok(typeof message === "string" && Buffer.byteLength(message) <= CHUNK_BYTES * 2); const value = JSON.parse(message);
    assert.deepEqual(Object.keys(value).sort(), ["count","data","index","kind","schemaVersion","transportSha256"].sort()); assert.equal(value.schemaVersion, 1); assert.equal(value.kind, "PRODUCTION_SECURITY_CATALOGUE_CHUNK");
    assert.ok(Number.isInteger(value.index) && value.index >= 0); assert.ok(Number.isInteger(value.count) && value.count > 0 && value.count <= MAX_CHUNKS); assert.match(value.transportSha256 || "", /^[a-f0-9]{64}$/); assert.match(value.data || "", /^[A-Za-z0-9+/=]+$/); return value; });
  const count = chunks[0].count, digest = chunks[0].transportSha256; assert.equal(chunks.length, count); assert.ok(chunks.every((chunk) => chunk.count === count && chunk.transportSha256 === digest));
  chunks.sort((a, b) => a.index - b.index); assert.deepEqual(chunks.map(({ index }) => index), Array.from({ length: count }, (_, index) => index));
  const encoded = chunks.map(({ data }) => data).join(""); assert.equal(sha256(encoded), digest); const envelope = JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
  assert.deepEqual(Object.keys(envelope).sort(), ["binding","ciphertext","iv","key","kind","plaintextSha256","schemaVersion","tag"].sort()); assert.equal(envelope.schemaVersion, 1); assert.equal(envelope.kind, "PRODUCTION_SECURITY_CATALOGUE_TRANSPORT"); assert.deepEqual(envelope.binding, expectedBinding); assert.match(envelope.plaintextSha256 || "", /^[a-f0-9]{64}$/);
  const key = crypto.privateDecrypt({ key: privateKeyPem, oaepHash: "sha256", padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, Buffer.from(envelope.key, "base64"));
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "base64")); decipher.setAAD(Buffer.from(JSON.stringify(envelope.binding))); decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
  const plaintext = gunzipSync(Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64")), decipher.final()])); assert.equal(sha256(plaintext), envelope.plaintextSha256); return JSON.parse(plaintext.toString("utf8"));
}
