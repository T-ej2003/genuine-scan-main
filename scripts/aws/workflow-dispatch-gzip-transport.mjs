import crypto from "node:crypto";
import { constants as zlibConstants, gunzipSync, gzipSync, inflateRawSync } from "node:zlib";

export const WORKFLOW_DISPATCH_PLATFORM_LIMIT = 65_535;
export const WORKFLOW_DISPATCH_INTERNAL_BUDGET = 60_000;
export const MAX_DECOMPRESSED_WORKFLOW_DISPATCH_BYTES = WORKFLOW_DISPATCH_INTERNAL_BUDGET;
export const MAX_ENCODED_WORKFLOW_DISPATCH_CHARACTERS = WORKFLOW_DISPATCH_INTERNAL_BUDGET;

const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

function deterministicGzip(bytes) {
  const compressed = gzipSync(bytes, { level: 9, strategy: zlibConstants.Z_DEFAULT_STRATEGY, windowBits: 15, memLevel: 8, mtime: 0 });
  compressed.fill(0, 4, 8);
  compressed[9] = 255;
  return compressed;
}

function gzipDeflateOffset(compressed, label) {
  if (compressed.length < 18 || compressed[0] !== 0x1f || compressed[1] !== 0x8b || compressed[2] !== 8 || (compressed[3] & 0xe0) !== 0) throw new Error(`${label} gzip framing is invalid.`);
  const flags = compressed[3]; let offset = 10;
  if (flags & 0x04) {
    if (offset + 2 > compressed.length) throw new Error(`${label} gzip framing is invalid.`);
    const extraLength = compressed.readUInt16LE(offset); offset += 2;
    if (offset + extraLength > compressed.length) throw new Error(`${label} gzip framing is invalid.`);
    offset += extraLength;
  }
  for (const flag of [0x08, 0x10]) if (flags & flag) {
    const end = compressed.indexOf(0, offset);
    if (end === -1) throw new Error(`${label} gzip framing is invalid.`);
    offset = end + 1;
  }
  if (flags & 0x02) offset += 2;
  if (offset + 8 >= compressed.length) throw new Error(`${label} gzip framing is invalid.`);
  return offset;
}

export function encodeWorkflowDispatchGzip(bytes, { label = "Workflow dispatch artifact", maxDecompressedBytes = MAX_DECOMPRESSED_WORKFLOW_DISPATCH_BYTES } = {}) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > maxDecompressedBytes) throw new Error(`${label} exceeds the ${maxDecompressedBytes}-byte decompressed limit.`);
  return deterministicGzip(bytes).toString("base64");
}

export function decodeWorkflowDispatchGzip(encoded, expectedSha256, { label = "Workflow dispatch artifact", maxDecompressedBytes = MAX_DECOMPRESSED_WORKFLOW_DISPATCH_BYTES, maxEncodedCharacters = MAX_ENCODED_WORKFLOW_DISPATCH_CHARACTERS } = {}) {
  if (typeof encoded !== "string" || encoded.length === 0 || encoded.length > maxEncodedCharacters || !CANONICAL_BASE64.test(encoded)) throw new Error(`${label} transport is not canonical base64.`);
  const compressed = Buffer.from(encoded, "base64");
  if (compressed.toString("base64") !== encoded) throw new Error(`${label} transport is not canonical base64.`);
  let bytes;
  try {
    const deflateOffset = gzipDeflateOffset(compressed, label);
    const deflateBytes = inflateRawSync(compressed.subarray(deflateOffset), { info: true, maxOutputLength: maxDecompressedBytes }).engine.bytesWritten;
    if (deflateOffset + deflateBytes + 8 !== compressed.length) throw new Error(`${label} transport must contain exactly one gzip member without trailing data.`);
    bytes = gunzipSync(compressed, { maxOutputLength: maxDecompressedBytes });
  } catch {
    throw new Error(`${label} transport is invalid or exceeds the decompressed limit.`);
  }
  if (!bytes.length || bytes.length > maxDecompressedBytes) throw new Error(`${label} transport is invalid or exceeds the decompressed limit.`);
  if (!/^[a-f0-9]{64}$/.test(expectedSha256 || "") || sha256(bytes) !== expectedSha256) throw new Error(`${label} bytes do not match their SHA-256.`);
  return bytes;
}

export function measureWorkflowDispatchInputs(inputs, { label = "Workflow dispatch payload", internalBudget = WORKFLOW_DISPATCH_INTERNAL_BUDGET } = {}) {
  const serialized = JSON.stringify(inputs);
  const characters = Array.from(serialized).length; const bytes = Buffer.byteLength(serialized);
  if (characters > internalBudget || bytes > internalBudget || characters > WORKFLOW_DISPATCH_PLATFORM_LIMIT || bytes > WORKFLOW_DISPATCH_PLATFORM_LIMIT) throw new Error(`${label} exceeds the ${internalBudget}-character internal budget.`);
  return Object.freeze({ characters, bytes, serialized });
}
