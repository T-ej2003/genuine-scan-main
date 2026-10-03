#!/usr/bin/env node
import crypto from "node:crypto";
import { readHistoricalRuntimeTransport } from "./verify-production-historical-runtime-handoff.mjs";
import { authenticateHistoricalRuntimeEvidence } from "./production-historical-runtime-evidence.mjs";
import fs from "node:fs";
import { pathToFileURL } from "node:url";
import { IMAGE_AUTHORIZATION_SCHEMA_VERSION, imageAuthorizationSha256 } from "./production-image-authorization.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";

const SHA = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;

// Existing release transport carries two independently authenticated proofs.
// Wrapping changes only the transport checksum, never either signed artifact.
export function packReleaseEvidenceTransport({ authorizationJson, authorizationSha256, historicalRuntimeJson, historicalRuntimeSha256 }) {
  if (!historicalRuntimeJson && !historicalRuntimeSha256) return { json: authorizationJson, sha256: authorizationSha256 };
  readHistoricalRuntimeTransport({ bytes: Buffer.from(historicalRuntimeJson || ""), expectedSha256: historicalRuntimeSha256 });
  if (crypto.createHash("sha256").update(authorizationJson).digest("hex") !== authorizationSha256) throw new Error("Image transport checksum changed");
  const json = JSON.stringify({ schemaVersion: 1, imageAuthorizationJson: authorizationJson, imageAuthorizationSha256: authorizationSha256, historicalRuntimeJson, historicalRuntimeSha256 });
  return { json, sha256: crypto.createHash("sha256").update(json).digest("hex") };
}

export function unpackReleaseEvidenceTransport({ json, sha256 }) {
  if (crypto.createHash("sha256").update(json).digest("hex") !== sha256) throw new Error("Release transport checksum changed");
  const value = JSON.parse(json);
  if (!Object.hasOwn(value, "imageAuthorizationJson")) return { authorizationJson: json, authorizationSha256: sha256 };
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(["historicalRuntimeJson", "historicalRuntimeSha256", "imageAuthorizationJson", "imageAuthorizationSha256", "schemaVersion"])) throw new Error("Release transport envelope malformed");
  if (value.schemaVersion !== 1) throw new Error("Release transport schema invalid");
  packReleaseEvidenceTransport({ authorizationJson: value.imageAuthorizationJson, authorizationSha256: value.imageAuthorizationSha256, historicalRuntimeJson: value.historicalRuntimeJson, historicalRuntimeSha256: value.historicalRuntimeSha256 });
  return { authorizationJson: value.imageAuthorizationJson, authorizationSha256: value.imageAuthorizationSha256, historicalRuntimeJson: value.historicalRuntimeJson, historicalRuntimeSha256: value.historicalRuntimeSha256 };
}

function parseBoundWebAuthorization({ sourceSha, authorizationBytes, expectedSha256, required }) {
  if (!required && authorizationBytes === undefined && expectedSha256 === undefined) return undefined;
  if (!Buffer.isBuffer(authorizationBytes) || !SHA256.test(expectedSha256 || "") || crypto.createHash("sha256").update(authorizationBytes).digest("hex") !== expectedSha256) throw new Error("Web image-authorization transport is malformed or hash-mismatched.");
  const value = JSON.parse(authorizationBytes);
  if (value?.operation !== "PRODUCTION_WEB_IMAGE_AUTHORIZATION" || value.valid !== true || value.sourceSha !== sourceSha) throw new Error("Web image authorization is stale or not source-bound.");
  return value;
}

export function assertNormalReleaseAuthorizationTransport({ sourceSha, authorizationBytes, expectedSha256, webAuthorizationBytes, webExpectedSha256, webPublicationRequired = false } = {}) {
  if (!SHA.test(sourceSha || "") || !Buffer.isBuffer(authorizationBytes) || !SHA256.test(expectedSha256 || "") || crypto.createHash("sha256").update(authorizationBytes).digest("hex") !== expectedSha256) throw new Error("Normal release image-authorization transport is malformed or hash-mismatched.");
  const authorization = JSON.parse(authorizationBytes);
  if (authorization?.schemaVersion !== IMAGE_AUTHORIZATION_SCHEMA_VERSION || authorization.valid !== true || authorization.sourceSha !== sourceSha || authorization.authorizationSha256 !== authorization.evidenceSha256 || authorization.authorizationSha256 !== imageAuthorizationSha256(authorization) || authorization.imageReuseEvidence?.toolingSha !== sourceSha || authorization.imageReuseEvidenceSha256 !== canonicalSha256(authorization.imageReuseEvidence) || authorization.imageReuseEvidence.webPublicationRequired !== webPublicationRequired) throw new Error("Normal release image authorization is stale or not a canonical source-bound envelope.");
  const web = parseBoundWebAuthorization({ sourceSha, authorizationBytes: webAuthorizationBytes, expectedSha256: webExpectedSha256, required: webPublicationRequired });
  if (webPublicationRequired && !web) throw new Error("Web-impacting release requires web image authorization transport.");
  return Object.freeze({ sourceSha, transportSha256: expectedSha256, webTransportSha256: webExpectedSha256, webPublicationRequired, authenticationDeferredToReleaseGate: true });
}

export function assertNormalReleaseGateInputs({ sourceSha, preserveCurrentFrontend, authorizationBytes, expectedSha256, webAuthorizationBytes, webExpectedSha256, webPublicationRequired = false, authenticateAuthorization, authenticateWebAuthorization } = {}) {
  assertNormalReleaseAuthorizationTransport({ sourceSha, authorizationBytes, expectedSha256, webAuthorizationBytes, webExpectedSha256, webPublicationRequired });
  if (preserveCurrentFrontend !== !webPublicationRequired) throw new Error("Normal release frontend action does not match canonical web impact.");
  const authorization = JSON.parse(authorizationBytes);
  if (typeof authenticateAuthorization !== "function" || authenticateAuthorization(authorization, sourceSha) !== true) throw new Error("Normal release image authorization was not authenticated by the canonical verifier.");
  if (webPublicationRequired && (typeof authenticateWebAuthorization !== "function" || authenticateWebAuthorization(JSON.parse(webAuthorizationBytes), sourceSha) !== true)) throw new Error("Web image authorization was not authenticated by the canonical verifier.");
  return true;
}

function required(argv, name) {
  const index = argv.indexOf(name);
  const value = index < 0 ? undefined : argv[index + 1];
  if (!value || value.startsWith("--") || argv.indexOf(name, index + 1) !== -1) throw new Error(`${name} is required exactly once.`);
  return value;
}

export function runCli(argv = process.argv.slice(2)) {
  if (![6, 8, 10, 12].includes(argv.length)) throw new Error("Normal release dispatch contract accepts three Stage-B options and an optional web authorization file.");
  const allowed = new Set(["--source-sha", "--authorization", "--authorization-sha256", "--web-authorization", "--historical-runtime-evidence", "--historical-runtime-evidence-sha256"]);
  for (let i = 0; i < argv.length; i += 2) if (!allowed.has(argv[i])) throw new Error("Unknown release transport option");
  const sourceSha = required(argv, "--source-sha");
  if (argv.includes("--historical-runtime-evidence") || argv.includes("--historical-runtime-evidence-sha256")) {
    const evidence = readHistoricalRuntimeTransport({ bytes: fs.readFileSync(required(argv, "--historical-runtime-evidence")), expectedSha256: required(argv, "--historical-runtime-evidence-sha256") });
    // Retained authority may originate in an older release. Gate independently
    // requires that exact proof already persisted, or a fresh current-source grant.
    authenticateHistoricalRuntimeEvidence({ evidence, retained: true });
  } const authorizationBytes = fs.readFileSync(required(argv, "--authorization")); const authorization = JSON.parse(authorizationBytes);
  const webAuthorizationBytes = argv.includes("--web-authorization") ? fs.readFileSync(required(argv, "--web-authorization")) : undefined;
  return assertNormalReleaseAuthorizationTransport({ sourceSha, authorizationBytes, expectedSha256: required(argv, "--authorization-sha256"), webPublicationRequired: authorization.imageReuseEvidence?.webPublicationRequired, ...(webAuthorizationBytes ? { webAuthorizationBytes, webExpectedSha256: crypto.createHash("sha256").update(webAuthorizationBytes).digest("hex") } : {}) });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  try { process.stdout.write(`${JSON.stringify(runCli())}\n`); }
  catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
