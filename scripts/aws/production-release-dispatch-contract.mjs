#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import { pathToFileURL } from "node:url";
import { IMAGE_AUTHORIZATION_SCHEMA_VERSION } from "./production-image-authorization.mjs";
import { deriveStageBImageImpactReport } from "./validate-stage-b-image-reuse.mjs";

const SHA = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;

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
  if (authorization?.schemaVersion !== IMAGE_AUTHORIZATION_SCHEMA_VERSION || authorization.valid !== true || authorization.sourceSha !== sourceSha || authorization.authorizationSha256 !== authorization.evidenceSha256) throw new Error("Normal release image authorization is stale or not a canonical source-bound envelope.");
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
  if (![6, 8].includes(argv.length)) throw new Error("Normal release dispatch contract accepts three Stage-B options and an optional web authorization file.");
  const sourceSha = required(argv, "--source-sha"); const authorizationBytes = fs.readFileSync(required(argv, "--authorization")); const authorization = JSON.parse(authorizationBytes);
  const impact = deriveStageBImageImpactReport({ imageReleaseSha: authorization.imageReleaseSha, toolingSha: sourceSha });
  const webAuthorizationBytes = argv.includes("--web-authorization") ? fs.readFileSync(required(argv, "--web-authorization")) : undefined;
  return assertNormalReleaseAuthorizationTransport({ sourceSha, authorizationBytes, expectedSha256: required(argv, "--authorization-sha256"), webPublicationRequired: impact.webPublicationRequired, ...(webAuthorizationBytes ? { webAuthorizationBytes, webExpectedSha256: crypto.createHash("sha256").update(webAuthorizationBytes).digest("hex") } : {}) });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  try { process.stdout.write(`${JSON.stringify(runCli())}\n`); }
  catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
