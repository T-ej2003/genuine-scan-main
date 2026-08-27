#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import { pathToFileURL } from "node:url";
import { IMAGE_AUTHORIZATION_SCHEMA_VERSION } from "./production-image-authorization.mjs";

const SHA = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;

export function assertNormalReleaseAuthorizationTransport({ sourceSha, authorizationBytes, expectedSha256 } = {}) {
  if (!SHA.test(sourceSha || "") || !Buffer.isBuffer(authorizationBytes) || !SHA256.test(expectedSha256 || "") || crypto.createHash("sha256").update(authorizationBytes).digest("hex") !== expectedSha256) throw new Error("Normal release image-authorization transport is malformed or hash-mismatched.");
  const authorization = JSON.parse(authorizationBytes);
  if (authorization?.schemaVersion !== IMAGE_AUTHORIZATION_SCHEMA_VERSION || authorization.valid !== true || authorization.sourceSha !== sourceSha || authorization.authorizationSha256 !== authorization.evidenceSha256) throw new Error("Normal release image authorization is stale or not a canonical source-bound envelope.");
  return Object.freeze({ sourceSha, transportSha256: expectedSha256, authenticationDeferredToReleaseGate: true });
}

export function assertNormalReleaseGateInputs({ sourceSha, preserveCurrentFrontend, authorizationBytes, expectedSha256, authenticateAuthorization } = {}) {
  assertNormalReleaseAuthorizationTransport({ sourceSha, authorizationBytes, expectedSha256 });
  if (preserveCurrentFrontend !== true) throw new Error("Normal release must explicitly preserve the reviewed production frontend.");
  const authorization = JSON.parse(authorizationBytes);
  if (typeof authenticateAuthorization !== "function" || authenticateAuthorization(authorization, sourceSha) !== true) throw new Error("Normal release image authorization was not authenticated by the canonical verifier.");
  return true;
}

function required(argv, name) {
  const index = argv.indexOf(name);
  const value = index < 0 ? undefined : argv[index + 1];
  if (!value || value.startsWith("--") || argv.indexOf(name, index + 1) !== -1) throw new Error(`${name} is required exactly once.`);
  return value;
}

export function runCli(argv = process.argv.slice(2)) {
  if (argv.length !== 6) throw new Error("Normal release dispatch contract accepts exactly three options.");
  return assertNormalReleaseAuthorizationTransport({ sourceSha: required(argv, "--source-sha"), authorizationBytes: fs.readFileSync(required(argv, "--authorization")), expectedSha256: required(argv, "--authorization-sha256") });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  try { process.stdout.write(`${JSON.stringify(runCli())}\n`); }
  catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
