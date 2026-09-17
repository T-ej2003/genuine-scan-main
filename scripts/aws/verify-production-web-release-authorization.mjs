#!/usr/bin/env node
import fs from "node:fs";
import crypto from "node:crypto";
import { pathToFileURL } from "node:url";
import { verifyProductionReleaseImageAuthorization, createReleaseGateImageAuthorizationRunner } from "./verify-production-release-image-authorization.mjs";
import { createPinnedRootAttestationVerifier } from "./production-root-attestation-key.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { assertCoordinatedImageAuthorization, WEB_RELEASE_DOWNSTREAM_RESERVE_MS } from "./production-web-release-contract.mjs";

const HASH = /^[a-f0-9]{64}$/;
const SHA = /^[a-f0-9]{40}$/;
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

function readBoundJson(file, expectedHash, label) {
  const bytes = fs.readFileSync(file);
  if (!HASH.test(expectedHash || "")) throw new Error(`${label} SHA-256 is malformed.`);
  if (sha256(bytes) !== expectedHash) throw new Error(`${label} bytes do not match their SHA-256.`);
  return JSON.parse(bytes);
}

export async function verifyCoordinatedWebRelease({ sourceSha, stageBAuthorization, webAuthorization, now = new Date().toISOString(), verifyWeb = createPinnedRootAttestationVerifier(), verifyStageBImageEvidence, minimumWebAuthorizationRemainingMs } = {}) {
  if (!SHA.test(sourceSha || "")) throw new Error("Protected source SHA is malformed.");
  verifyProductionReleaseImageAuthorization({ authorization: stageBAuthorization, sourceSha, verifyImageEvidence: verifyStageBImageEvidence, now });
  const impact = stageBAuthorization.imageReuseEvidence;
  return Object.freeze({ ...assertCoordinatedImageAuthorization({ sourceSha, stageBAuthorization, webAuthorization, webPublicationRequired: impact.webPublicationRequired, verifyWeb, now, minimumWebAuthorizationRemainingMs }), imageImpact: impact });
}

function required(argv, name) {
  const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1];
  if (!value || value.startsWith("--") || argv.indexOf(name, index + 1) !== -1) throw new Error(`${name} is required exactly once.`);
  return value;
}

export async function runCli(argv = process.argv.slice(2), deps = {}) {
  const reserveDownstreamLifetime = argv.includes("--reserve-downstream-lifetime");
  if (argv.length !== 14 + (reserveDownstreamLifetime ? 1 : 0) || argv.filter((value) => value === "--reserve-downstream-lifetime").length > 1) throw new Error("Coordinated web release verification accepts exactly seven options and an optional fixed downstream-lifetime reservation.");
  const sourceSha = required(argv, "--source-sha");
  const stageB = readBoundJson(required(argv, "--stage-b-authorization"), required(argv, "--stage-b-authorization-sha256"), "Stage-B authorization");
  const web = readBoundJson(required(argv, "--web-authorization"), required(argv, "--web-authorization-sha256"), "Web authorization");
  const releaseRun = deps.releaseRun || createReleaseGateImageAuthorizationRunner();
  const result = await verifyCoordinatedWebRelease({ sourceSha, stageBAuthorization: stageB, webAuthorization: web, verifyStageBImageEvidence: (options) => verifyImageEvidenceSignature({ ...options, run: releaseRun }), ...deps, minimumWebAuthorizationRemainingMs: reserveDownstreamLifetime ? WEB_RELEASE_DOWNSTREAM_RESERVE_MS : undefined });
  fs.writeFileSync(required(argv, "--output"), `${JSON.stringify(result)}\n`, { mode: 0o600, flag: "wx" });
  return result;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runCli().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
