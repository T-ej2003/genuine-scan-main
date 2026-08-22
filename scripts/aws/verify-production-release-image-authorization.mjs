#!/usr/bin/env node
import fs from "node:fs";
import { pathToFileURL } from "node:url";
import { assertImageAuthorization } from "./production-cutover-control-plane.mjs";
import { readBoundStageBPrivateJson } from "./stage-b-artifact-contract.mjs";

const repositories = { backend: "mscqr-backend", worker: "mscqr-worker", "rls-executor": "mscqr-backend", "rls-canary": "mscqr-backend" };

export function verifyProductionReleaseImageAuthorization({ authorization, sourceSha, verifyImageEvidence, now } = {}) {
  assertImageAuthorization(authorization, sourceSha, { verifyImageEvidence, now });
  return Object.freeze(Object.fromEntries(authorization.images.map(({ service, digest }) => [service, `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repositories[service]}@${digest}`])));
}

export function runCli(argv = process.argv.slice(2)) {
  const args = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    if (!new Set(["--source-sha", "--authorization", "--authorization-sha256", "--github-output"]).has(key) || !value || value.startsWith("--") || args.has(key)) throw new Error(`Invalid or duplicate argument: ${key || "<missing>"}`);
    args.set(key, value);
  }
  const required = (name) => { const value = args.get(name); if (!value) throw new Error(`${name} is required.`); return value; };
  const authorization = readBoundStageBPrivateJson({ filePath: required("--authorization"), expectedSha256: required("--authorization-sha256"), label: "Normal release image authorization" });
  const refs = verifyProductionReleaseImageAuthorization({ authorization, sourceSha: required("--source-sha") });
  fs.appendFileSync(required("--github-output"), Object.entries(refs).map(([service, ref]) => `${service.replaceAll("-", "_")}_image_ref=${ref}\n`).join(""));
  return refs;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runCli();
