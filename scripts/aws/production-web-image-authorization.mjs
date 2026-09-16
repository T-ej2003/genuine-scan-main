#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { buildWebImageAuthorization } from "./production-web-release-contract.mjs";
import { createPinnedRootAttestationVerifier } from "./production-root-attestation-key.mjs";

const SHA = /^[a-f0-9]{40}$/;
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--") || argv.indexOf(name, index + 1) !== -1) throw new Error(`${name} is required exactly once.`); return value; };
const readJson = (file, label) => { try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch (error) { throw new Error(`${label} is invalid: ${error.message}`); } };

export function assertFreshProtectedSource(sourceSha, { cwd = process.cwd(), git = execFileSync } = {}) {
  if (!SHA.test(sourceSha || "")) throw new Error("Protected source SHA is malformed.");
  const read = (args) => git("git", args, { cwd, encoding: "utf8" }).trim();
  if (read(["rev-parse", "HEAD"]) !== sourceSha || read(["rev-parse", "origin/main"]) !== sourceSha || read(["status", "--porcelain"]) !== "") throw new Error("Web authorization requires a clean exact protected-main checkout.");
  return true;
}

export function writeWebAuthorization({ output, authorization } = {}) {
  fs.writeFileSync(output, `${JSON.stringify(authorization, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  return crypto.createHash("sha256").update(fs.readFileSync(output)).digest("hex");
}

export function runCli(argv = process.argv.slice(2), deps = {}) {
  if (argv.length !== 12) throw new Error("Web authorization accepts exactly six options.");
  const sourceSha = required(argv, "--source-sha"); assertFreshProtectedSource(sourceSha, deps);
  const authorization = buildWebImageAuthorization({ sourceSha, evidence: readJson(required(argv, "--evidence"), "Web evidence"), signature: readJson(required(argv, "--signature"), "Web signature"), imageImpact: readJson(required(argv, "--image-impact"), "Image impact"), reviewer: required(argv, "--reviewer"), now: deps.now || new Date().toISOString(), verify: deps.verify || createPinnedRootAttestationVerifier() });
  const output = required(argv, "--output"); const sha256 = writeWebAuthorization({ output, authorization });
  return Object.freeze({ output, sha256, authorization });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  try { const result = runCli(); process.stdout.write(`WEB_IMAGE_AUTHORIZATION_SHA256=${result.sha256}\n`); }
  catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
