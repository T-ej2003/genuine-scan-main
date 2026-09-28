#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { establishSignerInstallSession, establishSignerRevokeSession } from "./component-installation-session.mjs";
import { signerLifecycleEvidenceBinding, SIGNER_BROKER_LIFECYCLE } from "./component-signer-policy-transition.mjs";
import { createProductionAwsCredentialEnvironment, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const required = (argv, name) => { const index = argv.indexOf(name), value = index < 0 ? undefined : argv[index + 1]; assert(value && !value.startsWith("--"), `${name} is required`); return value; };
const loadBootstrap = () => JSON.parse(execFileSync("aws", ["configure", "export-credentials", "--format", "process"], {
  env: createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-bootstrap-mfa", region: "eu-west-2" }),
  encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
}));
function readLedger(file) {
  const stat = fs.lstatSync(file); assert(stat.isFile() && !stat.isSymbolicLink() && !(stat.mode & 0o077), "Signer lifecycle evidence must be a private regular file");
  const value = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(value.kind, "MSCQR_SIGNER_POLICY_BROKER_LEDGER"); return value;
}
function writeLedger(file, value) {
  const parent = path.dirname(file), stat = fs.lstatSync(parent); assert(stat.isDirectory() && !stat.isSymbolicLink() && !(stat.mode & 0o077), "Signer lifecycle directory must be private");
  const temporary = `${file}.${process.pid}.tmp`; fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { flag: "wx", mode: 0o600 }); fs.renameSync(temporary, file); fs.chmodSync(file, 0o600);
}

export async function run(argv = process.argv.slice(2), { installSession = establishSignerInstallSession, revokeSession = establishSignerRevokeSession, loadUser = loadBootstrap } = {}) {
  const phase = required(argv, "--phase"), file = path.resolve(required(argv, "--state-file")), ledger = readLedger(file), authorization = ledger.authorization;
  assert(["install", "advance", "revoke"].includes(phase));
  const values = new Set(["--phase", "--state-file", ...(phase === "advance" ? ["--state", "--plan-sha256", "--approval-reference", "--signer-readback-sha256"] : [])]);
  const switches = new Set(phase === "revoke" ? ["--abort-before-apply-confirmed"] : []), seen = new Set();
  for (let index = 0; index < argv.length; index++) {
    const name = argv[index]; assert((values.has(name) || switches.has(name)) && !seen.has(name), "Unsupported signer broker option"); seen.add(name);
    if (!switches.has(name)) { assert(argv[index + 1] && !argv[index + 1].startsWith("--"), `${name} requires a value`); index += 1; }
  }
  const binding = { sourceSha: authorization.sourceSha, transitionId: authorization.transitionId, authorizationSha256: authorization.authorizationSha256 };
  if (phase === "install") {
    const session = await installSession(binding, { loadUser });
    const result = await session.invoke("SIGNER_INSTALL"); writeLedger(file, result); return result;
  }
  let evidenceState = ledger.state;
  if (phase === "advance") {
    const state = required(argv, "--state"), planSha256 = argv.includes("--plan-sha256") ? required(argv, "--plan-sha256") : null,
      approvalReference = argv.includes("--approval-reference") ? required(argv, "--approval-reference") : null,
      signerReadbackSha256 = argv.includes("--signer-readback-sha256") ? required(argv, "--signer-readback-sha256") : null;
    if (ledger.state === state) {
      assert.equal(ledger.planSha256, planSha256); assert.equal(ledger.approvalReference, approvalReference); assert.equal(ledger.signerReadbackSha256, signerReadbackSha256);
      evidenceState = SIGNER_BROKER_LIFECYCLE[SIGNER_BROKER_LIFECYCLE.indexOf(state) - 1]; assert(evidenceState, "Signer advance retry lacks a predecessor");
    }
    const evidenceSha256 = signerLifecycleEvidenceBinding({ state: evidenceState, ...binding });
    const session = await installSession(binding, { loadUser });
    const result = await session.invoke("SIGNER_ADVANCE", { state, evidenceSha256, planSha256, approvalReference, signerReadbackSha256 });
    writeLedger(file, result); return result;
  }
  if (ledger.state === "REVOKED") evidenceState = ledger.history?.at(-1)?.state;
  const evidenceSha256 = signerLifecycleEvidenceBinding({ state: evidenceState, ...binding });
  const session = await revokeSession(binding, { loadUser });
  const result = await session.invoke("SIGNER_REVOKE", { evidenceState, evidenceSha256, abort: argv.includes("--abort-before-apply-confirmed") });
  writeLedger(file, result); return result;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) run().then(value => process.stdout.write(`${JSON.stringify({ state: value.state, authorizationSha256: value.authorization.authorizationSha256 })}\n`)).catch(() => { process.stderr.write("Signer broker transition rejected.\n"); process.exitCode = 1; });
