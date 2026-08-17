#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createProductionCommandRunner, describeStageAIngress } from "./production-cutover-production-adapters.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { producePostApplyStageAPlanRecovery } from "./production-stage-a-recovery-evidence.mjs";

const accepted = new Set(["source-sha", "stage-a-state", "stage-a-handoff", "stage-b-state", "endpoint-security-group", "runtime-security-group", "output"]);
const args = new Map();
for (let i = 0; i < process.argv.slice(2).length; i += 2) {
  const key = process.argv[i + 2]?.replace(/^--/, "");
  const value = process.argv[i + 3];
  if (!accepted.has(key) || !value || args.has(key)) throw new Error(`Invalid or duplicate argument: --${key}`);
  args.set(key, value);
}
for (const key of ["stage-a-state", "stage-a-handoff", "stage-b-state", "endpoint-security-group", "runtime-security-group", "output"]) if (!args.get(key)) throw new Error(`--${key} is required.`);
const gitRun = (argv) => execFileSync("git", argv, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const fresh = readFreshProtectedMainIdentity({ run: gitRun, expectedSourceSha: args.get("source-sha") });
const run = createProductionCommandRunner({ profile: "mscqr-production-release-deployer" });
const ingress = describeStageAIngress({ run, endpointSecurityGroupId: args.get("endpoint-security-group"), runtimeSecurityGroupId: args.get("runtime-security-group") });
const evidence = producePostApplyStageAPlanRecovery({ sourceSha: fresh.headSha, stageAStatePath: args.get("stage-a-state"), stageAHandoffPath: args.get("stage-a-handoff"), stageBStatePath: args.get("stage-b-state"), ingress: { ...ingress, endpointSecurityGroupId: args.get("endpoint-security-group"), runtimeSecurityGroupId: args.get("runtime-security-group") }, outputPath: args.get("output"), repositoryRoot: process.cwd() });
process.stdout.write(`${JSON.stringify({ status: "valid", mode: evidence.mode, evidenceRef: evidence.evidenceRef, evidenceSha256: evidence.fileSha256, sourceSha: evidence.sourceSha, historicalPlanPresent: evidence.historicalPlanPresent }, null, 2)}\n`);
