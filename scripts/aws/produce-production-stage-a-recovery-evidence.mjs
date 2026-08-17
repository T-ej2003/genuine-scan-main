#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createProductionCommandRunner, describeStageAIngress } from "./production-cutover-production-adapters.mjs";
import { assertStageAStateContract } from "./generate-production-green-stage-a-prerequisites.mjs";
import { assertStageBPrivateFile } from "./stage-b-artifact-contract.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { producePostApplyStageAPlanRecovery } from "./production-stage-a-recovery-evidence.mjs";

const accepted = new Set(["source-sha", "stage-a-state", "stage-a-handoff", "stage-b-state", "output"]);
const args = new Map();
for (let i = 0; i < process.argv.slice(2).length; i += 2) {
  const key = process.argv[i + 2]?.replace(/^--/, "");
  const value = process.argv[i + 3];
  if (!accepted.has(key) || !value || args.has(key)) throw new Error(`Invalid or duplicate argument: --${key}`);
  args.set(key, value);
}
for (const key of ["stage-a-state", "stage-a-handoff", "stage-b-state", "output"]) if (!args.get(key)) throw new Error(`--${key} is required.`);
const gitRun = (argv) => execFileSync("git", argv, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const fresh = readFreshProtectedMainIdentity({ run: gitRun, expectedSourceSha: args.get("source-sha") });
const run = createProductionCommandRunner({ profile: "mscqr-production-release-deployer" });
const stageAStatePath = assertStageBPrivateFile({ filePath: args.get("stage-a-state"), repositoryRoot: process.cwd(), label: "Stage-A state" }).path;
const stageAState = JSON.parse(readFileSync(stageAStatePath, "utf8"));
const stageAContract = assertStageAStateContract(stageAState);
const ingress = describeStageAIngress({ run, endpointSecurityGroupId: stageAContract.endpointSecurityGroupId, runtimeSecurityGroupId: stageAContract.executorSecurityGroupId });
const evidence = producePostApplyStageAPlanRecovery({ sourceSha: fresh.headSha, stageAStatePath, stageAHandoffPath: args.get("stage-a-handoff"), stageBStatePath: args.get("stage-b-state"), ingress, outputPath: args.get("output"), repositoryRoot: process.cwd() });
process.stdout.write(`${JSON.stringify({ status: "valid", mode: evidence.mode, evidenceRef: evidence.evidenceRef, evidenceSha256: evidence.fileSha256, sourceSha: evidence.sourceSha, historicalPlanPresent: evidence.historicalPlanPresent }, null, 2)}\n`);
