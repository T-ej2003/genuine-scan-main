#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { createProductionCommandRunner } from "./production-cutover-production-adapters.mjs";
import { buildRootDropEvidence } from "./production-root-drop-evidence.mjs";

const args = new Map();
for (let i = 0; i < process.argv.slice(2).length; i += 2) {
  const key = process.argv[i + 2]?.replace(/^--/, "");
  const value = process.argv[i + 3];
  if (!["source-sha", "output"].includes(key) || !value || args.has(key)) throw new Error(`Invalid or duplicate argument: --${key}`);
  args.set(key, value);
}
if (!args.get("output")) throw new Error("--output is required.");
const gitRun = (argv) => execFileSync("git", argv, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const fresh = readFreshProtectedMainIdentity({ run: gitRun, expectedSourceSha: args.get("source-sha") });
const run = createProductionCommandRunner({ profile: "mscqr-production-release-deployer" });
const identity = JSON.parse(run(["sts", "get-caller-identity"]));
const evidence = buildRootDropEvidence({ sourceSha: fresh.headSha, callerArn: identity.Arn, accountId: identity.Account, region: process.env.AWS_REGION || "eu-west-2" });
writeStageBPrivateFileAtomic({ filePath: args.get("output"), bytes: Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`), repositoryRoot: process.cwd(), label: "Root-drop evidence" });
process.stdout.write(`${JSON.stringify({ status: "valid", evidenceRef: evidence.evidenceRef, evidenceSha256: evidence.evidenceSha256, callerArn: evidence.callerArn, sourceSha: evidence.sourceSha }, null, 2)}\n`);
