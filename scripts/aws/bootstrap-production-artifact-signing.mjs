#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { createProductionCommandRunner } from "./production-cutover-production-adapters.mjs";
import { bootstrapArtifactSigningBindings } from "./production-artifact-signing-bootstrap.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";

export function parseArgs(argv) {
  if (argv.length !== 2 || argv[0] !== "--source-sha" || !/^[a-f0-9]{40}$/.test(argv[1])) throw new Error("Artifact-signing bootstrap requires --source-sha <full protected-main SHA>.");
  return argv[1];
}

export async function runCli(argv = process.argv.slice(2), deps = {}) {
  const sourceSha = parseArgs(argv);
  const fresh = (deps.readFresh || readFreshProtectedMainIdentity)({
    expectedSourceSha: sourceSha,
    run: deps.git || ((args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })),
  });
  if (fresh.headSha !== sourceSha || fresh.freshRemoteMainSha !== sourceSha) throw new Error("Artifact-signing bootstrap requires exact fresh protected main.");
  const run = deps.run || createProductionCommandRunner({ profile: "mscqr-production-release-deployer" });
  const result = await (deps.bootstrap || bootstrapArtifactSigningBindings)({ run: async (args) => run(args), sourceSha, repositoryRoot: deps.repositoryRoot || process.cwd() });
  const output = { status: "valid", sourceSha, bindingFile: result.bindingFile, bindingEvidenceSha256: result.evidenceSha256, createdSecretContainers: result.created, secretValueWrites: 0, AWS_WRITES: result.createSecretCount };
  (deps.write || ((value) => process.stdout.write(value)))(`${JSON.stringify(output, null, 2)}\n`);
  return output;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) await runCli();
