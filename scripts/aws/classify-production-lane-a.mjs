import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { pathToFileURL } from "node:url";
import { classifyProductionChanges, PRODUCTION_RELEASE_CLASS } from "./production-deployment-classification.mjs";

const SHA = /^[a-f0-9]{40}$/;

export function classifyLaneAComponentRanges({ backendFiles = [], frontendFiles = [] } = {}) {
  const backend = classifyProductionChanges(backendFiles);
  const frontend = classifyProductionChanges(frontendFiles);
  for (const result of [backend, frontend]) {
    assert.equal(result.releaseClass, PRODUCTION_RELEASE_CLASS.NORMAL_APPLICATION, "Infrastructure, RLS, schema-sensitive, recovery, and ambiguous changes require Lane B.");
    assert.equal(result.worker, false, "Worker changes require Lane B until a production worker service is source-owned.");
  }
  return Object.freeze({
    releaseClass: PRODUCTION_RELEASE_CLASS.NORMAL_APPLICATION,
    backend: backend.backend,
    frontend: frontend.frontend,
    worker: false,
  });
}

const git = (args) => execFileSync("git", args, { encoding: "utf8" }).trim();
const filesBetween = (base, target) => {
  assert.match(base, SHA); assert.match(target, SHA);
  execFileSync("git", ["merge-base", "--is-ancestor", base, target], { stdio: "ignore" });
  const output = git(["diff", "--name-only", `${base}..${target}`]);
  return output ? output.split("\n") : [];
};

export function classifyLaneACommitRanges({ backendBaseSha, frontendBaseSha, targetSha }) {
  return classifyLaneAComponentRanges({
    backendFiles: filesBetween(backendBaseSha, targetSha),
    frontendFiles: filesBetween(frontendBaseSha, targetSha),
  });
}

function arg(name) {
  const prefix = `--${name}=`;
  const value = process.argv.slice(2).find((entry) => entry.startsWith(prefix))?.slice(prefix.length);
  assert.ok(value, `Missing ${prefix}<value>`);
  return value;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  const result = classifyLaneACommitRanges({
    backendBaseSha: arg("backend-base"),
    frontendBaseSha: arg("frontend-base"),
    targetSha: arg("target"),
  });
  const output = process.argv.slice(2).find((entry) => entry.startsWith("--github-output="))?.slice("--github-output=".length);
  if (output) fs.appendFileSync(output, `release_class=${result.releaseClass}\nbackend=${result.backend}\nfrontend=${result.frontend}\nworker=false\n`);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}
