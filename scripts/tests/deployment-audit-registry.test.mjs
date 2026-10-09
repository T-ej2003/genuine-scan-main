import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { load } from "js-yaml";

test("audit uses digest-pinned official nginx mirror without changing security stages", () => {
  const workflow = load(readFileSync(".github/workflows/deployment-audit.yml", "utf8"));
  const steps = workflow.jobs.audit.steps;
  const build = steps.find(step => step.name === "Build container for scan");
  const command = build.run.replaceAll("${{ steps.docker-detect.outputs.dockerfile }}", "Dockerfile")
    .replaceAll("${{ steps.docker-detect.outputs.context }}", ".");
  const output = execFileSync("bash", ["-eu", "-c", `docker() { printf '%s\\n' "$@"; }; ${command}`], { encoding: "utf8" });
  assert.deepEqual(output.trim().split("\n"), [
    "build", "--build-context",
    "nginx:1.29-alpine=docker-image://public.ecr.aws/docker/library/nginx@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de",
    "-t", "deployment-audit:latest", "-f", "Dockerfile", ".",
  ]);
  assert.match(readFileSync("Dockerfile", "utf8"), /^FROM nginx:1\.29-alpine$/m);
  assert.equal(steps.find(step => step.name === "Trivy container scan").with["image-ref"], "deployment-audit:latest");
  assert.equal(steps.find(step => step.name === "Trivy IaC scan").with["scan-type"], "config");
  assert.equal(steps.find(step => step.name === "Generate SBOM").with.format, "spdx-json");
  assert.equal(steps.find(step => step.name === "Run OSV Scanner").run, "node scripts/check-osv-runtime.mjs audit-artifacts/osv-source.json");
  assert.equal(workflow.on.pull_request, null);
  assert.equal(workflow.jobs.audit["continue-on-error"], undefined);
});
