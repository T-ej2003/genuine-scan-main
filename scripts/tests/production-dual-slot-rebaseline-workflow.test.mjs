import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(new URL(".", import.meta.url).pathname, "../..");
const workflow = readFileSync(path.join(root, ".github/workflows/authorize-production-dual-slot-rebaseline.yml"), "utf8");

test("rebaseline authorization workflow keeps dispatch inputs out of executable shell text", () => {
  const runBodies = [...workflow.matchAll(/^[ ]{8}run: \|\n((?:^[ ]{10}.*\n?)*)/gm)].map((match) => match[1]);
  assert.ok(runBodies.length >= 3);
  assert.equal(runBodies.some((body) => body.includes("${{ inputs.")), false);
  assert.equal(workflow.includes("environment: production"), true);
  assert.match(workflow, /actions:\s*read/);
  assert.equal(workflow.includes("--untracked-files=no"), false);
  assert.match(workflow, /git status --porcelain=v1 --untracked-files=all/);
  for (const name of ["SOURCE_SHA", "HISTORICAL_ROTATION_ID", "ROTATION_ID", "ABANDONMENT_EVIDENCE_SHA256", "BASELINE_IDENTITY_SHA256", "RESOURCES_JSON", "WRITE_IDENTITIES_JSON", "EXPECTED_SECRET_VALUE_WRITES", "EXPECTED_SECRET_DELETES", "LIVE_REFERENCE_AUDIT", "LIVE_REFERENCE_AUDIT_SHA256", "OBSERVED_SLOT_IDENTITIES_SHA256", "REASON", "APPROVER_ROLE", "VERIFICATION_REF"]) assert.match(workflow, new RegExp(`^          ${name}: \\$\\{\\{ inputs\\.`, "m"));
  assert.equal(/gh api[^\n]*--output/.test(workflow), false);
  assert.equal(/terraform\s+(plan|apply)|UpdateService|RegisterTaskDefinition|aws-access-key/i.test(workflow), false);
  assert.equal(workflow.trimEnd().endsWith("retention-days: 90"), true);
});

test("workflow authenticates an exact clean protected checkout before lifecycle code", () => {
  const protectedSource = workflow.indexOf("Authenticate protected source before dependencies");
  const install = workflow.indexOf("npm ci");
  const environmentApproval = workflow.indexOf("production-github-environment-approval.mjs");
  assert.ok(protectedSource >= 0 && protectedSource < install);
  assert.ok(environmentApproval > install);
  assert.match(workflow, /protected_main_sha="\$\(gh api "repos\/\$EXPECTED_REPOSITORY\/branches\/main"/);
  assert.match(workflow, /test "\$SOURCE_SHA" = "\$protected_main_sha"/);
  assert.match(workflow, /cmp --silent "\$RUNNER_TEMP\/dual-slot-rebaseline\/protected-source-inputs\.sha256" "\$RUNNER_TEMP\/dual-slot-rebaseline\/installed-source-inputs\.sha256"/);
});

test("every strict shell step binds its non-default inputs in that same step", () => {
  const step = (name) => workflow.slice(workflow.indexOf(`- name: ${name}`), workflow.indexOf("\n      - ", workflow.indexOf(`- name: ${name}`) + 1));
  const protectedSource = step("Authenticate protected source before dependencies");
  const postInstall = step("Re-authenticate protected source after dependency installation");
  const environment = step("Authenticate protected environment approval");
  const producer = step("Produce exact rebaseline authorization artifact");
  assert.match(protectedSource, /SOURCE_SHA: \$\{\{ inputs\.source_sha \}\}/);
  assert.match(postInstall, /SOURCE_SHA: \$\{\{ inputs\.source_sha \}\}/);
  assert.match(postInstall, /test "\$\(git rev-parse HEAD\)" = "\$SOURCE_SHA"/);
  assert.match(environment, /SOURCE_SHA: \$\{\{ inputs\.source_sha \}\}/);
  assert.match(environment, /--require-actual-approval/);
  for (const variable of ["SOURCE_SHA", "HISTORICAL_ROTATION_ID", "ROTATION_ID", "ABANDONMENT_EVIDENCE_SHA256", "BASELINE_IDENTITY_SHA256", "RESOURCES_JSON", "WRITE_IDENTITIES_JSON", "WRITE_PAYLOAD_IDENTITIES_JSON", "EXPECTED_SECRET_VALUE_WRITES", "EXPECTED_SECRET_DELETES", "LIVE_REFERENCE_AUDIT", "LIVE_REFERENCE_AUDIT_SHA256", "OBSERVED_SLOT_IDENTITIES_SHA256", "REASON", "APPROVER_ROLE", "VERIFICATION_REF", "ENVIRONMENT_APPROVAL_SHA"]) assert.match(producer, new RegExp(`${variable}:`));
});

test("strict workflow shells have an explicit source for every referenced uppercase variable", () => {
  const githubDefaults = new Set(["GITHUB_REPOSITORY", "GITHUB_WORKFLOW_REF", "GITHUB_EVENT_NAME", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_ACTOR", "GITHUB_OUTPUT", "GITHUB_TOKEN", "RUNNER_TEMP"]);
  for (const step of workflow.split("\n      - ").slice(1)) {
    if (!step.includes("set -euo pipefail")) continue;
    const env = new Set([...step.matchAll(/^          ([A-Z][A-Z0-9_]*):/gm)].map(([, name]) => name));
    const variables = new Set([...step.matchAll(/\$(?:\{)?([A-Z][A-Z0-9_]*)\}?/g)].map(([, name]) => name));
    for (const variable of variables) assert.ok(env.has(variable) || githubDefaults.has(variable), `${step.match(/^name: ([^\n]+)/)?.[1]} leaves ${variable} unbound under set -u`);
  }
});

test("malicious dispatch values remain environment data at the Node argument boundary", () => {
  const malicious = ["$(command)", "`command`", "\"; command; #", "line-one\nline-two"];
  const shell = workflow.match(/node scripts\/aws\/authorize-production-dual-slot-rebaseline\.mjs[\s\S]*?\n      - uses: actions\/upload-artifact/)[0];
  for (const value of malicious) assert.equal(shell.includes(value), false);
  assert.match(shell, /--source-sha "\$SOURCE_SHA"/);
  assert.match(shell, /--resources-json "\$RESOURCES_JSON"/);
  assert.match(shell, /--write-identities-json "\$WRITE_IDENTITIES_JSON"/);
  assert.match(shell, /--write-payload-identities-json "\$WRITE_PAYLOAD_IDENTITIES_JSON"/);
});
