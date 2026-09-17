import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { createProductionGithubCredentialEnvironment } from "./production-credential-source-contract.mjs";
import { assertComponentIamEnvironment, componentIamAuthorization } from "./component-iam-authorization.mjs";
import { assertArchivedInstallationAuthorization } from "./component-broker-authorization.mjs";
import { buildComponentBrokerPackage } from "./component-broker-package.mjs";
import { digest } from "./component-iam-installation-contract.mjs";

// Pure evidence construction, not a local grant. Only the fixed reusable
// workflow's OIDC role can submit this to immutable broker entry version 3.
export function approvedInstallationRequest({ sourceSha, transitionId, runId, main, run, environment, branches, approvals, packageEvidence, now }) {
  const contract = componentIamAuthorization;
  assert.equal(main.name, "main");
  assert.equal(main.protected, true);
  assert.equal(main.commit.sha, sourceSha);
  assert.equal(run.head_sha, sourceSha);
  assert.equal(run.head_branch, "main");
  assert.equal(run.repository.full_name, contract.repository);
  assert.equal(run.repository.id, 1145608538);
  assert.equal(run.head_repository.id, 1145608538);
  assert.equal(run.path, contract.workflow);
  assert.equal(run.event, "workflow_dispatch");
  assert.equal(run.status, "in_progress");
  assert.equal(run.run_attempt, 1);
  assert.equal(String(run.id), runId);
  for (const actor of [run.actor, run.triggering_actor]) {
    assert.equal(actor.type, "User");
    assert.equal(actor.login, "T-ej2003");
    assert.equal(actor.id, 183396573);
  }
  assertComponentIamEnvironment(environment, branches, approvals);
  const { manifest, manifestSha256, packageSha256 } = packageEvidence;
  assert.equal(manifest.sourceSha, sourceSha);
  assert.equal(manifestSha256, digest(manifest));
  const actor = { type: "User", login: "T-ej2003", id: 183396573 };
  const authorization = {
    schemaVersion: 1, account: contract.account, region: contract.region, sourceSha, transitionId, runId,
    operator: actor, reviewer: actor, environment: contract.environment,
    approvalObservedAt: new Date(now).toISOString(), expiresAt: new Date(now + contract.maxAgeMs).toISOString(),
    documentBindingsSha256: manifest.documentBindingsSha256, capabilitySetSha256: manifest.capabilitySetSha256,
    brokerPackageSha256: packageSha256, brokerManifestSha256: manifestSha256,
  };
  assertArchivedInstallationAuthorization(authorization, manifest, packageSha256, { now });
  return { operation: "AUTHORIZE", authorization };
}

async function prepare() {
  assert.deepEqual(process.argv.slice(2), ["prepare"], "Only prepare is supported");
  const { GITHUB_REPOSITORY, GITHUB_REF, GITHUB_SHA, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT, SOURCE_SHA, TRANSITION_ID, RUNNER_TEMP } = process.env;
  assert.equal(GITHUB_REPOSITORY, componentIamAuthorization.repository);
  assert.equal(GITHUB_REF, "refs/heads/main");
  assert.equal(GITHUB_RUN_ATTEMPT, "1");
  assert.equal(SOURCE_SHA, GITHUB_SHA);
  assert.match(GITHUB_RUN_ID || "", /^[1-9][0-9]*$/);
  assert(path.isAbsolute(RUNNER_TEMP || ""));
  const gh = (suffix) => JSON.parse(execFileSync("/usr/bin/gh", ["api", "--hostname", "github.com", `repos/${componentIamAuthorization.repository}/${suffix}`], {
    encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: { ...createProductionGithubCredentialEnvironment(), GH_HOST: "github.com", GH_PROMPT_DISABLED: "1" },
  }));
  const packageEvidence = await buildComponentBrokerPackage();
  const environmentPath = `environments/${componentIamAuthorization.environment}`;
  const request = approvedInstallationRequest({ sourceSha: SOURCE_SHA, transitionId: TRANSITION_ID, runId: GITHUB_RUN_ID,
    main: gh("branches/main"), run: gh(`actions/runs/${GITHUB_RUN_ID}`), environment: gh(environmentPath), branches: gh(`${environmentPath}/deployment-branch-policies`),
    approvals: gh(`actions/runs/${GITHUB_RUN_ID}/approvals`), packageEvidence, now: Date.now() });
  fs.writeFileSync(path.join(RUNNER_TEMP, "component-installation-request.json"), JSON.stringify(request), { flag: "wx", mode: 0o600 });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) prepare().catch(() => {
  console.error("Component installation authorization preparation rejected.");
  process.exitCode = 1;
});
