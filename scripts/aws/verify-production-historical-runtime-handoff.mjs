#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { pathToFileURL } from "node:url";
import { historicalWorkerTasks } from "./production-historical-runtime-contract.mjs";
import { canonicalSha256, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { assertProductionComponentDeploymentState, createProductionComponentDeploymentStateClient, stateHash } from "./production-component-deployment-state.mjs";
import { authenticateHistoricalRuntimeEvidence, authenticateRetainedHistoricalRuntime, verifyHistoricalRuntimeInventory } from "./production-historical-runtime-evidence.mjs";
import { createAwsReader } from "./production-green-stage-b-ecs-observations.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

export function verifyHistoricalRuntimeHandoff({ evidence, state, reader, sourceSha, verify, now }) {
  assert.ok(state, "Component state is not bootstrapped");
  if (state.historicalRuntimeRetention) {
    const reference = authenticateRetainedHistoricalRuntime({ state, reader, verify });
    if (evidence) {
      authenticateHistoricalRuntimeEvidence({ evidence, retained: true, verify });
      assert.equal(reference.referenceSha256, evidence.reference.referenceSha256);
      assert.equal(canonicalSha256(state.historicalRuntimeRetention.authority.binding), canonicalSha256(evidence.binding));
    }
    verifyHistoricalRuntimeInventory({ reference, reader });
    return reference;
  }
  const arns = reader.listTasks("RUNNING"); let workerPresent = false;
  for (let i = 0; i < arns.length; i += 100) {
    const response = reader.describeTasks(arns.slice(i, i + 100)); assert.equal(response.failures?.length, 0); assert.equal(response.tasks?.length, arns.slice(i, i + 100).length);
    workerPresent ||= historicalWorkerTasks({ tasks: response.tasks, reader }).length > 0;
  }
  if (!evidence) { assert.equal(workerPresent, false, "Historical worker requires the signed Stage B evidence handoff"); return undefined; }
  const reference = authenticateHistoricalRuntimeEvidence({ evidence, sourceSha, verify, now });
  assert.equal(state.generation, 1); assert.equal(state.updatedByLane, "BOOTSTRAP"); assert.equal(state.normalDeploymentReceipt, undefined);
  assert.equal(stateHash(state), reference.bootstrap.componentStateSha256); assert.equal(String(state.githubRunId), reference.bootstrap.githubRunId); assert.equal(state.updatedByWorkflow, reference.bootstrap.workflow);
  verifyHistoricalRuntimeInventory({ reference, reader });
  return reference;
}

// Shared by approval collection and broker execution; conflicting signed claims
// cannot override the authenticated durable retention record.
export function resolveHistoricalRuntimeAuthority(options) {
  if (options.state) assertProductionComponentDeploymentState(options.state);
  const reference = options.state || options.reader
    ? verifyHistoricalRuntimeHandoff(options)
    : options.evidence ? authenticateHistoricalRuntimeEvidence(options) : undefined;
  return reference?.referenceSha256;
}

export function readHistoricalRuntimeTransport({ bytes, expectedSha256 }) {
  assert.ok(Buffer.isBuffer(bytes)); assert.match(expectedSha256 || "", /^[a-f0-9]{64}$/);
  assert.equal(crypto.createHash("sha256").update(bytes).digest("hex"), expectedSha256, "Historical runtime transport checksum mismatch");
  return JSON.parse(bytes);
}

// Called only after the selected plan/report/signature have been verified by
// the existing Stage B apply/closure boundary. Never infer retention from ECS.
export function verifyStageBHistoricalRuntime({ reference, permissionReport, state, reader, verify }) {
  if (!reference) {
    const retained = verifyHistoricalRuntimeHandoff({ state: state || {}, reader, verify });
    assert.equal(retained, undefined, "Stage B omitted its retained historical runtime reference");
    return true;
  }
  assert.ok(state);
  assert.equal(permissionReport.historicalRuntimeAuthority?.referenceSha256, reference.referenceSha256);
  if (state.historicalRuntimeRetention) {
    const retained = authenticateRetainedHistoricalRuntime({ state, reader, verify });
    assert.equal(retained.referenceSha256, reference.referenceSha256);
  } else {
    assert.equal(state.generation, 1); assert.equal(state.updatedByLane, "BOOTSTRAP"); assert.equal(state.normalDeploymentReceipt, undefined);
    assert.equal(stateHash(state), reference.bootstrap.componentStateSha256);
    assert.equal(reference.recoverySourceSha, permissionReport.sourceSha);
  }
  verifyHistoricalRuntimeInventory({ reference, reader });
  return true;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2);
  assert.ok([2, 6].includes(args.length)); const values = {};
  for (let i = 0; i < args.length; i += 2) { assert.ok(["--source-sha", "--evidence", "--evidence-sha256"].includes(args[i])); assert.equal(values[args[i]], undefined); values[args[i]] = args[i + 1]; }
  assert.match(values["--source-sha"] || "", /^[a-f0-9]{40}$/);
  const evidence = values["--evidence"] ? readHistoricalRuntimeTransport({ bytes: fs.readFileSync(values["--evidence"]), expectedSha256: values["--evidence-sha256"] }) : undefined;
  const run = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER });
  const reader = createAwsReader({ run, region: STAGE_B.region, clusterArn: STAGE_B.clusterArn });
  const reference = verifyHistoricalRuntimeHandoff({ evidence, state: createProductionComponentDeploymentStateClient({ run }).read(), reader, sourceSha: values["--source-sha"] });
  process.stdout.write(`${JSON.stringify({ verified: true, referenceSha256: reference?.referenceSha256 || null })}\n`);
}
