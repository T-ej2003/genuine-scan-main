import assert from "node:assert/strict";
import { createHash } from "node:crypto";

export const NORMAL_RECEIPT_WORKFLOW = "T-ej2003/genuine-scan-main/.github/workflows/production-deploy.yml@refs/heads/main";
export const normalReceiptHash = (value) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
export const sameNormalIdentity = (a, b) => ["sourceSha", "imageDigest", "taskDefinitionArn", "desiredCount"].every((key) => a?.[key] === b?.[key]);
const SHA = /^[a-f0-9]{40}$/;
const families = { backend: "mscqr-production-rls-green-backend-candidate", frontend: "mscqr-frontend" };

export function classifyNormalLiveComponentState({ live, predecessor, authenticatedReceipt, component } = {}) {
  if (sameNormalIdentity(live, predecessor)) return "LIVE_IS_PREDECESSOR";
  if (authenticatedReceipt) {
    assertNormalDeploymentReceipt(authenticatedReceipt);
    if (authenticatedReceipt.phase === "VERIFIED" && authenticatedReceipt.predecessors[component]
      && sameNormalIdentity(predecessor, authenticatedReceipt.predecessors[component])
      && authenticatedReceipt.candidates[component] && sameNormalIdentity(live, authenticatedReceipt.candidates[component]))
      return "LIVE_IS_RECONCILABLE_NORMAL_DEPLOYMENT";
  }
  return "LIVE_IS_UNKNOWN";
}

// Stored in the exact IAM-protected production state item, never accepted from
// a workflow input or an uploaded/local journal. Hashes bind content, not trust.
export function assertNormalDeploymentReceipt(value) {
  assert.equal(value?.schemaVersion, 1);
  assert.ok(Buffer.byteLength(JSON.stringify(value)) <= 16384, "Normal receipt exceeds its bounded identity record");
  assert.deepEqual(Object.keys(value).sort(), ["schemaVersion", "kind", "workflow", "sourceSha", "planSha256", "githubRunId", "phase", "predecessors", "images", "candidates", ...(value.phase === "VERIFIED" ? ["verification"] : [])].sort());
  assert.equal(value.kind, "NORMAL_DEPLOYMENT_RECEIPT");
  assert.equal(value.workflow, NORMAL_RECEIPT_WORKFLOW);
  assert.match(value.sourceSha || "", SHA);
  assert.match(value.planSha256 || "", /^[a-f0-9]{64}$/);
  assert.match(value.githubRunId || "", /^[1-9][0-9]*$/);
  assert.ok(["PREPARED", "VERIFIED", "ROLLING_BACK"].includes(value.phase));
  const names = Object.keys(value.predecessors || {}).sort();
  assert.ok(names.length > 0 && names.every((name) => Object.hasOwn(families, name)));
  assert.deepEqual(Object.keys(value.images || {}).sort(), names);
  assert.ok(value.candidates && typeof value.candidates === "object" && !Array.isArray(value.candidates));
  for (const name of names) {
    const previous = value.predecessors[name];
    assert.match(previous?.sourceSha || "", SHA); assert.match(previous?.establishedThroughSha || "", SHA);
    assert.match(previous?.imageDigest || "", /^sha256:[a-f0-9]{64}$/);
    assert.match(previous?.taskDefinitionArn || "", /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/[^:]+:[1-9][0-9]*$/);
    assert.ok(Number.isSafeInteger(previous.desiredCount) && previous.desiredCount > 0);
    assert.match(value.images[name] || "", new RegExp(`^368992683803\\.dkr\\.ecr\\.eu-west-2\\.amazonaws\\.com/${name === "backend" ? "mscqr-backend" : "mscqr-web"}@sha256:[a-f0-9]{64}$`));
  }
  for (const [name, candidate] of Object.entries(value.candidates)) {
    assert.ok(names.includes(name));
    assert.deepEqual(Object.keys(candidate).sort(), ["sourceSha", "establishedThroughSha", "imageDigest", "taskDefinitionArn", "desiredCount"].sort());
    assert.equal(candidate.sourceSha, value.sourceSha); assert.equal(candidate.establishedThroughSha, value.sourceSha);
    assert.equal(candidate.imageDigest, value.images[name].split("@")[1]);
    assert.equal(candidate.desiredCount, value.predecessors[name].desiredCount);
    assert.match(candidate.taskDefinitionArn || "", new RegExp(`^arn:aws:ecs:eu-west-2:368992683803:task-definition/${families[name]}:[1-9][0-9]*$`));
    assert.notEqual(candidate.taskDefinitionArn, value.predecessors[name].taskDefinitionArn);
  }
  if (value.phase === "VERIFIED") {
    assert.deepEqual(Object.keys(value.candidates).sort(), names);
    assert.equal(value.verification, "STABILITY_READINESS_AUTHENTICATED_SMOKE_PASSED");
  } else assert.equal(value.verification, undefined);
  return value;
}
