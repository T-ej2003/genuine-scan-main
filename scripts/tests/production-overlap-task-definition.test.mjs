import assert from "node:assert/strict";
import test from "node:test";
import { buildOverlapTaskDefinition, OVERLAP_TASK_MARKER, registerOverlapTaskDefinition } from "../aws/production-overlap-task-definition.mjs";

const sourceSha = "a".repeat(40);
const backendImage = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"b".repeat(64)}`;
const taskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
const valueReferenceBindings = new Set(["JWT_SECRET_PREVIOUS", "QR_SIGN_ACTIVE_KEY_VERSION", "QR_SIGN_PUBLIC_KEY_PREVIOUS", "QR_SIGN_PREVIOUS_KEY_VERSION"]);
const secretBindings = Object.fromEntries([
  "JWT_SECRET_CURRENT", "JWT_SECRET_PREVIOUS", "QR_SIGN_PRIVATE_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_CURRENT", "QR_SIGN_ACTIVE_KEY_VERSION", "QR_SIGN_PUBLIC_KEY_PREVIOUS", "QR_SIGN_PREVIOUS_KEY_VERSION", "ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT", "ARTIFACT_SIGN_ACTIVE_KEY_VERSION", "ARTIFACT_SIGN_PUBLIC_KEYS_JSON",
].map((name) => [name, `arn:aws:secretsmanager:eu-west-2:368992683803:secret:fixture/${name}${valueReferenceBindings.has(name) ? ":value::" : ""}`]).concat([["ROTATION_INVENTORY_RLS_ROLE", "mscqr_prod_rls_read"]]));
const input = { backendImage, releaseSha: sourceSha, backendLogGroup: "/ecs/mscqr-production/rls-green-backend", secretBindings };
const awsReadback = (definition) => ({
  ...structuredClone(definition), taskDefinitionArn, revision: 9, status: "ACTIVE", enableFaultInjection: false,
  containerDefinitions: definition.containerDefinitions.map((container) => ({ ...structuredClone(container), cpu: 0, environmentFiles: [], systemControls: [], ulimits: [], volumesFrom: [], logConfiguration: { ...container.logConfiguration, secretOptions: [] } })),
  placementConstraints: [],
});

test("overlap registration uses the shared ECS readback normalizer for benign AWS defaults", async () => {
  const payload = buildOverlapTaskDefinition(input);
  await assert.doesNotReject(() => registerOverlapTaskDefinition({
    input,
    register: async () => ({ taskDefinition: { taskDefinitionArn } }),
    describe: async () => ({ ...awsReadback(payload.taskDefinition), tags: [OVERLAP_TASK_MARKER] }),
  }));
});

test("overlap registration rejects an executable readback drift despite benign defaults", async () => {
  const payload = buildOverlapTaskDefinition(input);
  const readback = awsReadback(payload.taskDefinition);
  readback.containerDefinitions[0].image = backendImage.replace(/b{64}$/, "c".repeat(64));
  await assert.rejects(() => registerOverlapTaskDefinition({
    input,
    register: async () => ({ taskDefinition: { taskDefinitionArn } }),
    describe: async () => ({ ...readback, tags: [OVERLAP_TASK_MARKER] }),
  }), /execution contract/);
});
