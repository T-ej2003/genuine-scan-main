import assert from "node:assert/strict";
import test from "node:test";
import { buildOverlapTaskDefinition, OVERLAP_TASK_MARKER, registerOverlapTaskDefinition } from "../aws/production-overlap-task-definition.mjs";

const sourceSha = "a".repeat(40);
const backendImage = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"b".repeat(64)}`;
const taskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:9";
const valueReferenceBindings = new Set(["JWT_SECRET_PREVIOUS", "QR_SIGN_ACTIVE_KEY_VERSION", "QR_SIGN_PUBLIC_KEY_PREVIOUS", "QR_SIGN_PREVIOUS_KEY_VERSION"]);
const secretBindings = Object.fromEntries([
  "JWT_SECRET_CURRENT", "JWT_SECRET_PREVIOUS", "QR_SIGN_PRIVATE_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_CURRENT", "QR_SIGN_ACTIVE_KEY_VERSION", "QR_SIGN_PUBLIC_KEY_PREVIOUS", "QR_SIGN_PREVIOUS_KEY_VERSION", "ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT", "ARTIFACT_SIGN_ACTIVE_KEY_VERSION", "ARTIFACT_SIGN_PUBLIC_KEYS_JSON",
].map((name) => [name, `arn:aws:secretsmanager:eu-west-2:368992683803:secret:fixture/${name}${valueReferenceBindings.has(name) ? ":value::" : ""}`]).concat([["ROTATION_INVENTORY_OPERATION", "rotation-inventory-v1"]]));
const input = { backendImage, imageReleaseSha: sourceSha, backendLogGroup: "/ecs/mscqr-production/rls-green-backend", secretBindings };
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

const durableFixture = () => {
  const entries = new Map();
  const revisions = new Map();
  let calls = 0;
  const journal = {
    readOperation: (id, phase) => entries.get(`${id}:${phase}`) || null,
    writeOperation: (id, phase, value) => {
      const key = `${id}:${phase}`;
      if (entries.has(key)) {
        assert.deepEqual(entries.get(key), value);
        return false;
      }
      entries.set(key, structuredClone(value));
      return true;
    },
  };
  const options = {
    input, sourceSha, rotationId: "rotation-test-1234", journal,
    list: () => [...revisions.keys()],
    describe: arn => revisions.get(arn),
    register: async payload => {
      calls += 1;
      revisions.set(taskDefinitionArn, { ...awsReadback(payload.taskDefinition), tags: payload.tags });
      return { taskDefinition: { taskDefinitionArn } };
    },
  };
  return { entries, revisions, options, calls: () => calls };
};

test("durable overlap registration adopts a completed revision after a lost AWS response", async () => {
  const fixture = durableFixture();
  fixture.options.register = async payload => {
    fixture.revisions.set(taskDefinitionArn, { ...awsReadback(payload.taskDefinition), tags: payload.tags });
    throw new Error("AWS response lost");
  };
  await assert.rejects(() => registerOverlapTaskDefinition(fixture.options), /response lost/);
  const durablePayload=[...fixture.entries].find(([key])=>key.endsWith(':PAYLOAD'));
  assert.ok(durablePayload,'exact reviewed ECS payload must be durable before native registration');
  assert.equal(durablePayload[1].taskDefinition.containerDefinitions[0].image,backendImage);
  fixture.options.register = () => { throw new Error("duplicate registration"); };
  const recovered = await registerOverlapTaskDefinition(fixture.options);
  assert.equal(recovered.taskDefinitionArn, taskDefinitionArn);
  assert.equal(recovered.mutationCount, 0);
  assert.equal((await registerOverlapTaskDefinition(fixture.options)).mutationCount, 0);
});

test("durable overlap registration fails closed on ambiguous dispatch, conflicting readback, and concurrent attempts", async () => {
  const fixture = durableFixture();
  fixture.options.register = () => { throw new Error("AWS timeout"); };
  await assert.rejects(() => registerOverlapTaskDefinition(fixture.options), /AWS timeout/);
  await assert.rejects(() => registerOverlapTaskDefinition(fixture.options), /outcome remains ambiguous/);
  const fresh = durableFixture();
  const original = fresh.options.journal.writeOperation;
  fresh.options.journal.writeOperation = (id, phase, value) => phase === "DISPATCH" ? (original(id, phase, value), false) : original(id, phase, value);
  await assert.rejects(() => registerOverlapTaskDefinition(fresh.options), /already dispatched/);
  assert.equal(fresh.calls(), 0);
});
