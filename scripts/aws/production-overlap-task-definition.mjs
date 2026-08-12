import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { assertFixedTaskDefinition } from "./production-green-stage-b-task-definitions.mjs";

const ROOT = path.resolve("infra/aws/terraform/production-green-stage-b/task-definitions");
const TEMPLATE_PATH = path.join(ROOT, "green-backend-rotation-candidate.json");
const FAMILY = "mscqr-production-rls-green-backend-candidate";
const DIGEST = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/;
const SHA = /^[a-f0-9]{40}$/;
const ARN = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-backend-candidate:[1-9][0-9]*$/;
const SECRET_REF = /^arn:aws:secretsmanager:eu-west-2:368992683803:secret:[A-Za-z0-9/_+=.@-]+(?::[A-Za-z0-9_-]+::)?$/;
const BASE_SECRET_REF = /^arn:aws:secretsmanager:eu-west-2:368992683803:secret:[A-Za-z0-9/_+=.@-]+$/;
const ECS_VALUE_REF = /^arn:aws:secretsmanager:eu-west-2:368992683803:secret:[A-Za-z0-9/_+=.@-]+:value::$/;
const ROTATION_BINDING_SHAPES = Object.freeze({
  JWT_SECRET_CURRENT: BASE_SECRET_REF,
  JWT_SECRET_PREVIOUS: ECS_VALUE_REF,
  QR_SIGN_PRIVATE_KEY_CURRENT: BASE_SECRET_REF,
  QR_SIGN_PUBLIC_KEY_CURRENT: BASE_SECRET_REF,
  QR_SIGN_ACTIVE_KEY_VERSION: ECS_VALUE_REF,
  QR_SIGN_PUBLIC_KEY_PREVIOUS: ECS_VALUE_REF,
  QR_SIGN_PREVIOUS_KEY_VERSION: ECS_VALUE_REF,
});
const REQUIRED_BINDINGS = Object.freeze(["JWT_SECRET_CURRENT", "JWT_SECRET_PREVIOUS", "QR_SIGN_PRIVATE_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_CURRENT", "QR_SIGN_ACTIVE_KEY_VERSION", "QR_SIGN_PUBLIC_KEY_PREVIOUS", "QR_SIGN_PREVIOUS_KEY_VERSION", "ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT", "ARTIFACT_SIGN_ACTIVE_KEY_VERSION", "ARTIFACT_SIGN_PUBLIC_KEYS_JSON", "ROTATION_INVENTORY_RLS_ROLE"]);
export const OVERLAP_TASK_MARKER = Object.freeze({ key: "MSCQRExecTarget", value: "production-backend" });
export const OVERLAP_TASK_TEMPLATE_PATH = "infra/aws/terraform/production-green-stage-b/task-definitions/green-backend-rotation-candidate.json";

export function canonicalBackendDatabaseSecretReference() {
  const value = JSON.parse(fs.readFileSync(TEMPLATE_PATH, "utf8")).containerDefinitions?.find(({ name }) => name === "backend")?.secrets?.find(({ name }) => name === "DATABASE_URL")?.valueFrom;
  if (!SECRET_REF.test(value || "")) throw new Error("Canonical backend DATABASE_URL secret reference is unavailable.");
  return value;
}

const replace = (value, bindings) => Array.isArray(value) ? value.map((item) => replace(item, bindings)) : value && typeof value === "object"
  ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, replace(item, bindings)]))
  : typeof value === "string" ? value.replace(/{{([A-Z0-9_]+)}}/g, (_, key) => {
    if (typeof bindings[key] !== "string" || !bindings[key]) throw new Error(`Missing overlap task binding: ${key}.`);
    return bindings[key];
  }) : value;

export function assertUniqueSecretBindingNames(definition) {
  const names = definition?.containerDefinitions?.flatMap(({ secrets = [] }) => secrets.map(({ name }) => name)) || [];
  if (new Set(names).size !== names.length) throw new Error("Overlap task definition contains duplicate secret binding names.");
  return true;
}

export function buildOverlapTaskDefinition({ backendImage, releaseSha, backendLogGroup, secretBindings, postPrepare = false } = {}) {
  if (!DIGEST.test(backendImage || "") || !SHA.test(releaseSha || "") || typeof backendLogGroup !== "string" || !backendLogGroup) throw new Error("Overlap task identity bindings are invalid.");
  if (!secretBindings || typeof secretBindings !== "object" || Array.isArray(secretBindings) || Object.keys(secretBindings).sort().join(",") !== [...REQUIRED_BINDINGS].sort().join(",")) throw new Error("Overlap task bindings are incomplete or contain an unreviewed target.");
  for (const name of REQUIRED_BINDINGS) {
    if (name === "ROTATION_INVENTORY_RLS_ROLE") { if (!/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(secretBindings[name] || "")) throw new Error("Runtime inventory role binding is invalid."); }
    else if (!SECRET_REF.test(secretBindings[name] || "")) throw new Error(`Overlap task secret binding is not an exact production reference: ${name}.`);
    else if (ROTATION_BINDING_SHAPES[name] && !((postPrepare && ["JWT_SECRET_CURRENT", "QR_SIGN_PRIVATE_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_CURRENT"].includes(name) ? ECS_VALUE_REF : ROTATION_BINDING_SHAPES[name]).test(secretBindings[name]))) throw new Error(`Overlap task secret binding has the wrong SDK/ECS reference shape: ${name}.`);
  }
  const definition = replace(JSON.parse(fs.readFileSync(TEMPLATE_PATH, "utf8")), {
    BACKEND_IMAGE: backendImage,
    RELEASE_SHA: releaseSha,
    BACKEND_LOG_GROUP: backendLogGroup,
    ...secretBindings,
  });
  assertUniqueSecretBindingNames(definition);
  if (/{{[A-Z0-9_]+}}/.test(JSON.stringify(definition)) || definition.family !== FAMILY) throw new Error("Overlap task definition is unresolved or has the wrong family.");
  assertFixedTaskDefinition(definition);
  const backend = definition.containerDefinitions?.find(({ name }) => name === "backend");
  if (!backend || definition.executionRoleArn !== "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-execution" || definition.taskRoleArn !== "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-task"
    || backend.image !== backendImage || backend.environment?.find(({ name }) => name === "RELEASE_GIT_SHA")?.value !== releaseSha
    || backend.environment?.find(({ name }) => name === "ROTATION_INVENTORY_APPROVED")?.value !== "true"
    || !/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(backend.environment?.find(({ name }) => name === "ROTATION_INVENTORY_RLS_ROLE")?.value || "")
    || !["JWT_SECRET_CURRENT", "JWT_SECRET_PREVIOUS", "QR_SIGN_PRIVATE_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_CURRENT", "QR_SIGN_ACTIVE_KEY_VERSION", "QR_SIGN_PUBLIC_KEY_PREVIOUS", "QR_SIGN_PREVIOUS_KEY_VERSION", "ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT", "ARTIFACT_SIGN_ACTIVE_KEY_VERSION", "ARTIFACT_SIGN_PUBLIC_KEYS_JSON"].every((name) => backend.secrets?.some((secret) => secret.name === name && typeof secret.valueFrom === "string" && secret.valueFrom))) {
    throw new Error("Overlap task definition is missing a required rotation or artifact binding.");
  }
  return { taskDefinition: definition, tags: [OVERLAP_TASK_MARKER] };
}

export async function registerOverlapTaskDefinition({ input, register, describe = null }) {
  if (typeof register !== "function") throw new Error("Overlap task registration adapter is required.");
  const payload = buildOverlapTaskDefinition(input);
  const response = await register(payload);
  const arn = response?.taskDefinition?.taskDefinitionArn || response?.taskDefinitionArn;
  if (!ARN.test(arn || "")) throw new Error("Overlap registration did not return the exact reviewed task-definition ARN.");
  if (describe) {
    const registered = await describe(arn);
    if (registered?.taskDefinitionArn !== arn || registered?.family !== FAMILY || registered?.status !== "ACTIVE") throw new Error("Registered overlap task definition did not converge to the reviewed payload.");
    if (!Array.isArray(registered.tags) || !registered.tags.some(({ key, value }) => key === OVERLAP_TASK_MARKER.key && value === OVERLAP_TASK_MARKER.value)) throw new Error("Registered overlap task definition is missing the creation-time execution marker.");
    const registeredBackend = registered.containerDefinitions?.find(({ name }) => name === "backend");
    if (registeredBackend && registeredBackend.image !== payload.taskDefinition.containerDefinitions.find(({ name }) => name === "backend")?.image) throw new Error("Registered overlap image differs from the authorized immutable digest.");
  }
  return { ...payload, valid: true, evidenceRef: arn, evidenceSha256: createHash("sha256").update(JSON.stringify(payload)).digest("hex"), taskDefinitionArn: arn };
}

export function createAwsOverlapTaskRegistrationAdapter({ run }) {
  if (typeof run !== "function") throw new Error("AWS overlap registration runner is required.");
  return async ({ taskDefinition, tags }) => {
    const response = await run(["ecs", "register-task-definition", "--cli-input-json", JSON.stringify({ ...taskDefinition, tags }), "--output", "json"]);
    const registered = typeof response === "string" ? JSON.parse(response) : response;
    const arn = registered?.taskDefinition?.taskDefinitionArn;
    if (!ARN.test(arn || "")) throw new Error("AWS overlap registration response is outside the reviewed family.");
    return registered;
  };
}
