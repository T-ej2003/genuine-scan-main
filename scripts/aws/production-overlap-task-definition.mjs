import {readConditionalPrepareContext} from './production-cutover-conditional-capability.mjs';
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { STAGE_B, canonicalJson, assertConditionalProductionEnabled, CONDITIONAL_LANE_ENABLED } from "./production-green-stage-b-contract.mjs";
import { assertFixedTaskDefinition } from "./production-green-stage-b-task-definitions.mjs";
import { deriveEcsRuntimeDependencies } from "./production-ecs-runtime-dependencies.mjs";
import { assertEcsTaskDefinitionReadback } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs";

import {conditionalRotationClaimId,claimLegacyCutoverLane} from './production-cutover-conditional-lock.mjs';

const nativeRegistrars=new WeakSet(),nativeRequests=new WeakMap();
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
const REQUIRED_BINDINGS = Object.freeze(["JWT_SECRET_CURRENT", "JWT_SECRET_PREVIOUS", "QR_SIGN_PRIVATE_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_CURRENT", "QR_SIGN_ACTIVE_KEY_VERSION", "QR_SIGN_PUBLIC_KEY_PREVIOUS", "QR_SIGN_PREVIOUS_KEY_VERSION", "ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT", "ARTIFACT_SIGN_ACTIVE_KEY_VERSION", "ARTIFACT_SIGN_PUBLIC_KEYS_JSON", "ROTATION_INVENTORY_OPERATION"]);
export const OVERLAP_TASK_MARKER = Object.freeze({ key: "MSCQRExecTarget", value: "production-backend" });
export const OVERLAP_OPERATION_TAG = "MSCQROverlapOperation";
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

export function buildOverlapTaskDefinition({ backendImage, imageReleaseSha, backendLogGroup, secretBindings, postPrepare = false } = {}) {
  if (!DIGEST.test(backendImage || "") || !SHA.test(imageReleaseSha || "") || typeof backendLogGroup !== "string" || !backendLogGroup) throw new Error("Overlap task identity bindings are invalid.");
  if (!secretBindings || typeof secretBindings !== "object" || Array.isArray(secretBindings) || Object.keys(secretBindings).sort().join(",") !== [...REQUIRED_BINDINGS].sort().join(",")) throw new Error("Overlap task bindings are incomplete or contain an unreviewed target.");
  for (const name of REQUIRED_BINDINGS) {
    if (name === "ROTATION_INVENTORY_OPERATION") { if (secretBindings[name] !== STAGE_B.inventoryOperation) throw new Error("Runtime fixed inventory operation binding is invalid."); }
    else if (!SECRET_REF.test(secretBindings[name] || "")) throw new Error(`Overlap task secret binding is not an exact production reference: ${name}.`);
    else if (ROTATION_BINDING_SHAPES[name] && !((postPrepare && ["JWT_SECRET_CURRENT", "QR_SIGN_PRIVATE_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_CURRENT"].includes(name) ? ECS_VALUE_REF : ROTATION_BINDING_SHAPES[name]).test(secretBindings[name]))) throw new Error(`Overlap task secret binding has the wrong SDK/ECS reference shape: ${name}.`);
  }
  const definition = { ...replace(JSON.parse(fs.readFileSync(TEMPLATE_PATH, "utf8")), {
    BACKEND_IMAGE: backendImage,
    RELEASE_SHA: imageReleaseSha,
    BACKEND_LOG_GROUP: backendLogGroup,
    ...secretBindings,
  }), runtimePlatform: { ...STAGE_B.taskRuntimePlatform } };
  assertUniqueSecretBindingNames(definition);
  deriveEcsRuntimeDependencies(definition);
  if (/{{[A-Z0-9_]+}}/.test(JSON.stringify(definition)) || definition.family !== FAMILY) throw new Error("Overlap task definition is unresolved or has the wrong family.");
  assertFixedTaskDefinition(definition);
  const backend = definition.containerDefinitions?.find(({ name }) => name === "backend");
  if (!backend || definition.executionRoleArn !== "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-execution" || definition.taskRoleArn !== "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-task"
    || backend.image !== backendImage || backend.environment?.find(({ name }) => name === "RELEASE_GIT_SHA")?.value !== imageReleaseSha
    || backend.environment?.find(({ name }) => name === "ROTATION_INVENTORY_APPROVED")?.value !== "true"
    || backend.environment?.find(({ name }) => name === "ROTATION_INVENTORY_OPERATION")?.value !== STAGE_B.inventoryOperation
    || !["JWT_SECRET_CURRENT", "JWT_SECRET_PREVIOUS", "QR_SIGN_PRIVATE_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_CURRENT", "QR_SIGN_ACTIVE_KEY_VERSION", "QR_SIGN_PUBLIC_KEY_PREVIOUS", "QR_SIGN_PREVIOUS_KEY_VERSION", "ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT", "ARTIFACT_SIGN_ACTIVE_KEY_VERSION", "ARTIFACT_SIGN_PUBLIC_KEYS_JSON"].every((name) => backend.secrets?.some((secret) => secret.name === name && typeof secret.valueFrom === "string" && secret.valueFrom))) {
    throw new Error("Overlap task definition is missing a required rotation or artifact binding.");
  }
  return { taskDefinition: definition, tags: [OVERLAP_TASK_MARKER] };
}

export async function registerOverlapTaskDefinition({ input, register, describe = null, list = null, journal = null, sourceSha, rotationId, executionId, nativeRegister, conditionalContext, reconcileRead }) {
  const conditional=conditionalContext?readConditionalPrepareContext(conditionalContext):null;
  if(conditional){assertConditionalProductionEnabled();executionId=conditional.executionId;if(sourceSha!==conditional.d.historicalReleaseSha||rotationId!==conditional.d.rotationId)throw new Error('Conditional registration identity differs');}
  if (executionId || nativeRegister) assertConditionalProductionEnabled();
  if (!conditional && journal && rotationId && CONDITIONAL_LANE_ENABLED) await claimLegacyCutoverLane({store:journal,rotationId});
  if (!conditional && journal && rotationId && !CONDITIONAL_LANE_ENABLED && await journal.readOperation(conditionalRotationClaimId(rotationId),'CLAIM') !== null) throw new Error('Rotation is claimed by conditional execution; legacy registration is forbidden.');
  if(nativeRegistrars.has(register)&&!journal)throw new Error('Native overlap registration requires the durable rotation guard');
  if (typeof register !== "function") throw new Error("Overlap task registration adapter is required.");
  const payload = buildOverlapTaskDefinition(input);
  const operationId = journal ? createHash("sha256").update(canonicalJson({ sourceSha, rotationId, payload })).digest("hex") : null;
  if (journal && (!SHA.test(sourceSha || "") || !/^[A-Za-z0-9._-]{8,128}$/.test(rotationId || "")
      || typeof describe !== "function" || typeof list !== "function"
      || typeof journal.readOperation !== "function" || typeof journal.writeOperation !== "function")) throw new Error("Durable overlap registration boundary is incomplete.");
  if (journal) payload.tags.push({ key: OVERLAP_OPERATION_TAG, value: operationId });
  if (executionId || nativeRegister) {
    if (!conditional || !journal || !/^[a-f0-9]{64}$/.test(executionId||'')) throw new Error('Conditional registration requires exact context and durable native boundary.');
    payload.tags.push({key:'MSCQRConditionalExecution',value:executionId});
  }
  const intent = operationId && { sourceSha, rotationId, operationId, payloadSha256: createHash("sha256").update(canonicalJson(payload)).digest("hex") };
  if (journal) {
    const previous = await journal.readOperation(operationId, "INTENT");
    if (previous && canonicalJson(previous) !== canonicalJson(intent)) throw new Error("Overlap registration intent conflicts with durable history.");
    if (!previous) await journal.writeOperation(operationId, "INTENT", intent);
  }
  const verify = async arn => {
    if (!ARN.test(arn || "")) throw new Error("Overlap registration did not return the exact reviewed task-definition ARN.");
    if (!describe) return;
    const registered = await describe(arn);
    if (registered?.taskDefinitionArn !== arn || registered?.family !== FAMILY || registered?.status !== "ACTIVE") throw new Error("Registered overlap task definition did not converge to the reviewed payload.");
    assertEcsTaskDefinitionReadback({ definition: registered, taskDefinitionArn: arn, expected: payload.taskDefinition, label: "Registered overlap task definition" });
    if (!Array.isArray(registered.tags) || !registered.tags.some(({ key, value }) => key === OVERLAP_TASK_MARKER.key && value === OVERLAP_TASK_MARKER.value)) throw new Error("Registered overlap task definition is missing the creation-time execution marker.");
    if (journal && !registered.tags.some(({ key, value }) => key === OVERLAP_OPERATION_TAG && value === operationId)) throw new Error("Registered overlap task definition is not bound to the durable operation.");
    if(conditional && canonicalJson([...registered.tags].sort((a,b)=>a.key.localeCompare(b.key)))!==canonicalJson([...payload.tags].sort((a,b)=>a.key.localeCompare(b.key))))throw new Error('Conditional registration tags differ');
    const registeredBackend = registered.containerDefinitions?.find(({ name }) => name === "backend");
    if (registeredBackend && registeredBackend.image !== payload.taskDefinition.containerDefinitions.find(({ name }) => name === "backend")?.image) throw new Error("Registered overlap image differs from the authorized immutable digest.");
  };
  const result = (arn, mutationCount) => ({ ...payload, valid: true, evidenceRef: arn, evidenceSha256: createHash("sha256").update(JSON.stringify(payload)).digest("hex"), taskDefinitionArn: arn, mutationCount });
  if (journal) {
    const completed = await journal.readOperation(operationId, "COMPLETED");
    if (completed) {
      if (canonicalJson(completed.intent) !== canonicalJson(intent)) throw new Error("Overlap registration completion conflicts with durable intent.");
      if(conditional)throw new Error('Conditional registration history requires read-only authoritative reconciliation');
      await verify(completed.taskDefinitionArn);
      return result(completed.taskDefinitionArn, 0);
    }
    const matching = [];
    for (const arn of await list(FAMILY)) {
      if (!ARN.test(arn || "")) throw new Error("Overlap task census contains an invalid ARN.");
      const candidate = await describe(arn);
      if (candidate?.tags?.some(({ key, value }) => key === OVERLAP_OPERATION_TAG && value === operationId)) matching.push(arn);
    }
    if (matching.length > 1) throw new Error("Overlap operation produced multiple task-definition revisions.");
    if (conditional && matching.length) throw new Error('Conditional registration history requires read-only authoritative reconciliation');
    if (matching.length === 1) {
      await verify(matching[0]);
      await journal.writeOperation(operationId, "COMPLETED", { intent, taskDefinitionArn: matching[0] });
      return result(matching[0], 0);
    }
    if (await journal.readOperation(operationId, "DISPATCH")) throw new Error("Overlap registration outcome remains ambiguous; another revision is forbidden.");
    if (await journal.writeOperation(operationId, "DISPATCH", intent) !== true) throw new Error("Overlap registration was already dispatched; another revision is forbidden.");
  }
  const invokeRegistration=async()=>{
    if(nativeRegistrars.has(register))nativeRequests.set(payload,{journal,rotationId,conditional});
    try{return await register(payload);}finally{nativeRequests.delete(payload);}
  };
  let response;
  try{response = conditional ? (await conditional.dispatch('REGISTER_TASK_DEFINITION',{...payload.taskDefinition,tags:payload.tags},invokeRegistration,async output=>verify(output?.taskDefinition?.taskDefinitionArn||output?.taskDefinitionArn))).output : await invokeRegistration();}
  catch(error){
    if(!conditional||error.code!=='OUTCOME_UNKNOWN'||typeof reconcileRead!=='function')throw error;
    try{response=await conditional.reconcileRegistration({run:reconcileRead});}
    catch(reconciliationError){throw new Error('Registration remains UNKNOWN after read-only reconciliation; never register again',{cause:reconciliationError});}
  }
  const arn = response?.taskDefinition?.taskDefinitionArn || response?.taskDefinitionArn;
  await verify(arn);
  if (journal) await journal.writeOperation(operationId, "COMPLETED", { intent, taskDefinitionArn: arn });
  return result(arn, 1);
}

export function createAwsOverlapTaskRegistrationAdapter({ run }) {
  if (typeof run !== "function") throw new Error("AWS overlap registration runner is required.");
  const register=async payload => {
    const own=nativeRequests.get(payload);if(!own)throw new Error('Native registration is outside the claimed canonical consumer');nativeRequests.delete(payload);
    if(!own.conditional){
      if(CONDITIONAL_LANE_ENABLED)await claimLegacyCutoverLane({store:own.journal,rotationId:own.rotationId});
      else if(await own.journal.readOperation(conditionalRotationClaimId(own.rotationId),'CLAIM')!==null)throw new Error('Conditional rotation claim forbids native legacy registration');
    }
    const {taskDefinition,tags}=payload;
    const response = await run(["ecs", "register-task-definition", "--cli-input-json", JSON.stringify({ ...taskDefinition, tags }), "--output", "json"]);
    const registered = typeof response === "string" ? JSON.parse(response) : response;
    const arn = registered?.taskDefinition?.taskDefinitionArn;
    if (!ARN.test(arn || "")) throw new Error("AWS overlap registration response is outside the reviewed family.");
    return registered;
  };
  nativeRegistrars.add(register);return register;
}
