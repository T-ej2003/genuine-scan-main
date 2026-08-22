import fs from "node:fs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";

export const NORMAL_ACTIVATION = Object.freeze({
  account: "368992683803", region: "eu-west-2", lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", minimumSerial: 102,
  cluster: "mscqr-prod-euw2-main", clusterArn: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main",
  service: "mscqr-backend-servi-euw2", serviceArn: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2",
  family: "mscqr-production-rls-green-backend-candidate", container: "backend",
  roleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", administratorArn: "arn:aws:iam::368992683803:root",
  policyArn: "arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBFinalApplyWrite", policyPath: "documents/ops/iam/MSCQRProductionGreenStageBFinalApplyWrite-v1.json",
  stateUrl: "s3://mscqr-production-terraform-state-368992683803-eu-west-2/env:/production/mscqr/production/rls-green/stage-b/terraform.tfstate",
});

export const NORMAL_CANDIDATE_ARN = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-backend-candidate:([1-9][0-9]*)$/;
export const AWS_MANAGED_POLICY_DOCUMENT_LIMIT = 6144;
export const canonicalNormalActivationValue = (value) => Array.isArray(value)
  ? `[${value.map(canonicalNormalActivationValue).join(",")}]`
  : value && typeof value === "object"
    ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalNormalActivationValue(value[key])}`).join(",")}}`
    : JSON.stringify(value);

export function normalActivationCandidateArnFromState(state) {
  const candidates = (state?.resources || []).filter(({ mode, type, name }) => mode === "managed" && type === "aws_ecs_task_definition" && name === "candidate")
    .flatMap(({ instances = [] }) => instances)
    .filter(({ index_key: key }) => key === "backend");
  const targetArn = candidates.length === 1 ? candidates[0].attributes?.arn : null;
  if (state?.version !== 4 || state.lineage !== NORMAL_ACTIVATION.lineage || !Number.isInteger(state.serial) || state.serial < NORMAL_ACTIVATION.minimumSerial || !NORMAL_CANDIDATE_ARN.test(targetArn || "") || state.outputs?.task_definition_arns?.value?.backend !== targetArn) throw new Error("Stage-B state does not contain one authenticated normal backend candidate revision.");
  return targetArn;
}

export function buildNormalActivationPolicy(targetArn, sourcePolicy = JSON.parse(fs.readFileSync(NORMAL_ACTIVATION.policyPath, "utf8"))) {
  if (!NORMAL_CANDIDATE_ARN.test(targetArn || "")) throw new Error("Normal activation policy requires one exact candidate revision.");
  const policy = structuredClone(normalizeIamPolicyDocument(sourcePolicy, "normal activation source policy"));
  const statement = policy.Statement?.filter(({ Sid }) => Sid === "ActivateBackendCandidate");
  if (statement?.length !== 1) throw new Error("Normal activation source policy must contain one exact update statement.");
  const sourceTarget = statement[0].Condition?.ArnEquals?.["ecs:task-definition"];
  const recovery = policy.Statement?.filter(({ Sid }) => Sid === "RecoverLegacyBackend");
  if (!NORMAL_CANDIDATE_ARN.test(sourceTarget || "") || recovery?.length !== 1 || recovery[0].Condition?.ArnLike?.["ecs:task-definition"] !== "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:*") throw new Error("Normal activation and recovery update bindings are malformed.");
  statement[0].Condition.ArnEquals["ecs:task-definition"] = targetArn;
  if (Buffer.byteLength(JSON.stringify(policy)) > AWS_MANAGED_POLICY_DOCUMENT_LIMIT) throw new Error("Normal activation policy exceeds the AWS managed-policy document limit.");
  return policy;
}

export function assertNormalActivationPolicy(policy, targetArn) {
  const expected = buildNormalActivationPolicy(targetArn);
  if (canonicalNormalActivationValue(normalizeIamPolicyDocument(policy, "live normal activation policy")) !== canonicalNormalActivationValue(expected)) throw new Error("Live FinalApplyWrite policy does not exactly match the state-derived normal activation target.");
  const update = expected.Statement.find(({ Sid }) => Sid === "ActivateBackendCandidate");
  const recovery = expected.Statement.find(({ Sid }) => Sid === "RecoverLegacyBackend");
  if (update.Resource !== NORMAL_ACTIVATION.serviceArn || update.Action !== "ecs:UpdateService" || update.Condition?.StringEquals?.["ecs:cluster"] !== NORMAL_ACTIVATION.clusterArn || update.Condition?.StringEquals?.["aws:RequestedRegion"] !== NORMAL_ACTIVATION.region || update.Condition?.ArnEquals?.["ecs:task-definition"] !== targetArn || recovery?.Resource !== NORMAL_ACTIVATION.serviceArn || recovery.Action !== "ecs:UpdateService" || recovery.Condition?.StringEquals?.["ecs:cluster"] !== NORMAL_ACTIVATION.clusterArn || recovery.Condition?.ArnLike?.["ecs:task-definition"] !== "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:*") throw new Error("Normal activation and recovery update policies are broader than their separate service/cluster/revision contracts.");
  if (canonicalNormalActivationValue(expected).includes(`${NORMAL_ACTIVATION.family}:*`)) throw new Error("Normal activation policy must never authorize a wildcard candidate revision.");
  return true;
}

export function assertNormalActivationPolicyDeltaOnly(policy) {
  const normalized = structuredClone(normalizeIamPolicyDocument(policy, "current normal activation policy"));
  const statement = normalized.Statement?.filter(({ Sid }) => Sid === "ActivateBackendCandidate");
  const currentTarget = statement?.[0]?.Condition?.ArnEquals?.["ecs:task-definition"];
  if (statement?.length !== 1 || !NORMAL_CANDIDATE_ARN.test(currentTarget || "") || canonicalNormalActivationValue(normalized) !== canonicalNormalActivationValue(buildNormalActivationPolicy(currentTarget))) throw new Error("FinalApplyWrite policy contains changes outside the exact normal candidate revision binding.");
  return currentTarget;
}
