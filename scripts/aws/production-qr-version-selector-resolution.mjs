import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import JSZip from "jszip";
import { parseEcsSecretsManagerReference } from "./production-ecs-runtime-dependencies.mjs";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";

export const QR_VERSION_SELECTOR_RESOLUTION = Object.freeze({
  operation: "READ_ONLY_QR_VERSION_SELECTOR_RESOLUTION",
  purpose: "LEGACY_ROTATION_BASELINE_READ_ONLY_DERIVATION",
  account: "368992683803",
  region: "eu-west-2",
  cluster: "mscqr-prod-euw2-main",
  service: "mscqr-backend-servi-euw2",
  container: "backend",
  environment: "production-bootstrap-operator-policy-authorization",
  workflowPath: ".github/workflows/resolve-production-qr-version-selector.yml",
  workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/resolve-production-qr-version-selector.yml@refs/heads/main",
  artifactName: "production-qr-version-selector-resolution",
  secretName: /^arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr\/prod\/rotation\/qr-current-version-[A-Za-z0-9]{6}$/,
});

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const QR_VERSION = /^[A-Za-z0-9._-]{1,64}$/;
const digest = (value) => crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
const taskDefinitionDigest = (value) => crypto.createHash("sha256").update(canonicalJson(normalizeTaskDefinition(value))).digest("hex");
function normalizeTaskDefinition(value, key) {
  if (value instanceof Date) return value.toISOString();
  if (key === "registeredAt" || key === "deregisteredAt") {
    if (value === undefined) return undefined;
    const timestamp = typeof value === "string" || value instanceof Date ? new Date(value) : null;
    if (!timestamp || !Number.isFinite(timestamp.getTime())) throw new Error("Task-definition timestamp is malformed.");
    return timestamp.toISOString();
  }
  if (Array.isArray(value)) return value.map((item) => normalizeTaskDefinition(item));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined).map(([childKey, item]) => [childKey, normalizeTaskDefinition(item, childKey)]));
  return value;
}

export function readGitHubApiToken({ env = process.env, run = (args) => execFileSync("gh", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) } = {}) {
  const token = env.GITHUB_TOKEN || run(["auth", "token"]).trim();
  if (!token) throw new Error("Authenticated GitHub access is required to consume QR version resolution evidence.");
  return token;
}

export function buildQrVersionReadSessionPolicy(secretArn) {
  if (!QR_VERSION_SELECTOR_RESOLUTION.secretName.test(secretArn || "")) throw new Error("QR version read session policy target is outside the production contract.");
  return Object.freeze({ Version: "2012-10-17", Statement: [
    { Effect: "Allow", Action: "sts:GetCallerIdentity", Resource: "*" },
    { Effect: "Allow", Action: "ecs:DescribeServices", Resource: `arn:aws:ecs:${QR_VERSION_SELECTOR_RESOLUTION.region}:${QR_VERSION_SELECTOR_RESOLUTION.account}:service/${QR_VERSION_SELECTOR_RESOLUTION.cluster}/${QR_VERSION_SELECTOR_RESOLUTION.service}`, Condition: { StringEquals: { "aws:RequestedRegion": QR_VERSION_SELECTOR_RESOLUTION.region } } },
    { Effect: "Allow", Action: "ecs:DescribeTaskDefinition", Resource: [`arn:aws:ecs:${QR_VERSION_SELECTOR_RESOLUTION.region}:${QR_VERSION_SELECTOR_RESOLUTION.account}:task-definition/mscqr-production-rls-green-backend-candidate:*`, `arn:aws:ecs:${QR_VERSION_SELECTOR_RESOLUTION.region}:${QR_VERSION_SELECTOR_RESOLUTION.account}:task-definition/mscqr-backend:*`], Condition: { StringEquals: { "aws:RequestedRegion": QR_VERSION_SELECTOR_RESOLUTION.region } } },
    { Effect: "Allow", Action: "secretsmanager:GetSecretValue", Resource: secretArn, Condition: { StringEquals: { "aws:RequestedRegion": QR_VERSION_SELECTOR_RESOLUTION.region } } },
    { Effect: "Allow", Action: "secretsmanager:DescribeSecret", Resource: secretArn, Condition: { StringEquals: { "aws:RequestedRegion": QR_VERSION_SELECTOR_RESOLUTION.region } } },
  ] });
}

export function assertQrVersionSelector({ taskDefinition, expectedSecretArn } = {}) {
  if (!QR_VERSION_SELECTOR_RESOLUTION.secretName.test(expectedSecretArn || "")) throw new Error("Authorized QR version secret identity is outside the production contract.");
  const definition = taskDefinition?.taskDefinition || taskDefinition;
  const taskDefinitionArn = definition?.taskDefinitionArn;
  const backends = definition?.containerDefinitions?.filter(({ name }) => name === QR_VERSION_SELECTOR_RESOLUTION.container) || [];
  if (!/^arn:aws:ecs:eu-west-2:368992683803:task-definition\/[A-Za-z0-9_-]+:[1-9][0-9]*$/.test(taskDefinitionArn || "") || backends.length !== 1) throw new Error("Live backend task-definition identity is invalid.");
  const matches = (backends[0].secrets || []).filter(({ name }) => name === "QR_SIGN_ACTIVE_KEY_VERSION");
  if (matches.length !== 1) throw new Error("Live QR active-version secret binding is missing or ambiguous.");
  let selector;
  try { selector = parseEcsSecretsManagerReference(matches[0].valueFrom); } catch { throw new Error("Live QR active-version secret selector is malformed."); }
  if (selector.resource !== expectedSecretArn || selector.jsonKey !== "value" || selector.versionStage || selector.versionId || selector.selectorMode !== "AWSCURRENT") throw new Error("Live QR active-version selector does not match the exact authorized default-current binding.");
  return Object.freeze({ taskDefinitionArn, taskDefinitionSha256: taskDefinitionDigest(definition), secretArn: selector.resource, jsonKey: selector.jsonKey, versionSemantics: "AWSCURRENT" });
}

export function assertQrVersionResolutionCurrent({ taskDefinition, resolution, secretMetadata } = {}) {
  const binding = assertQrVersionSelector({ taskDefinition, expectedSecretArn: resolution?.secretArn });
  const current = Object.entries(secretMetadata?.VersionIdsToStages || {}).filter(([, stages]) => Array.isArray(stages) && stages.includes("AWSCURRENT"));
  if (resolution?.taskDefinitionArn !== binding.taskDefinitionArn || resolution?.taskDefinitionSha256 !== binding.taskDefinitionSha256 || resolution?.versionId !== current[0]?.[0] || current.length !== 1 || secretMetadata?.ARN !== binding.secretArn) throw new Error("QR version resolution no longer matches the live task definition and AWSCURRENT secret version.");
  return true;
}

export function resolveQrVersionSelectorValue({ response, binding } = {}) {
  if (!binding || !QR_VERSION_SELECTOR_RESOLUTION.secretName.test(binding.secretArn || "") || binding.jsonKey !== "value" || binding.versionSemantics !== "AWSCURRENT") throw new Error("QR version selector authorization binding is invalid.");
  if (response?.ARN !== binding.secretArn || typeof response.SecretString !== "string" || !Array.isArray(response.VersionStages) || response.VersionStages.length !== 1 || response.VersionStages[0] !== "AWSCURRENT" || !/^[A-Za-z0-9_-]{32,64}$/.test(response.VersionId || "")) throw new Error("QR version secret response identity or stage is invalid.");
  let parsed;
  try { parsed = JSON.parse(response.SecretString); } catch { throw new Error("QR version secret JSON is malformed."); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || typeof parsed.value !== "string" || !QR_VERSION.test(parsed.value)) throw new Error("QR active key-version identifier is invalid.");
  return Object.freeze({ ...binding, versionId: response.VersionId, qrCurrentVersion: parsed.value });
}

export function assertQrVersionResolutionEvidence(value, { sourceSha, changeTicket, expectedSecretArn, now = new Date() } = {}) {
  const fields = ["schemaVersion", "kind", "operation", "purpose", "sourceSha", "changeTicket", "account", "region", "secretArn", "jsonKey", "versionSemantics", "taskDefinitionArn", "taskDefinitionSha256", "versionId", "qrCurrentVersion", "workflowRunId", "workflowRunAttempt", "createdAt", "evidenceSha256"];
  if (!value || Object.keys(value).sort().join(",") !== [...fields].sort().join(",") || value.schemaVersion !== 1 || value.kind !== "PRODUCTION_QR_VERSION_SELECTOR_RESOLUTION" || value.operation !== QR_VERSION_SELECTOR_RESOLUTION.operation || value.purpose !== QR_VERSION_SELECTOR_RESOLUTION.purpose || value.sourceSha !== sourceSha || !SHA40.test(sourceSha || "") || value.changeTicket !== changeTicket || !/^CHG-[A-Za-z0-9-]{6,64}$/.test(changeTicket || "") || value.account !== QR_VERSION_SELECTOR_RESOLUTION.account || value.region !== QR_VERSION_SELECTOR_RESOLUTION.region || value.secretArn !== expectedSecretArn || !QR_VERSION_SELECTOR_RESOLUTION.secretName.test(value.secretArn || "") || value.jsonKey !== "value" || value.versionSemantics !== "AWSCURRENT" || !/^arn:aws:ecs:eu-west-2:368992683803:task-definition\/[A-Za-z0-9_-]+:[1-9][0-9]*$/.test(value.taskDefinitionArn || "") || !SHA256.test(value.taskDefinitionSha256 || "") || !/^[A-Za-z0-9_-]{32,64}$/.test(value.versionId || "") || !QR_VERSION.test(value.qrCurrentVersion || "") || !/^[1-9][0-9]*$/.test(value.workflowRunId || "") || value.workflowRunAttempt !== "1" || typeof value.createdAt !== "string") throw new Error("QR version resolution evidence binding is invalid.");
  const body = { ...value }; delete body.evidenceSha256;
  if (value.evidenceSha256 !== digest(body)) throw new Error("QR version resolution evidence digest is invalid.");
  const created = Date.parse(value.createdAt); const current = now instanceof Date ? now.getTime() : Date.parse(now);
  if (!Number.isFinite(created) || !Number.isFinite(current) || created > current || current - created > 30 * 60 * 1000) throw new Error("QR version resolution evidence is stale.");
  return value;
}

export function createQrVersionResolutionEvidence({ binding, resolved, sourceSha, changeTicket, workflowRunId, createdAt = new Date().toISOString() } = {}) {
  if (!SHA40.test(sourceSha || "") || !/^CHG-[A-Za-z0-9-]{6,64}$/.test(changeTicket || "") || !/^[1-9][0-9]*$/.test(workflowRunId || "") || resolved?.secretArn !== binding?.secretArn || !QR_VERSION.test(resolved?.qrCurrentVersion || "")) throw new Error("QR version resolution inputs are incomplete.");
  const body = { schemaVersion: 1, kind: "PRODUCTION_QR_VERSION_SELECTOR_RESOLUTION", operation: QR_VERSION_SELECTOR_RESOLUTION.operation, purpose: QR_VERSION_SELECTOR_RESOLUTION.purpose, sourceSha, changeTicket, account: QR_VERSION_SELECTOR_RESOLUTION.account, region: QR_VERSION_SELECTOR_RESOLUTION.region, secretArn: binding.secretArn, jsonKey: binding.jsonKey, versionSemantics: binding.versionSemantics, taskDefinitionArn: binding.taskDefinitionArn, taskDefinitionSha256: binding.taskDefinitionSha256, versionId: resolved.versionId, qrCurrentVersion: resolved.qrCurrentVersion, workflowRunId, workflowRunAttempt: "1", createdAt };
  return Object.freeze({ ...body, evidenceSha256: digest(body) });
}

export async function resolveQrVersionResolutionArtifact({ workflowRunId, sourceSha, changeTicket, expectedSecretArn, taskDefinition, secretMetadata, token, fetchImpl = fetch, now = new Date() } = {}) {
  if (!/^[1-9][0-9]*$/.test(workflowRunId || "") || typeof token !== "string" || !token || typeof fetchImpl !== "function" || !taskDefinition || !secretMetadata) throw new Error("QR version resolution artifact coordinates and fresh live bindings are required.");
  const base = "https://api.github.com/repos/T-ej2003/genuine-scan-main";
  const headers = { accept: "application/vnd.github+json", authorization: `Bearer ${token}`, "x-github-api-version": "2022-11-28" };
  const read = async (url) => { const response = await fetchImpl(url, { headers }); if (!response.ok) throw new Error("QR version resolution artifact could not be authenticated."); return response; };
  const runResponse = await read(`${base}/actions/runs/${workflowRunId}`);
  const workflow = await runResponse.json();
  if (String(workflow.id) !== workflowRunId || workflow.path !== QR_VERSION_SELECTOR_RESOLUTION.workflowPath || workflow.repository?.full_name !== "T-ej2003/genuine-scan-main" || workflow.head_repository?.full_name !== "T-ej2003/genuine-scan-main" || workflow.event !== "workflow_dispatch" || workflow.head_sha !== sourceSha || workflow.status !== "completed" || workflow.conclusion !== "success" || String(workflow.run_attempt) !== "1") throw new Error("QR version resolution workflow provenance is invalid.");
  const artifactResponse = await read(`${base}/actions/runs/${workflowRunId}/artifacts?per_page=100`);
  const artifacts = (await artifactResponse.json()).artifacts;
  const matches = artifacts?.filter((artifact) => artifact.name === QR_VERSION_SELECTOR_RESOLUTION.artifactName && artifact.expired === false && String(artifact.workflow_run?.id) === workflowRunId && artifact.workflow_run?.head_sha === sourceSha && /^sha256:[a-f0-9]{64}$/.test(artifact.digest || "")) || [];
  if (matches.length !== 1 || artifacts.length !== 1) throw new Error("QR version resolution artifact inventory is missing, duplicate, or unexpected.");
  const archiveResponse = await read(`${base}/actions/artifacts/${matches[0].id}/zip`);
  const archive = Buffer.from(await archiveResponse.arrayBuffer());
  if (archive.length > 1024 * 1024 || `sha256:${crypto.createHash("sha256").update(archive).digest("hex")}` !== matches[0].digest) throw new Error("QR version resolution artifact digest is invalid.");
  const zip = await JSZip.loadAsync(archive, { checkCRC32: true });
  const entries = Object.values(zip.files).filter(({ dir }) => !dir);
  const fileMode = entries[0]?.unixPermissions;
  const mode = typeof fileMode === "number" ? fileMode : Number.parseInt(String(fileMode || "0"), 8);
  if (Object.keys(zip.files).length !== 1 || entries.length !== 1 || entries[0].name !== "resolution.json" || (mode & 0o170000) === 0o120000) throw new Error("QR version resolution artifact contents are not exact.");
  let evidence;
  try { evidence = JSON.parse(await entries[0].async("string")); } catch { throw new Error("QR version resolution artifact payload is malformed."); }
  assertQrVersionResolutionEvidence(evidence, { sourceSha, changeTicket, expectedSecretArn, now });
  if (evidence.workflowRunId !== workflowRunId) throw new Error("QR version resolution artifact run binding is invalid.");
  assertQrVersionResolutionCurrent({ taskDefinition, resolution: evidence, secretMetadata });
  return evidence;
}
