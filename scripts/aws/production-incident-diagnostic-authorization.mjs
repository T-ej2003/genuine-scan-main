#!/usr/bin/env node
// One incident, one source-bound approval. The launcher must verify this artifact against the actual GitHub run.
import fs from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import JSZip from "jszip";
import { canonicalSha256, canonicalJson } from "./stage-b-task-definition-recovery-contract.mjs";
import { createProductionGithubCommandRunner } from "./production-credential-source-contract.mjs";
import { readAuthenticatedGitHubProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { assertProductionEnvironmentApprovalIdentity, assertProductionEnvironmentActualReviewer,
  assertProductionEnvironmentApprovalFreshness, PRODUCTION_ENVIRONMENT_APPROVAL } from "./production-github-environment-approval.mjs";
import { buildIncidentDiagnosticSql } from "../../backend/scripts/production-incident-diagnostic-sql.mjs";
import { INCIDENT_DATABASE, INCIDENT_SCOPE, INCIDENT_SOURCE_SHA } from "../../backend/scripts/production-incident-diagnostic-queries.mjs";

const workflowRef = "T-ej2003/genuine-scan-main/.github/workflows/authorize-production-incident-diagnostic.yml@refs/heads/main";
const bucket = "mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an";
const sha40 = /^[a-f0-9]{40}$/;
const imageDigest = /^sha256:[a-f0-9]{64}$/;
const uuid = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/;
const byteSha256 = (value) => createHash("sha256").update(value).digest("hex");
const exactFields = (value, fields) => value && !Array.isArray(value) && canonicalJson(Object.keys(value).sort()) === canonicalJson([...fields].sort());

export async function verifyIncidentImagePublication({ runId, sourceSha, image, run = createProductionGithubCommandRunner() } = {}) {
  if (!/^[1-9][0-9]*$/.test(String(runId || "")) || !sha40.test(sourceSha || "") || !imageDigest.test(image || "")) throw new Error("Diagnostic image publication coordinates are invalid.");
  const repository = "T-ej2003/genuine-scan-main";
  const workflow = JSON.parse(run("gh", ["api", `repos/${repository}/actions/runs/${runId}`]));
  if (String(workflow.id) !== String(runId) || workflow.repository?.full_name !== repository
      || workflow.head_repository?.full_name !== repository || workflow.head_sha !== sourceSha
      || workflow.path !== ".github/workflows/production-green-backend-image-publish.yml"
      || workflow.event !== "workflow_dispatch" || workflow.status !== "completed" || workflow.conclusion !== "success") throw new Error("Diagnostic image publication workflow is invalid.");
  const listing = JSON.parse(run("gh", ["api", `repos/${repository}/actions/runs/${runId}/artifacts`, "--paginate", "--slurp"]));
  const artifacts = (Array.isArray(listing) ? listing.flatMap((page) => page.artifacts || []) : []).filter((item) =>
    item.name === "production-green-backend-image-evidence" && item.expired === false
    && String(item.workflow_run?.id) === String(runId) && item.workflow_run?.head_sha === sourceSha
    && item.workflow_run?.repository_id === workflow.repository.id && /^sha256:[a-f0-9]{64}$/.test(item.digest || ""));
  if (artifacts.length !== 1) throw new Error("Exactly one diagnostic image publication artifact is required.");
  const bytes = Buffer.from(run("gh", ["api", `repos/${repository}/actions/artifacts/${artifacts[0].id}/zip`], { encoding: null }));
  if (`sha256:${byteSha256(bytes)}` !== artifacts[0].digest) throw new Error("Diagnostic image publication archive digest is invalid.");
  const archive = await JSZip.loadAsync(bytes);
  const read = async (name) => {
    const entry = archive.file(name);
    if (!entry || entry.dir) throw new Error(`Diagnostic image publication lacks ${name}.`);
    return entry.async("string");
  };
  const records = (await read("production-green-backend-image.jsonl")).trim().split("\n").map(JSON.parse);
  const ref = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${image}`;
  if (records.length !== 1 || records[0].service !== "backend" || records[0].image_tag !== `${sourceSha}-backend-only` || records[0].image_ref !== ref) throw new Error("Diagnostic image publication does not bind the exact backend-only digest.");
  const inspected = JSON.parse(await read("backend-image-inspect.json"));
  const labels = inspected?.[0]?.Config?.Labels || {};
  const env = inspected?.[0]?.Config?.Env || [];
  const provenance = JSON.parse(await read("backend.provenance.json"));
  if (inspected.length !== 1 || labels["org.opencontainers.image.revision"] !== sourceSha
      || !env.includes(`GIT_SHA=${sourceSha}`) || !env.includes(`RELEASE_GIT_SHA=${sourceSha}`)
      || provenance.subject?.imageRef !== ref || provenance.invocation?.sha !== sourceSha
      || String(provenance.invocation?.runId) !== String(runId)) throw new Error("Diagnostic image labels or provenance are invalid.");
  return Object.freeze({ runId: String(runId), artifactId: artifacts[0].id,
    artifactDigest: artifacts[0].digest, sourceSha, image });
}

export function incidentJournalPolicy({ executionId, expiresAt }) {
  if (!uuid.test(executionId || "") || !Number.isFinite(Date.parse(expiresAt))) throw new Error("Journal scope is invalid.");
  const resource = ["reservation.json", "terminal.json"].map((name) => `arn:aws:s3:::${bucket}/production-incident-20261112/${executionId}/${name}`);
  return Object.freeze({ Version: "2012-10-17", Statement: [
    { Sid: "WriteOneIncidentJournal", Effect: "Allow", Action: "s3:PutObject", Resource: resource,
      Condition: { StringEquals: { "s3:x-amz-server-side-encryption": "AES256" }, DateLessThan: { "aws:CurrentTime": expiresAt } } },
    { Sid: "ReadBackOneIncidentJournal", Effect: "Allow", Action: "s3:GetObject", Resource: resource,
      Condition: { DateLessThan: { "aws:CurrentTime": expiresAt } } },
  ] });
}

export function incidentSecretPolicy({ expiresAt }) {
  if (!Number.isFinite(Date.parse(expiresAt))) throw new Error("Secret capability expiry is invalid.");
  return Object.freeze({ Version: "2012-10-17", Statement: [{ Sid: "ReadOnlyExactIncidentCanaryCredential",
    Effect: "Allow", Action: "secretsmanager:GetSecretValue",
    Resource: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase4/read-only-canary-database-url-rR3kri",
    Condition: { DateLessThan: { "aws:CurrentTime": expiresAt } } }] });
}

export function incidentTaskTemplate({ image } = {}) {
  if (!imageDigest.test(image || "")) throw new Error("Diagnostic image digest is invalid.");
  return Object.freeze({ family: "mscqr-production-incident-20261112-read-only", cpu: "256", memory: "512",
    networkMode: "awsvpc", requiresCompatibilities: ["FARGATE"],
    runtimePlatform: { cpuArchitecture: "X86_64", operatingSystemFamily: "LINUX" },
    executionRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-executor-execution",
    taskRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-task",
    containerDefinitions: [{ name: "incident-20261112-read-only", image: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${image}`,
      essential: true, readonlyRootFilesystem: true, portMappings: [], entryPoint: ["node", "scripts/production-incident-diagnostic-task.mjs"],
      command: [], secrets: [
        { name: "RLS_CANARY_DATABASE_URL", valueFrom: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase4/read-only-canary-database-url-rR3kri" },
        { name: "MSCQR_INCIDENT_ADMIN_PASSWORD", valueFrom: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:rds!db-70d459ec-4f6f-45da-aafc-618e83d660a1-Dy9GLo:password::" },
      ],
      environment: [], logConfiguration: { logDriver: "awslogs", options: { "awslogs-group": "/ecs/mscqr-production/full-rls-green", "awslogs-region": "eu-west-2", "awslogs-stream-prefix": "incident-20261112" } } }] });
}

export function incidentTaskDefinition(authorization) {
  const template = incidentTaskTemplate({ image: authorization.image });
  const runtime = { account: authorization.account, region: authorization.region, sourceSha: authorization.sourceSha,
    diagnosticSourceSha: authorization.diagnosticSourceSha, database: authorization.database,
    executionId: authorization.executionId, issuedAt: authorization.issuedAt, expiresAt: authorization.expiresAt,
    approvalEvidenceSha256: authorization.approvalEvidenceSha256, provisionSha256: authorization.provisionSha256,
    querySha256: authorization.querySha256, teardownSha256: authorization.teardownSha256 };
  return { ...template, containerDefinitions: [{ ...template.containerDefinitions[0], environment: [
    { name: "MSCQR_INCIDENT_DIAGNOSTIC_AUTHORIZATION", value: JSON.stringify(runtime) },
  ] }] };
}

export function createIncidentDiagnosticAuthorization({ diagnosticSourceSha, image, imagePublication, executionId = randomUUID(), approvalEvidence,
  issuedAt = new Date().toISOString() } = {}) {
  if (!sha40.test(diagnosticSourceSha || "") || !imageDigest.test(image || "") || !uuid.test(executionId || "")) throw new Error("Diagnostic source, image, or execution identity is invalid.");
  assertProductionEnvironmentApprovalIdentity(approvalEvidence, { sourceSha: diagnosticSourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository });
  if (approvalEvidence.workflowRef !== workflowRef || approvalEvidence.schemaVersion !== 3) throw new Error("Diagnostic requires its own protected workflow approval.");
  const approvedBy = assertProductionEnvironmentActualReviewer(approvalEvidence, { sourceSha: diagnosticSourceSha,
    repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, executionActor: approvalEvidence.executionActor });
  assertProductionEnvironmentApprovalFreshness(approvalEvidence, { now: new Date(issuedAt) });
  if (!imagePublication || imagePublication.sourceSha !== diagnosticSourceSha || imagePublication.image !== image
      || !/^[1-9][0-9]*$/.test(String(imagePublication.runId || ""))
      || !Number.isSafeInteger(imagePublication.artifactId) || imagePublication.artifactId < 1
      || !/^sha256:[a-f0-9]{64}$/.test(imagePublication.artifactDigest || "")) throw new Error("Diagnostic image publication is not authenticated.");
  const expiresAt = new Date(Date.parse(issuedAt) + 30 * 60 * 1000).toISOString();
  const sql = buildIncidentDiagnosticSql({ executionId, issuedAt, expiresAt });
  const body = { schemaVersion: 1, kind: "PRODUCTION_INCIDENT_20261112_DIAGNOSTIC_AUTHORIZATION", operation: "READ_ONLY_INCIDENT_DIAGNOSTIC",
    repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, sourceSha: INCIDENT_SOURCE_SHA, diagnosticSourceSha, image,
    account: "368992683803", region: "eu-west-2", database: INCIDENT_DATABASE,
    databaseInstance: "mscqr-production-rls-green-phase2", databaseResourceId: "db-3C27FYJOJ2IY27X7QGQG5YB4IM",
    databaseHostname: "mscqr-production-rls-green-phase2.c3ewey6o6mq5.eu-west-2.rds.amazonaws.com",
    databaseVersion: "18.4", executionId, scope: { ...INCIDENT_SCOPE,
      printCreateRequestId: "970e5ca7-19d3-46bb-a05d-e8533def35be",
      testLabelRequestId: "dc0d47a4-e71e-436b-aa95-396fd29208f7" },
    issuedAt, expiresAt, provisionSha256: byteSha256(sql.provision), querySha256: byteSha256(sql.query),
    teardownSha256: byteSha256(sql.teardown), journalPolicy: incidentJournalPolicy({ executionId, expiresAt }),
    executionSecretPolicy: incidentSecretPolicy({ expiresAt }),
    taskTemplateSha256: canonicalSha256(incidentTaskTemplate({ image })),
    imagePublication, approvalEvidence, approvalEvidenceSha256: approvalEvidence.evidenceSha256, approvedBy };
  const exact = { ...body, taskDefinitionSha256: canonicalSha256(incidentTaskDefinition(body)) };
  return Object.freeze({ ...exact, authorizationSha256: canonicalSha256(exact) });
}

export function assertIncidentDiagnosticAuthorization(value, { now = new Date() } = {}) {
  const fields = ["schemaVersion", "kind", "operation", "repository", "sourceSha", "diagnosticSourceSha", "image", "imagePublication", "account", "region", "database", "databaseInstance", "databaseResourceId", "databaseHostname", "databaseVersion", "executionId", "scope", "issuedAt", "expiresAt", "provisionSha256", "querySha256", "teardownSha256", "journalPolicy", "executionSecretPolicy", "taskTemplateSha256", "taskDefinitionSha256", "approvalEvidence", "approvalEvidenceSha256", "approvedBy", "authorizationSha256"];
  if (!exactFields(value, fields) || value.schemaVersion !== 1 || value.kind !== "PRODUCTION_INCIDENT_20261112_DIAGNOSTIC_AUTHORIZATION"
      || value.operation !== "READ_ONLY_INCIDENT_DIAGNOSTIC" || value.repository !== PRODUCTION_ENVIRONMENT_APPROVAL.repository
      || value.sourceSha !== INCIDENT_SOURCE_SHA || !sha40.test(value.diagnosticSourceSha || "") || !imageDigest.test(value.image || "")
      || value.account !== "368992683803" || value.region !== "eu-west-2" || value.database !== INCIDENT_DATABASE
      || value.imagePublication?.sourceSha !== value.diagnosticSourceSha || value.imagePublication?.image !== value.image
      || !/^[1-9][0-9]*$/.test(String(value.imagePublication?.runId || ""))
      || !Number.isSafeInteger(value.imagePublication?.artifactId) || value.imagePublication.artifactId < 1
      || !/^sha256:[a-f0-9]{64}$/.test(value.imagePublication?.artifactDigest || "")
      || value.databaseInstance !== "mscqr-production-rls-green-phase2" || value.databaseResourceId !== "db-3C27FYJOJ2IY27X7QGQG5YB4IM"
      || value.databaseHostname !== "mscqr-production-rls-green-phase2.c3ewey6o6mq5.eu-west-2.rds.amazonaws.com" || value.databaseVersion !== "18.4"
      || !uuid.test(value.executionId || "")
      || Date.parse(value.issuedAt) > now.getTime() || now.getTime() >= Date.parse(value.expiresAt)
      || Date.parse(value.expiresAt) - Date.parse(value.issuedAt) !== 30 * 60 * 1000
      || value.approvalEvidenceSha256 !== value.approvalEvidence?.evidenceSha256
      || canonicalJson(value.scope) !== canonicalJson({ ...INCIDENT_SCOPE,
        printCreateRequestId: "970e5ca7-19d3-46bb-a05d-e8533def35be",
        testLabelRequestId: "dc0d47a4-e71e-436b-aa95-396fd29208f7" })
      || canonicalJson(value.journalPolicy) !== canonicalJson(incidentJournalPolicy(value))
      || canonicalJson(value.executionSecretPolicy) !== canonicalJson(incidentSecretPolicy(value))
      || value.taskTemplateSha256 !== canonicalSha256(incidentTaskTemplate({ image: value.image }))
      || value.taskDefinitionSha256 !== canonicalSha256(incidentTaskDefinition(value))
      || canonicalSha256(Object.fromEntries(Object.entries(value).filter(([key]) => key !== "authorizationSha256"))) !== value.authorizationSha256) throw new Error("Diagnostic authorization is expired or altered.");
  const sql = buildIncidentDiagnosticSql(value);
  if (value.provisionSha256 !== byteSha256(sql.provision) || value.querySha256 !== byteSha256(sql.query)
      || value.teardownSha256 !== byteSha256(sql.teardown)) throw new Error("Diagnostic SQL package is not authorized.");
  assertProductionEnvironmentApprovalIdentity(value.approvalEvidence, { sourceSha: value.diagnosticSourceSha, repository: value.repository });
  if (value.approvalEvidence.workflowRef !== workflowRef || value.approvalEvidence.schemaVersion !== 3
      || assertProductionEnvironmentActualReviewer(value.approvalEvidence, { sourceSha: value.diagnosticSourceSha,
        repository: value.repository, executionActor: value.approvalEvidence.executionActor }) !== value.approvedBy) throw new Error("Diagnostic reviewer is not authenticated.");
  assertProductionEnvironmentApprovalFreshness(value.approvalEvidence, { now });
  return value;
}

export async function resolveIncidentDiagnosticAuthorization({ runId, attempt = "1", sourceSha, run = createProductionGithubCommandRunner(), now = new Date() } = {}) {
  if (!/^[1-9][0-9]*$/.test(String(runId || "")) || !/^[1-9][0-9]*$/.test(String(attempt || "")) || !sha40.test(sourceSha || "")) throw new Error("Diagnostic workflow coordinates are invalid.");
  const repository = "T-ej2003/genuine-scan-main";
  readAuthenticatedGitHubProtectedMainIdentity({ expectedSourceSha: sourceSha, githubRun: run });
  const workflow = JSON.parse(run("gh", ["api", `repos/${repository}/actions/runs/${runId}`]));
  if (String(workflow.id) !== String(runId) || workflow.repository?.full_name !== repository
      || workflow.head_repository?.full_name !== repository
      || workflow.path !== ".github/workflows/authorize-production-incident-diagnostic.yml"
      || workflow.head_sha !== sourceSha || workflow.event !== "workflow_dispatch"
      || workflow.status !== "completed" || workflow.conclusion !== "success"
      || String(workflow.run_attempt) !== String(attempt)) throw new Error("Diagnostic workflow provenance is invalid.");
  const listing = JSON.parse(run("gh", ["api", `repos/${repository}/actions/runs/${runId}/artifacts`, "--paginate", "--slurp"]));
  const artifacts = (Array.isArray(listing) ? listing.flatMap((page) => page.artifacts || []) : []).filter((item) =>
    item.name === "production-incident-20261112-diagnostic-authorization" && item.expired === false
    && String(item.workflow_run?.id) === String(runId) && item.workflow_run?.head_sha === sourceSha
    && item.workflow_run?.repository_id === workflow.repository.id && /^sha256:[a-f0-9]{64}$/.test(item.digest || ""));
  if (artifacts.length !== 1) throw new Error("Exactly one fresh diagnostic authorization artifact is required.");
  const bytes = Buffer.from(run("gh", ["api", `repos/${repository}/actions/artifacts/${artifacts[0].id}/zip`], { encoding: null }));
  if (`sha256:${byteSha256(bytes)}` !== artifacts[0].digest) throw new Error("Diagnostic artifact archive digest is invalid.");
  const archive = await JSZip.loadAsync(bytes);
  const entries = Object.values(archive.files).filter((entry) => !entry.dir);
  if (entries.length !== 1 || entries[0].name !== "authorization.json") throw new Error("Diagnostic artifact contents are invalid.");
  const authorization = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await entries[0].async("uint8array")));
  assertIncidentDiagnosticAuthorization(authorization, { now });
  if (authorization.diagnosticSourceSha !== sourceSha
      || String(authorization.approvalEvidence.workflowRunId) !== String(runId)
      || String(authorization.approvalEvidence.workflowRunAttempt) !== String(attempt)) throw new Error("Diagnostic approval run is not bound to this artifact.");
  const publication = await verifyIncidentImagePublication({ runId: authorization.imagePublication.runId,
    sourceSha, image: authorization.image, run });
  if (canonicalJson(publication) !== canonicalJson(authorization.imagePublication)) throw new Error("Diagnostic image publication has changed.");
  return { authorization, workflow, artifact: artifacts[0] };
}

if (import.meta.url === new URL(process.argv[1], "file:").href) {
  const [approvalPath, sourceSha, image, publicationRunId, executionId, outputPath] = process.argv.slice(2);
  if (!approvalPath || !outputPath || process.argv.length !== 8) throw new Error("Exact approval, source, image, publication run, execution ID, and output paths are required.");
  const approvalEvidence = JSON.parse(fs.readFileSync(approvalPath, "utf8"));
  const imagePublication = await verifyIncidentImagePublication({ runId: publicationRunId, sourceSha, image });
  const value = createIncidentDiagnosticAuthorization({ approvalEvidence, diagnosticSourceSha: sourceSha, image, imagePublication, executionId });
  fs.writeFileSync(outputPath, `${canonicalJson(value)}\n`, { mode: 0o600, flag: "wx" });
}
