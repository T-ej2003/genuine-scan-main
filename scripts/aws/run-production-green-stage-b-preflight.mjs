#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { runReleaseReadPreflight } from "./production-green-stage-b-identity-capabilities.mjs";
import { assertStageBDeploymentCapabilityGraph } from "./generate-production-green-stage-b-capability-graph.mjs";
import { generateStageBTerraformBackendConfig } from "./generate-production-green-stage-b-backend-config.mjs";
import { assertStageBTerraformInitializedBackendMetadata, ensureStageBTerraformBackendMetadataPrivate } from "./stage-b-terraform-backend-contract.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, writeStageBPrivateFileAtomic, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { assertStageBTerraformWorkspace } from "./stage-b-terraform-workspace.mjs";
import { generateStageAPrerequisites, STAGE_A_STATE_OBJECT } from "./generate-production-green-stage-a-prerequisites.mjs";
import { generateStageBTfvars } from "./generate-production-green-stage-b-tfvars.mjs";
import { resolveStageBRecoveryMode } from "./stage-b-deployment-contract.mjs";
import {
  ACCOUNT,
  APPROVED_PREFLIGHT_GENERATOR_ARNS,
  REGION,
  RELEASE_ROLE_ARN,
  assertReleasePolicyEvidence,
  canonicalizeJson,
  collectLiveReleasePolicyEvidence,
  runPermissionPreflight,
  simulatePrincipalPolicy,
  operatorPolicyConditionKeyOrigins,
  sourcePolicyConditionKeyOrigins,
  assertCutoverCriticalEvidence,
  assertStageBPermissionEvidenceKind,
  INITIAL_ADMINISTRATOR_CAPABILITY_EVIDENCE_KIND,
  signPermissionReport,
  createPermissionReportKmsSigner,
  verifyPermissionReportSignature,
  assertStageBAdministratorEvidenceIdentity,
} from "./validate-production-green-stage-b-permissions.mjs";
import { collectLiveEcsExecOperatorEvidence, ECS_EXEC_OPERATOR_ROLE_ARN } from "./production-ecs-exec-operator-contract.mjs";
import { assertStageARootDropKeyPolicySource } from "./production-stage-a-control-plane.mjs";
import { buildTemporaryCapabilityEvidence } from "./production-stage-a-temporary-kms-capability.mjs";
import { assertStageBDeploymentIdentityValues, readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { createProductionAwsCommandRunner, createProductionAwsCredentialEnvironment } from "./production-credential-source-contract.mjs";
import { imageEvidenceSha256, verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { assertImageAuthorization } from "./production-cutover-control-plane.mjs";
import { readStageBPrivateFileBytes } from "./stage-b-artifact-contract.mjs";
import { createAwsReader, observeStageBBrokerApprovalBindings } from "./production-green-stage-b-ecs-observations.mjs";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const SHA40 = /^[a-f0-9]{40}$/;
const readOption = (argv, name) => { const i = argv.indexOf(name); return i < 0 ? undefined : argv[i + 1]; };
const value = (argv, name) => { const result = readOption(argv, name); if (!result || result.startsWith("--")) throw new Error(`${name} is required.`); return result; };
const write = (output, document) => {
  const resolved = assertStageBArtifactPath({ artifactPath: output, repositoryRoot: root, label: "Production preflight output", allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(resolved), repositoryRoot: root, create: true });
  const written = writeStageBPrivateFileAtomic({ filePath: resolved, bytes: Buffer.from(`${JSON.stringify(document, null, 2)}\n`), repositoryRoot: root, label: "Production preflight output" });
  return { path: written.path, sha256: written.sha256 };
};
const writePair = (output, signatureOutput, document, signature) => {
  const outputPath = assertStageBArtifactPath({ artifactPath: output, repositoryRoot: root, label: "Production preflight output", allowExisting: false });
  const signaturePath = assertStageBArtifactPath({ artifactPath: signatureOutput, repositoryRoot: root, label: "Production preflight signature", allowExisting: false });
  if (path.dirname(outputPath) !== path.dirname(signaturePath)) throw new Error("Production preflight output and signature must use one private directory.");
  ensureStageBPrivateDirectory({ directory: path.dirname(outputPath), repositoryRoot: root, create: true });
  const [reportFile, signatureFile] = writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [
    { filePath: outputPath, bytes: Buffer.from(`${JSON.stringify(document, null, 2)}\n`), label: "Production preflight output" },
    { filePath: signaturePath, bytes: Buffer.from(`${JSON.stringify(signature, null, 2)}\n`), label: "Production preflight signature" },
  ] });
  return { report: reportFile, signature: signatureFile };
};
const readImageAuthorization = (filePath, expectedSha256, sourceSha, run, verifyImageEvidence = (options) => verifyImageEvidenceSignature({ ...options, run })) => {
  const file = readStageBPrivateFileBytes({ filePath, repositoryRoot: root, label: "Current image authorization" });
  if (file.sha256 !== expectedSha256) throw new Error("Current image authorization file SHA-256 does not match the supplied binding.");
  let authorization;
  try { authorization = JSON.parse(file.bytes); } catch (error) { throw new Error(`Current image authorization is not valid JSON: ${error.message}`); }
  assertImageAuthorization(authorization, sourceSha, { verifyImageEvidence });
  return { authorization, fileSha256: file.sha256 };
};

const readPrivateJson = (filePath, label) => {
  const file = readStageBPrivateFileBytes({ filePath, repositoryRoot: root, label });
  try { return { document: JSON.parse(file.bytes.toString("utf8")), bytes: file.bytes }; } catch (error) { throw new Error(`${label} is not valid JSON: ${error.message}`); }
};

function assertReadinessImageAuthorizationBinding(argv, authorization) {
  const expected = [
    ["--image-release-sha", authorization.imageReleaseSha],
    ["--workflow-run-id", authorization.workflowRunId],
    ["--canonical-artifact-sha256", authorization.imageEvidence?.canonicalArtifactSha256],
  ];
  for (const [option, expectedValue] of expected) if (value(argv, option) !== String(expectedValue)) throw new Error(`Release readiness ${option} does not match the authenticated image authorization.`);
  const evidence = readPrivateJson(value(argv, "--image-evidence"), "Current image evidence");
  if (imageEvidenceSha256(evidence.document) !== authorization.imageEvidenceSha256) throw new Error("Release readiness image evidence does not match the authenticated image authorization.");
  const signature = readPrivateJson(value(argv, "--image-evidence-signature"), "Current image-evidence signature");
  if (canonicalizeJson(signature.document) !== canonicalizeJson(authorization.imageEvidenceSignature)) throw new Error("Release readiness image-evidence signature does not match the authenticated image authorization.");
  return { imageEvidenceBytes: evidence.bytes, imageEvidenceSignatureBytes: signature.bytes };
}

function continueReleaseReadiness(argv, { run = (command, args, options) => execFileSync(command, args, options), imageEvidenceBytes, imageEvidenceSignatureBytes } = {}) {
  const backendConfig = value(argv, "--backend-config"); const terraformDataDir = value(argv, "--terraform-data-dir");
  const preflightDirectory = path.dirname(path.resolve(value(argv, "--output")));
  const stageAState = path.join(preflightDirectory, "stage-a-state.json"); const stageBState = path.join(preflightDirectory, "stage-b-state.json");
  const handoff = value(argv, "--stage-a-handoff"); const tfvars = value(argv, "--tfvars"); const bindingReport = value(argv, "--binding-report");
  const toolingSha = value(argv, "--tooling-sha"); const toolingTreeSha256 = value(argv, "--tooling-tree-sha256");
  const partialApplyRecovery = argv.includes("--partial-apply-recovery");
  const freshImagePartialApplyRecovery = argv.includes("--fresh-image-partial-apply-recovery");
  const recoveryMode = resolveStageBRecoveryMode({ recoveryOnly: false, partialApplyRecovery, freshImagePartialApplyRecovery });
  const releaseAwsRun = createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer", exec: (command, args, options) => run(command, args, options) });
  generateStageAPrerequisites({ stateBackup: stageAState, stateObject: STAGE_A_STATE_OBJECT, toolingSha, toolingTreeSha256, outputPath: handoff, phase: "POST_APPLY", run: (args) => releaseAwsRun(args) });
  const generated = generateStageBTfvars({
    imageEvidence: value(argv, "--image-evidence"), imageEvidenceSignature: value(argv, "--image-evidence-signature"), stateBackup: stageBState,
    imageEvidenceBytes, imageEvidenceSignatureBytes,
    stageAInput: handoff, stageAStateBackup: stageAState, brokerPackagePath: value(argv, "--broker-package"), toolingSha, toolingTreeSha256,
    imageReleaseSha: value(argv, "--image-release-sha"), workflowRunId: value(argv, "--workflow-run-id"), canonicalArtifactSha256: value(argv, "--canonical-artifact-sha256"),
    environment: "production", outputPath: tfvars, bindingReportPath: bindingReport, partialApplyRecovery, freshImagePartialApplyRecovery,
    verifySignature: (options) => verifyImageEvidenceSignature({ ...options, run: (args) => releaseAwsRun(args) }),
    ...(["PARTIAL_APPLY_RECOVERY", "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY"].includes(recoveryMode) ? { recovery: { refreshReportPath: value(argv, "--refresh-report"), observationBindingPath: value(argv, "--refresh-binding-report") } } : {}),
  });
  generateStageBTerraformBackendConfig({ outputPath: backendConfig });
  ensureStageBPrivateDirectory({ directory: terraformDataDir, repositoryRoot: root, create: true, normalize: true });
  const terraformRoot = path.join(root, "infra/aws/terraform/production-green-stage-b");
  const env = { ...createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer", region: REGION }), TF_DATA_DIR: terraformDataDir, TF_WORKSPACE: "default" };
  run("terraform", [`-chdir=${terraformRoot}`, "init", `-backend-config=${backendConfig}`, "-input=false", "-lockfile=readonly", "-no-color"], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const backendMetadata = ensureStageBTerraformBackendMetadataPrivate({ terraformDataDir, repositoryRoot: root, normalize: true });
  const metadata = JSON.parse(fs.readFileSync(backendMetadata.backendMetadataPath, "utf8")).backend;
  assertStageBTerraformInitializedBackendMetadata(metadata);
  const observedWorkspace = String(run("terraform", [`-chdir=${terraformRoot}`, "workspace", "show"], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })).trim();
  assertStageBTerraformWorkspace({ envWorkspace: env.TF_WORKSPACE, observedWorkspace });
  return { backendReady: true, stateReady: true, handoffReady: true, tfvarsReady: true, tfvarsSha256: generated.tfvarsSha256, bindingReportSha256: sha256(fs.readFileSync(generated.bindingReportPath)), ...backendMetadata };
}

export function runProductionPreflightCli(argv = process.argv.slice(2), dependencies = {}) {
  const identity = value(argv, "--identity");
  const profile = identity === "administrator" ? "default" : identity === "release-deployer" ? "mscqr-production-release-deployer" : undefined;
  const commandRun = dependencies.commandRun || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile });
  const caller = dependencies.caller || (() => JSON.parse(commandRun(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"])).Arn);
  const collectPolicies = dependencies.collectPolicies || (() => collectLiveReleasePolicyEvidence({ run: commandRun }));
  const collectEcsExecOperatorEvidence = dependencies.collectEcsExecOperatorEvidence || (() => collectLiveEcsExecOperatorEvidence({ run: commandRun }));
  const permissionPreflight = dependencies.permissionPreflight || runPermissionPreflight;
  const sign = dependencies.sign || createPermissionReportKmsSigner({ run: commandRun });
  const verify = dependencies.verify;
  const verifyImageEvidence = dependencies.verifyImageEvidence;
  const releasePreflight = dependencies.releasePreflight || runReleaseReadPreflight;
  const continueReadiness = dependencies.continueReadiness || ((args, publication) => continueReleaseReadiness(args, publication));
  const validateCapabilityGraph = dependencies.validateCapabilityGraph || assertStageBDeploymentCapabilityGraph;
  const readStageATerraformSource = dependencies.readStageATerraformSource || (() => fs.readFileSync(path.join(root, "infra/aws/terraform/production-green-stage-a/main.tf"), "utf8"));
  const readProtectedMainCheckout = dependencies.readProtectedMainCheckout || (() => readStageBProtectedMainCheckout({ cwd: root }));
  const output = value(argv, "--output"); const capabilityGraph = validateCapabilityGraph(); const observedCaller = caller();
  if (identity === "administrator") {
    if (value(argv, "--phase") !== "initial") throw new Error("Administrator capability preflight requires --phase initial.");
    if (!APPROVED_PREFLIGHT_GENERATOR_ARNS.includes(observedCaller)) throw new Error("Administrator production preflight requires the approved root identity.");
    if (argv.filter((argument) => argument === "--source-sha").length !== 1) throw new Error("Administrator production preflight requires exactly one --source-sha.");
    const sourceSha = value(argv, "--source-sha");
    if (!SHA40.test(sourceSha)) throw new Error("Administrator production preflight requires a full protected source SHA.");
    const protectedMain = readProtectedMainCheckout();
    if (!protectedMain || protectedMain.toolingSha !== sourceSha || protectedMain.currentHead !== sourceSha || protectedMain.originMainHead !== sourceSha || protectedMain.porcelainStatus) throw new Error("Administrator production preflight requires the exact clean protected-main source.");
    const imageAuthorizationFile = dependencies.readImageAuthorization
      ? dependencies.readImageAuthorization(value(argv, "--image-authorization"), value(argv, "--image-authorization-sha256"), sourceSha)
      : readImageAuthorization(value(argv, "--image-authorization"), value(argv, "--image-authorization-sha256"), sourceSha, commandRun, verifyImageEvidence || undefined);
    const imageAuthorization = imageAuthorizationFile.authorization;
    if (imageAuthorizationFile.fileSha256 !== value(argv, "--image-authorization-sha256")) throw new Error("Current image authorization file SHA-256 does not match the supplied binding.");
    if (dependencies.readImageAuthorization) assertImageAuthorization(imageAuthorization, sourceSha, { verifyImageEvidence: verifyImageEvidence || (() => true) });
    const deploymentIdentity = assertStageBDeploymentIdentityValues({
      toolingSha: sourceSha,
      imageReleaseSha: imageAuthorization.imageReleaseSha,
      canonicalImageEvidenceSha256: imageAuthorization.imageEvidenceSha256,
      expectedToolingSha: sourceSha,
      expectedImageReleaseSha: imageAuthorization.imageReleaseSha,
      expectedCanonicalImageEvidenceSha256: imageAuthorization.imageEvidenceSha256,
    });
    const planPath = path.join(root, "scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json");
    const manifestPath = path.join(root, "documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json");
    const planBytes = fs.readFileSync(planPath); const plan = JSON.parse(planBytes); const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    const productionPlan = { ...plan, variables: { ...plan.variables,
      tooling_sha: { ...plan.variables.tooling_sha, value: deploymentIdentity.toolingSha },
      image_release_sha: { ...plan.variables.image_release_sha, value: deploymentIdentity.imageReleaseSha },
      canonical_image_evidence_sha256: { ...plan.variables.canonical_image_evidence_sha256, value: deploymentIdentity.canonicalImageEvidenceSha256 },
    } };
    assertStageARootDropKeyPolicySource(readStageATerraformSource());
    const generatedAt = new Date().toISOString();
    const report = permissionPreflight({
      reportGeneratorCallerArn: observedCaller, simulatedRoleArn: RELEASE_ROLE_ARN, manifest, plan: productionPlan, planBytes,
      deploymentIdentity, imageAuthorizationSha256: imageAuthorization.authorizationSha256, imageAuthorizationFileSha256: imageAuthorizationFile.fileSha256,
      generatedAt, now: generatedAt, ecsExecVerifierEvidence: collectEcsExecOperatorEvidence(),
      policyPublishedAt: generatedAt, cloudTrailSessionName: "pre-plan-capability", policyEvidence: collectPolicies(),
      simulate: ({ roleArn, evaluation }) => simulatePrincipalPolicy({
        roleArn,
        evaluation,
        conditionKeyOrigins: roleArn === ECS_EXEC_OPERATOR_ROLE_ARN
          ? operatorPolicyConditionKeyOrigins()
          : sourcePolicyConditionKeyOrigins(),
        run: commandRun,
      }),
      cloudTrail: () => ({ status: "clear", eventsChecked: 0, unresolvedDenials: [] }), purpose: "pre-plan-capability",
      phase: "initial",
    });
    assertStageBPermissionEvidenceKind(report, INITIAL_ADMINISTRATOR_CAPABILITY_EVIDENCE_KIND, "initial");
    assertStageBAdministratorEvidenceIdentity(report, { sourceSha, imageAuthorization, imageAuthorizationFileSha256: imageAuthorizationFile.fileSha256 });
    report.temporaryKmsCapability = buildTemporaryCapabilityEvidence({
      state: "ABSENCE_VERIFIED",
      sourceSha,
      transitionId: `preflight-${sourceSha.slice(0, 12)}`,
      defaultVersionId: report.policyEvidence.policies.find(({ name }) => name === "MSCQRProductionGreenStageARelease")?.defaultVersionId,
      observedAt: generatedAt,
    });
    report.capabilityGraph = capabilityGraph;
    if (report.status !== "valid") {
      const reportFile = write(output, report);
      return { identity, status: "blocked", administratorSimulation: { failed: report.deniedCount, skipped: 0 }, policySourceLiveMismatches: report.policySourceLiveMismatchCount, report: reportFile, capabilityGraph };
    }
    const reportBytes = Buffer.from(`${JSON.stringify(report, null, 2)}\n`);
    const signature = sign(report, { now: generatedAt, reportBytes }); const files = writePair(output, value(argv, "--signature-output"), report, signature);
    return { identity, status: report.status, administratorSimulation: { failed: report.deniedCount, skipped: 0 }, policySourceLiveMismatches: 0, report: files.report, signature: files.signature, capabilityGraph };
  }
  if (identity === "release-deployer") {
    if (!new RegExp(`^arn:aws:sts::${ACCOUNT}:assumed-role/mscqr-production-release-deployer/[^/]+$`).test(observedCaller)) throw new Error("Release production preflight requires the exact release-deployer identity.");
    if (argv.filter((argument) => argument === "--tooling-sha").length !== 1) throw new Error("Release production preflight requires exactly one --tooling-sha.");
    const sourceSha = value(argv, "--tooling-sha");
    if (!SHA40.test(sourceSha)) throw new Error("Release production preflight requires a full protected source SHA.");
    const protectedMain = readProtectedMainCheckout();
    if (!protectedMain || protectedMain.toolingSha !== sourceSha || protectedMain.currentHead !== sourceSha || protectedMain.originMainHead !== sourceSha || protectedMain.porcelainStatus) throw new Error("Release production preflight requires the exact clean protected-main source.");
    const adminReportBytes = fs.readFileSync(path.resolve(value(argv, "--administrator-report"))); const adminReport = JSON.parse(adminReportBytes);
    const administratorSignatureBytes = fs.readFileSync(path.resolve(value(argv, "--administrator-report-signature")));
    const signature = JSON.parse(administratorSignatureBytes);
    const releaseRun = createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer" });
    const imageAuthorizationFile = dependencies.readImageAuthorization
      ? dependencies.readImageAuthorization(value(argv, "--image-authorization"), value(argv, "--image-authorization-sha256"), sourceSha)
      : readImageAuthorization(value(argv, "--image-authorization"), value(argv, "--image-authorization-sha256"), sourceSha, (args) => releaseRun(args), verifyImageEvidence || undefined);
    if (imageAuthorizationFile.fileSha256 !== value(argv, "--image-authorization-sha256")) throw new Error("Current image authorization file SHA-256 does not match the supplied binding.");
    if (dependencies.readImageAuthorization) assertImageAuthorization(imageAuthorizationFile.authorization, sourceSha, { verifyImageEvidence: verifyImageEvidence || (() => true) });
    (verify || ((options) => verifyPermissionReportSignature({ ...options, run: (args) => releaseRun(args) })))({ report: adminReport, signatureArtifact: signature, reportBytes: adminReportBytes, signatureBytes: administratorSignatureBytes });
    assertStageBPermissionEvidenceKind(adminReport, INITIAL_ADMINISTRATOR_CAPABILITY_EVIDENCE_KIND, "initial");
    assertStageBAdministratorEvidenceIdentity(adminReport, { sourceSha, imageAuthorization: imageAuthorizationFile.authorization, imageAuthorizationFileSha256: imageAuthorizationFile.fileSha256 });
    if (adminReport.purpose !== "pre-plan-capability" || adminReport.status !== "valid" || adminReport.simulatedRoleArn !== RELEASE_ROLE_ARN) throw new Error("Administrator pre-plan capability report is invalid.");
    assertCutoverCriticalEvidence(adminReport);
    if (canonicalizeJson(adminReport.capabilityGraph) !== canonicalizeJson(capabilityGraph)) throw new Error("Administrator pre-plan capability graph is stale.");
    assertReleasePolicyEvidence(adminReport.policyEvidence);
    const authenticatedPublication = assertReadinessImageAuthorizationBinding(argv, imageAuthorizationFile.authorization);
    const report = releasePreflight({ region: REGION, outputDirectory: path.dirname(path.resolve(output)), run: (args) => releaseRun(args) });
    report.sourceSha = sourceSha;
    report.requiredReads["kms:Verify"] = "allowed";
    report.administratorReportSha256 = sha256(adminReportBytes);
    report.policyVersions = adminReport.policyEvidence.policies.map(({ arn, defaultVersionId, liveSha256 }) => ({ arn, defaultVersionId, liveSha256 }));
    if (report.status !== "valid") {
      const blockedReport = { ...report, capabilityGraph, unmappedCalls: 0, unclassifiedCapabilities: 0, identityBoundaryViolations: 0, sourceLivePolicyMismatches: 0, administratorSimulationFailures: 0, releaseReadFailures: report.failed.length, configurationFailures: 0 };
      const reportFile = write(output, blockedReport);
      return { identity, status: report.status, releaseReadCapabilities: { failed: report.failed.length, skipped: report.skipped.length }, report: reportFile, backendReady: false, stateReady: false, handoffReady: false, tfvarsReady: false, capabilityGraph };
    }
    const readiness = continueReadiness(argv, authenticatedPublication);
    const stageBApprovalLiveObservation = argv.includes("--capture-stage-b-approval-live-observation")
      ? observeStageBBrokerApprovalBindings({ reader: createAwsReader({ region: STAGE_B.region, clusterArn: STAGE_B.clusterArn, run: releaseRun }) })
      : undefined;
    const finalReport = { ...report, ...readiness, ...(stageBApprovalLiveObservation ? { stageBApprovalLiveObservation } : {}), capabilityGraph, unmappedCalls: 0, unclassifiedCapabilities: 0, identityBoundaryViolations: 0, sourceLivePolicyMismatches: 0, administratorSimulationFailures: 0, releaseReadFailures: 0, configurationFailures: 0, status: "ready-for-plan" }; const reportFile = write(output, finalReport);
    return { identity, status: "ready-for-plan", releaseReadCapabilities: { failed: 0, skipped: 0 }, report: reportFile, ...readiness, capabilityGraph };
  }
  throw new Error("--identity must be administrator or release-deployer.");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = runProductionPreflightCli();
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!new Set(["valid", "ready-for-plan"]).has(result.status)) process.exitCode = 1;
}
