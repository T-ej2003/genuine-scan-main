#!/usr/bin/env node
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { deriveLegacyRotationBaseline } from "./production-initial-dual-slot-bootstrap.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readStageBPrivateFileBytes, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { MIXED_DUAL_SLOT_RECOVERY_LIVE_PREDECESSOR, MIXED_DUAL_SLOT_RECOVERY_ORDER, MIXED_DUAL_SLOT_PREDECESSOR, assertMixedDualSlotRecoveryPreparation, resolveMixedDualSlotRecoveryAuthorizationArtifact } from "./production-mixed-dual-slot-recovery-contract.mjs";
import { readMixedDualSlotRecoveryIamCapabilityPreflight } from "./preflight-production-mixed-dual-slot-recovery-iam.mjs";
import { executeMixedDualSlotRecovery, prepareMixedDualSlotRecovery } from "./recover-production-mixed-dual-slot-topology.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const requireBackend = createRequire(path.join(root, "backend/package.json"));
const { SecretsManagerClient } = requireBackend("@aws-sdk/client-secrets-manager");
const { STSClient, GetCallerIdentityCommand } = requireBackend("@aws-sdk/client-sts");
const { fromIni } = requireBackend("@aws-sdk/credential-provider-ini");
const option = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? undefined : argv[index + 1]; };
const required = (argv, name) => { const value = option(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const parseJson = (bytes, label) => { try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { throw new Error(`${label} is malformed.`); } };
const EXECUTION_WORKFLOW_REF = "T-ej2003/genuine-scan-main/.github/workflows/execute-production-mixed-dual-slot-topology-recovery.yml@refs/heads/main";

function assertArgs(argv) {
  const modes = ["--prepare", "--execute"].filter((name) => argv.includes(name));
  if (modes.length !== 1) throw new Error("Exactly one of --prepare or --execute is required.");
  const allowed = new Set(modes[0] === "--prepare" ? ["--prepare", "--source-sha", "--output"] : ["--execute", "--source-sha", "--preparation", "--preparation-file-sha256", "--authorization-run-id", "--authorization-run-attempt"]);
  const seen = new Set();
  for (let index = 0; index < argv.length; index += 1) { const arg = argv[index]; if (!allowed.has(arg) || seen.has(arg)) throw new Error(`Unsupported or duplicate argument: ${arg}`); seen.add(arg); if (arg === modes[0]) continue; if (!argv[index + 1] || argv[index + 1].startsWith("--")) throw new Error(`${arg} is required.`); index += 1; }
  return modes[0];
}

function protectedSource(sourceSha) { return readStageBProtectedMainCheckout({ cwd: root, fetchOriginMain: true, expectedSourceSha: sourceSha, requireCanonicalRepository: true }); }

function clients(mode) {
  const named = mode === "--prepare";
  const credentials = named ? fromIni({ profile: "mscqr-production-release-deployer" }) : undefined;
  return { secrets: new SecretsManagerClient({ region: "eu-west-2", credentials }), sts: new STSClient({ region: "eu-west-2", credentials }) };
}

async function assertReleaseDeployer(sts) {
  const caller = await sts.send(new GetCallerIdentityCommand({}));
  if (caller.Account !== "368992683803" || !/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/.test(caller.Arn || "")) throw new Error("Mixed recovery requires the exact production release-deployer session.");
}

function readLivePredecessor() {
  const credentialSource = process.env.GITHUB_ACTIONS === "true" ? PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER : PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE;
  const run = createProductionCommandRunner({ credentialSource, ...(credentialSource === PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE ? { profile: "mscqr-production-release-deployer" } : {}), region: "eu-west-2" });
  const service = JSON.parse(run(["ecs", "describe-services", "--cluster", MIXED_DUAL_SLOT_RECOVERY_LIVE_PREDECESSOR.cluster, "--services", MIXED_DUAL_SLOT_RECOVERY_LIVE_PREDECESSOR.service])).services?.[0];
  if (service?.taskDefinition !== MIXED_DUAL_SLOT_RECOVERY_LIVE_PREDECESSOR.taskDefinition || service.desiredCount !== 2 || service.runningCount !== 2 || service.pendingCount !== 0 || service.deployments?.length !== 1 || service.deployments[0]?.rolloutState !== "COMPLETED") throw new Error("Mixed recovery live ECS predecessor changed.");
  const taskDefinition = JSON.parse(run(["ecs", "describe-task-definition", "--task-definition", service.taskDefinition, "--include", "TAGS"]));
  const backend = taskDefinition.taskDefinition?.containerDefinitions?.find(({ name }) => name === "backend");
  if (backend?.image !== MIXED_DUAL_SLOT_RECOVERY_LIVE_PREDECESSOR.backendImage) throw new Error("Mixed recovery live backend image changed.");
  const baseline = deriveLegacyRotationBaseline(taskDefinition);
  const active = [baseline.jwtCurrent, baseline.qrPrivateCurrent, baseline.qrPublicCurrent].sort();
  if (JSON.stringify(active) !== JSON.stringify([...MIXED_DUAL_SLOT_RECOVERY_LIVE_PREDECESSOR.legacySecretArns].sort())) throw new Error("Mixed recovery live legacy selectors changed.");
  if (active.some((arn) => MIXED_DUAL_SLOT_RECOVERY_ORDER.some((slot) => MIXED_DUAL_SLOT_PREDECESSOR[slot].arn === arn))) throw new Error("Mixed recovery targets intersect active legacy runtime material.");
  return MIXED_DUAL_SLOT_RECOVERY_LIVE_PREDECESSOR;
}

async function main(argv = process.argv.slice(2)) {
  const mode = assertArgs(argv); const sourceSha = required(argv, "--source-sha");
  protectedSource(sourceSha);
  const { secrets, sts } = clients(mode); await assertReleaseDeployer(sts);
  if (mode === "--prepare") {
    const iamCapabilityPreflight = readMixedDualSlotRecoveryIamCapabilityPreflight({ sourceSha });
    const preparation = await prepareMixedDualSlotRecovery({ send: (command) => secrets.send(command), sourceSha, livePredecessor: readLivePredecessor(), iamCapabilityPreflight });
    const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "Mixed recovery preparation", allowExisting: false });
    ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "Mixed recovery preparation directory" });
    writeStageBPrivateFileAtomic({ filePath: output, bytes: Buffer.from(`${JSON.stringify(preparation, null, 2)}\n`), repositoryRoot: root, label: "Mixed recovery preparation" });
    return { status: "PREPARED", preparationSha256: preparation.preparationSha256, output };
  }
  if (process.env.GITHUB_ACTIONS !== "true" || process.env.GITHUB_WORKFLOW_REF !== EXECUTION_WORKFLOW_REF || process.env.GITHUB_SHA !== sourceSha) throw new Error("Mixed recovery execution is restricted to its protected-main execution workflow.");
  const captured = readStageBPrivateFileBytes({ filePath: required(argv, "--preparation"), repositoryRoot: root, label: "Mixed recovery preparation" });
  if (captured.sha256 !== required(argv, "--preparation-file-sha256")) throw new Error("Mixed recovery preparation bytes changed after authorization.");
  const preparation = parseJson(captured.bytes, "Mixed recovery preparation"); assertMixedDualSlotRecoveryPreparation(preparation, { sourceSha });
  const resolved = resolveMixedDualSlotRecoveryAuthorizationArtifact({ workflowRunId: required(argv, "--authorization-run-id"), workflowRunAttempt: required(argv, "--authorization-run-attempt"), sourceSha, preparation, preparationFileSha256: captured.sha256 });
  const reauthenticate = async () => { protectedSource(sourceSha); readLivePredecessor(); };
  const result = await executeMixedDualSlotRecovery({ send: (command) => secrets.send(command), preparation, preparationFileSha256: captured.sha256, sourceSha, authorization: resolved.authorization, reauthenticate });
  return { status: result.stageLabelMutations === 0 ? "COMPLETED_CONSUMED" : "COMPLETED", authorizationSha256: resolved.authorization.authorizationSha256, ...result };
}

process.stdout.write(`${JSON.stringify(await main(), null, 2)}\n`);
