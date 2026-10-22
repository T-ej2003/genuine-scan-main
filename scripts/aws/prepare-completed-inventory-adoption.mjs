#!/usr/bin/env node
import {isConditionalNativeSigner} from './production-cutover-consumption-journal.mjs';
import {assertConditionalProductionEnabled} from './production-green-stage-b-contract.mjs';
import {assertLegacyProductionUnclaimed} from './production-cutover-conditional-lock.mjs';
import fs from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { authenticateCompletedInventoryAdoptionEvidence, authenticateFreshInventoryCompletionReceipt, buildCompletedInventoryAdoptionEvidence, buildFreshInventoryAdoptionEvidence, kmsAdoptionMessage } from "./production-completed-inventory-adoption.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { ensureStageBPrivateDirectory, readBoundStageBPrivateJson, readStageBPrivateFileBytes, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";
import { preDeploymentOperationKey, createPreDeploymentOperationIdentity, inventoryCompletionKey } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs";
import { canonicalJson, COMPLETED_INVENTORY_PREDECESSOR, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import {bridgeSignerFromEnvironment} from './production-release-bridge-sign-journal.mjs';

const json = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
const read = (argv, name) => {
  const index = argv.indexOf(`--${name}`);
  if (index < 0 || !argv[index + 1] || argv[index + 1].startsWith("--")) throw new Error(`--${name} is required.`);
  return argv[index + 1];
};
const hash = value => createHash("sha256").update(value).digest("hex");
const fromAws = item => Object.fromEntries(Object.entries(item || {}).map(([key, value]) => [key, value.S ?? (value.N !== undefined ? Number(value.N) : value.SS)]));

export async function prepareCompletedInventoryAdoption({ argv, root = process.cwd(), runRead, runSign, authenticateCheckout = readStageBProtectedMainCheckout, proveSourceAdvance, now = new Date(), nativeSign, legacyGuard = assertLegacyProductionUnclaimed } = {}) {
  if (nativeSign) {assertConditionalProductionEnabled();if(!isConditionalNativeSigner(nativeSign))throw new Error('Confirmed conditional signing claim required');}
  const originalPath = path.resolve(read(argv, "original-config"));
  const originalHash = read(argv, "original-config-sha256");
  const continuationPath = path.resolve(read(argv, "continuation-config"));
  const continuationHash = read(argv, "continuation-config-sha256");
  const originalConfig = readBoundStageBPrivateJson({ filePath: originalPath, expectedSha256: originalHash, repositoryRoot: root, label: "Completed inventory original runtime config" });
  const continuationConfig = readBoundStageBPrivateJson({ filePath: continuationPath, expectedSha256: continuationHash, repositoryRoot: root, label: "Completed inventory continuation runtime config" });
  const manifest = JSON.parse(readStageBPrivateFileBytes({ filePath: path.join(path.dirname(continuationPath), "cutover-runtime-manifest.json"), repositoryRoot: root, label: "Cutover runtime manifest" }).bytes);
  if (continuationConfig.rotationConfigFile !== continuationPath || path.dirname(continuationConfig.rotationStateFile || "") !== path.dirname(continuationPath) || continuationConfig.completedInventoryAdoptionRequired !== true || manifest.runtimeConfigSha256 !== continuationHash || manifest.readyToConsumeMfa !== true) throw new Error("Continuation runtime is not the prepared self-bound adoption config.");
  const fresh = canonicalJson(originalConfig.newInventoryAfterCompleted) === canonicalJson(COMPLETED_INVENTORY_PREDECESSOR);
  const crossSource = originalConfig.sourceSha !== continuationConfig.sourceSha;
  if (crossSource && (!fresh || continuationConfig.completedInventoryPredecessorSourceSha !== originalConfig.sourceSha)) throw new Error("Cross-source inventory adoption requires the exact durable predecessor.");
  const toolingSha = continuationConfig.recoveryTooling?.sourceSha || continuationConfig.sourceSha;
  if (crossSource && (manifest.releaseSourceSha !== continuationConfig.sourceSha || manifest.protectedMainSha !== toolingSha
      || (continuationConfig.recoveryTooling && continuationConfig.recoveryTooling.releaseSourceSha !== continuationConfig.sourceSha))) throw new Error("Cross-source inventory runtime tooling or release identity changed.");
  if (crossSource) authenticateCheckout({ cwd: root, expectedSourceSha: toolingSha, requireCanonicalRepository: true });
  const proveDescendant = proveSourceAdvance || (({ ancestorSha, descendantSha }) => {
    try { execFileSync("git", ["merge-base", "--is-ancestor", ancestorSha, descendantSha], { cwd: root, stdio: "ignore" }); return true; } catch { return false; }
  });
  if (crossSource && !proveDescendant({ ancestorSha: originalConfig.sourceSha, descendantSha: continuationConfig.sourceSha })) throw new Error("Inventory successor source ancestry is invalid.");
  const currentApproval = crossSource ? readBoundStageBPrivateJson({ filePath: path.resolve(read(argv, "current-approval")), expectedSha256: read(argv, "current-approval-sha256"), repositoryRoot: root, label: "Current-source Stage B approval" }) : null;
  const receiptReader = crossSource ? runSign : runRead;
  if (originalConfig.newInventoryAfterCompleted && !fresh) throw new Error("Fresh inventory predecessor marker is invalid.");
  const recoveryEvidence = fresh ? null : readBoundStageBPrivateJson({ filePath: path.resolve(read(argv, "original-recovery-evidence")), expectedSha256: read(argv, "original-recovery-evidence-sha256"), repositoryRoot: root, label: "Original absent-claim recovery" });
  const approval = fresh ? null : readBoundStageBPrivateJson({ filePath: path.resolve(read(argv, "original-approval")), expectedSha256: read(argv, "original-approval-sha256"), repositoryRoot: root, label: "Original Stage B approval" });
  const identity = createPreDeploymentOperationIdentity({ approvalId: originalConfig.inventoryApprovalId, releaseSha: originalConfig.sourceSha, imageReleaseSha: originalConfig.imageReleaseSha, rotationId: originalConfig.rotationId, taskDefinitionArn: originalConfig.inventoryTaskDefinitionArn, imageDigest: originalConfig.overlapTaskInput.backendImage });
  const claim = fresh ? null : fromAws(json(runRead, ["dynamodb", "get-item", "--table-name", STAGE_B.replayTable, "--consistent-read", "--key", JSON.stringify({ approvalMode: { S: preDeploymentOperationKey(identity) } })]).Item);
  if (!fresh && !Object.keys(claim).length) throw new Error("Completed inventory replay claim is absent.");
  const completionReceipt = fresh ? fromAws(json(receiptReader, ["dynamodb", "get-item", "--table-name", STAGE_B.replayTable, "--consistent-read", "--key", JSON.stringify({ approvalMode: { S: inventoryCompletionKey(preDeploymentOperationKey(identity)) } })]).Item) : null;
  if (fresh && !Object.keys(completionReceipt).length) throw new Error("Durable inventory completion receipt is absent.");
  const stateBoundInventorySha256 = continuationConfig.rotationSuccessor?.inventoryEvidenceSha256;
  const changedImage = crossSource && (originalConfig.imageReleaseSha !== continuationConfig.imageReleaseSha
    || originalConfig.overlapTaskInput?.backendImage !== continuationConfig.overlapTaskInput?.backendImage);
  const distinctStateHash = fresh && changedImage && stateBoundInventorySha256 !== completionReceipt.inventorySha256;
  const task = fresh ? null : json(runRead, ["ecs", "describe-tasks", "--cluster", STAGE_B.clusterArn, "--tasks", claim.taskArn, "--include", "TAGS"]).tasks?.[0];
  const definition = fresh ? null : json(runRead, ["ecs", "describe-task-definition", "--task-definition", identity.taskDefinitionArn, "--include", "TAGS"]);
  const stream = fresh ? null : `predeployment-inventory/inventory/${claim.taskArn?.split("/").pop()}`;
  const logs = fresh ? null : json(runRead, ["logs", "get-log-events", "--log-group-name", STAGE_B.inventoryLogGroupName, "--log-stream-name", stream, "--start-from-head"]);
  if (!fresh && (logs.nextBackwardToken === undefined || !Array.isArray(logs.events) || logs.events.length !== 1)) throw new Error("Completed inventory log readback is incomplete or ambiguous.");
  const readIdentity = json(receiptReader, ["sts", "get-caller-identity"]);
  const signerIdentity = json(runSign, ["sts", "get-caller-identity"]);
  if (readIdentity.Arn !== (crossSource ? signerIdentity.Arn : `arn:aws:iam::${STAGE_B.account}:root`) || !new RegExp(`^arn:aws:sts::${STAGE_B.account}:assumed-role/mscqr-production-rls-independent-checker/`).test(signerIdentity.Arn || "")) throw new Error("Completed inventory adoption reader or signer identity is invalid.");
  const bridge=process.env.MSCQR_BRIDGE_OPERATION_ID ? await bridgeSignerFromEnvironment({directory:path.dirname(continuationPath),repositoryRoot:root,readCaller:()=>json(runSign,['sts','get-caller-identity'])}) : null;
  if(bridge&&(nativeSign||continuationConfig.sourceSha!==process.env.MSCQR_BRIDGE_SOURCE_SHA||continuationConfig.rotationId!==process.env.MSCQR_BRIDGE_ROTATION_ID))throw new Error('Bridge adoption identity differs');
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-inventory-adoption-"));
  fs.chmodSync(temporary, 0o700);
  const messageFile = path.join(temporary, "message");
  const message = value => { fs.writeFileSync(messageFile, value, { mode: 0o600 }); return `fileb://${messageFile}`; };
  try {
    const verifySignature = ({ keyId, message: bytes, signature }) => {
      const input = kmsAdoptionMessage(bytes);
      return json(receiptReader, ["kms", "verify", "--key-id", keyId, "--message", message(input.bytes), "--message-type", input.type, "--signature", Buffer.from(signature).toString("base64"), "--signing-algorithm", "RSASSA_PSS_SHA_256"]).SignatureValid === true;
    };
    const sign = async ({ keyId, message: bytes }) => {
      if (!nativeSign) await legacyGuard({config:continuationConfig,repositoryRoot:root,run:runRead});
      const input = kmsAdoptionMessage(bytes);
      const signRun=bridge?createProductionAwsCommandRunner({credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION,singleAttemptMutation:'KMS_SIGN'}):runSign;
      const invoke=()=>json(signRun, ["kms", "sign", "--key-id", keyId, "--message", message(input.bytes), "--message-type", input.type, "--signing-algorithm", "RSASSA_PSS_SHA_256"]);
      return (nativeSign ? await nativeSign({keyId,message:Buffer.from(bytes),messageType:input.type,signingAlgorithm:'RSASSA_PSS_SHA_256'},invoke)
        : bridge ? await bridge({phase:'INVENTORY_ADOPTION',keyId,message:input.bytes,messageType:input.type,signingAlgorithm:'RSASSA_PSS_SHA_256',invoke}) : invoke()).Signature;
    };
    const outputPath = path.join(path.dirname(continuationPath), "inventory-completed-adoption-evidence.json");
    if (fs.existsSync(outputPath)) {
      const existing = JSON.parse(readStageBPrivateFileBytes({ filePath: outputPath, repositoryRoot: root, label: "Completed inventory adoption evidence" }).bytes);
      const payload = await authenticateCompletedInventoryAdoptionEvidence(existing, { config: continuationConfig, configSha256: continuationHash, proveDescendant, now }, verifySignature);
      if (fresh) {
        const authenticated = await authenticateFreshInventoryCompletionReceipt(completionReceipt, { config: crossSource ? originalConfig : continuationConfig, verifySignature });
        if (payload.completionReceiptSha256 !== authenticated.receiptSha256 || payload.taskArn !== completionReceipt.taskArn) throw new Error("Persisted inventory adoption differs from durable completion.");
      } else if (payload.replayRowSha256 !== hash(canonicalJson(claim)) || payload.taskArn !== task?.taskArn
          || payload.inventorySha256 !== hash(JSON.stringify(JSON.parse(logs.events[0].message)))) throw new Error("Persisted inventory adoption differs from current readbacks.");
      return { outputPath, expiresAt: payload.expiresAt, operationKey: payload.operationKey, reused: true };
    }
    if (distinctStateHash && !/^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[A-Za-z0-9_-]+$/.test(completionReceipt.taskArn || "")) throw new Error("Durable inventory task identity is invalid.");
    if (distinctStateHash) await authenticateFreshInventoryCompletionReceipt(completionReceipt, { config: originalConfig, verifySignature });
    const predecessorState = distinctStateHash ? readBoundStageBPrivateJson({ filePath: continuationConfig.rotationSuccessor.predecessorStateFile,
      expectedSha256: continuationConfig.rotationSuccessor.predecessorStateSha256, repositoryRoot: root, label: "Original rotation state" }) : null;
    const completionStream = distinctStateHash ? `predeployment-inventory/inventory/${completionReceipt.taskArn.split("/").pop()}` : null;
    const completionLogs = distinctStateHash ? json(runRead, ["logs", "get-log-events", "--log-group-name", STAGE_B.inventoryLogGroupName,
      "--log-stream-name", completionStream, "--start-from-head"]) : null;
    if (distinctStateHash && (completionLogs.nextBackwardToken === undefined || !Array.isArray(completionLogs.events)
        || completionLogs.events.length !== 1)) throw new Error("State-bound inventory log readback is incomplete or ambiguous.");
    const evidence = fresh
      ? await buildFreshInventoryAdoptionEvidence({ originalConfig, originalConfigSha256: originalHash, continuationConfig, continuationConfigSha256: continuationHash, completionReceipt,
        completionLogEvents: completionLogs?.events, predecessorState, currentApproval, proveDescendant, verifySignature, sign, now })
      : await buildCompletedInventoryAdoptionEvidence({ originalConfig, originalConfigSha256: originalHash, continuationConfig, continuationConfigSha256: continuationHash, approval, recoveryEvidence, replayRow: claim, task, taskDefinition: { ...definition.taskDefinition, tags: definition.tags }, logEvents: logs.events, verifySignature, sign, now });
    ensureStageBPrivateDirectory({ directory: path.dirname(outputPath), repositoryRoot: root });
    writeStageBPrivateFileExclusive({ filePath: outputPath, bytes: Buffer.from(`${JSON.stringify(evidence)}\n`), repositoryRoot: root, label: "Completed inventory adoption evidence" });
    return { outputPath, expiresAt: evidence.payload.expiresAt, operationKey: evidence.payload.operationKey };
  } finally { fs.rmSync(temporary, { recursive: true, force: true }); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const runRead = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-root" });
  const runSign = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION });
  console.log(JSON.stringify(await prepareCompletedInventoryAdoption({ argv: process.argv.slice(2), runRead, runSign,
    ...(process.env.MSCQR_BRIDGE_OPERATION_ID?{now:new Date(process.env.MSCQR_BRIDGE_PHASE_TIMESTAMP)}:{}) })));
}
