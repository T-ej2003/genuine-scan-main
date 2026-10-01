import fs from "node:fs";
import { pathToFileURL } from "node:url";

const OPERATION = "VICTORIA_FAILED_ONBOARDING_RECOVERY_V1";
const TARGET = "victoria@mscqr.com";
const DATABASE = "mscqr_production";
const TASK_ARN = /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[0-9a-f-]+$/i;

export function validateVictoriaRecoveryBrokerLaunch(value, { sourceSha, nonce }) {
  if (!value || Object.keys(value).sort().join(",") !== "nonce,operation,sourceSha,taskArn"
      || value.operation !== OPERATION || value.sourceSha !== sourceSha || value.nonce !== nonce
      || !TASK_ARN.test(value.taskArn || "")) throw new Error("VICTORIA_RECOVERY_BROKER_RESULT_INVALID");
  return Object.freeze({ ...value });
}

export function validateVictoriaRecoveryBrokerCleanup(value, { sourceSha, nonce }) {
  if (!value || Object.keys(value).sort().join(",") !== "networkAuthorityRevoked,nonce,operation,sourceSha,taskStopped"
      || value.operation !== OPERATION || value.sourceSha !== sourceSha || value.nonce !== nonce
      || value.networkAuthorityRevoked !== true || value.taskStopped !== true) {
    throw new Error("VICTORIA_RECOVERY_CLEANUP_RESULT_INVALID");
  }
  return Object.freeze({ ...value });
}

export function validateVictoriaRecoveryResult(value, { sourceSha, nonce, requireSuccess = true } = {}) {
  const result = value?.result;
  const envelopeFields = ["authorizationNonce", "operation", "reason", "result", "sourceSha", "status", "temporaryAuthorityCleanup"];
  if (!value || Object.keys(value).sort().join(",") !== envelopeFields.join(",")
      || value.operation !== OPERATION || value.sourceSha !== sourceSha || value.authorizationNonce !== nonce
      || !["complete", "stopped", "transaction-failed", "authority-cleanup-failed"].includes(value.status)
      || typeof value.reason !== "string" || typeof value.temporaryAuthorityCleanup !== "boolean"
      || (result !== null && (!result || result.operation !== OPERATION || result.targetEmail !== TARGET
        || result.targetDatabase !== DATABASE || typeof result.pruneComplete !== "boolean" || typeof result.reason !== "string"
        || value.reason !== result.reason))
      || (requireSuccess && (value.status !== "complete" || value.temporaryAuthorityCleanup !== true
        || result?.pruneComplete !== true || result?.userExists !== false || result?.activeAccountExists !== false
        || result?.emailVerified !== false || result?.validUnusedInvite !== false
        || result?.auditHistoryPreserved !== true || result?.auditHistoryDeleted !== 0
        || !["FAILED_ONBOARDING_PRUNED", "FAILED_ONBOARDING_ALREADY_CLEAN"].includes(result?.reason)))) {
    throw new Error("VICTORIA_RECOVERY_RESULT_INVALID");
  }
  return Object.freeze({ operation: OPERATION, targetEmail: TARGET, targetDatabase: DATABASE,
    status: value.status, pruneComplete: result?.pruneComplete === true, temporaryAuthorityCleanup: value.temporaryAuthorityCleanup,
    reason: value.reason });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2);
  if (args.length !== 6 || args[0] !== "--result" || args[2] !== "--source-sha" || args[4] !== "--nonce") {
    throw new Error("VICTORIA_RECOVERY_RESULT_ARGUMENTS_INVALID");
  }
  const value = JSON.parse(fs.readFileSync(args[1], "utf8"));
  process.stdout.write(`${JSON.stringify(validateVictoriaRecoveryResult(value, { sourceSha: args[3], nonce: args[5] }))}\n`);
}
