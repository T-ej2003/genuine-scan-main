import { ECS_EXEC_OPERATOR_BOOTSTRAP_MFA_SERIAL_ARN, ECS_EXEC_OPERATOR_BOOTSTRAP_USER_ARN, ECS_EXEC_OPERATOR_CALLER_PATTERN, ECS_EXEC_OPERATOR_ROLE_ARN } from "./production-ecs-exec-operator-contract.mjs";
import { createHash } from "node:crypto";

const verifier = new RegExp(ECS_EXEC_OPERATOR_CALLER_PATTERN);

export function assertVerifierMfaSerial(value) {
  const serial = String(value || "").trim();
  if (serial !== ECS_EXEC_OPERATOR_BOOTSTRAP_MFA_SERIAL_ARN) throw new Error("Verifier MFA serial must be the exact reviewed bootstrap-operator MFA device ARN.");
  return serial;
}

// The caller supplies the process-scoped STS adapter. No credentials are
// returned, persisted, logged, or included in the resulting evidence.
export async function establishEcsExecVerifierSession({ adapter, mfaSerial, mfaCode, getMfaCode, sessionName = "mscqr-production-ecs-exec-verifier" } = {}) {
  if (!adapter || typeof adapter.getCallerIdentity !== "function" || typeof adapter.assumeRole !== "function") throw new Error("Verifier session adapter is incomplete.");
  if (getMfaCode !== undefined && typeof getMfaCode !== "function") throw new Error("MFA serial and code are required for verifier session establishment.");
  const verifiedMfaSerial = assertVerifierMfaSerial(mfaSerial);
  const callerArn = await adapter.getCallerIdentity();
  if (callerArn !== ECS_EXEC_OPERATOR_BOOTSTRAP_USER_ARN) throw new Error("Only the reviewed bootstrap operator may assume the ECS Exec verifier role.");
  let code = "";
  try {
    code = String(await (getMfaCode ? getMfaCode() : mfaCode) || "").trim();
    if (!/^\d{6,8}$/.test(code)) throw new Error("MFA serial and code are required for verifier session establishment.");
    const assumed = await adapter.assumeRole({ roleArn: ECS_EXEC_OPERATOR_ROLE_ARN, sessionName, mfaSerial: verifiedMfaSerial, mfaCode: code });
    code = "";
    const assumedArn = assumed?.callerArn || await adapter.getAssumedCallerIdentity?.(assumed);
    if (!verifier.test(assumedArn || "")) throw new Error("Verifier session did not resolve to the reviewed assumed role.");
    const evidence = { valid: true, evidenceRef: `sts:${ECS_EXEC_OPERATOR_ROLE_ARN}`, evidenceSha256: createHash("sha256").update(`${ECS_EXEC_OPERATOR_ROLE_ARN}\n${assumedArn}`).digest("hex"), roleArn: ECS_EXEC_OPERATOR_ROLE_ARN, callerArn: assumedArn, expiration: assumed?.expiration };
    if (assumed?.session) Object.defineProperty(evidence, "session", { value: assumed.session, enumerable: false });
    return evidence;
  } finally {
    code = "";
  }
}
