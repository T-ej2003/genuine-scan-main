import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { promptProductionMfaCode } from "../security/production-interactive-mfa-provider.mjs";
import { createProductionAwsCredentialEnvironment, productionAwsExecutable, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { identityBootstrap } from "./component-installation-identity-contract.mjs";

const sdk = createRequire(new URL("../../infra/aws/terraform/production-component-deployment-state/broker-package/package.json", import.meta.url));
const rootArn = `arn:aws:iam::${identityBootstrap.account}:root`;
export const brokerPolicySuccessorRootMfaSource = Object.freeze({ profile: "mscqr-production-root-long-term", durationSeconds: 3600 });

const secret = value => ({ accessKeyId: value.AccessKeyId, secretAccessKey: value.SecretAccessKey, ...(value.SessionToken ? { sessionToken: value.SessionToken } : {}) });
const clear = value => { if (value) for (const field of ["AccessKeyId", "SecretAccessKey", "SessionToken", "accessKeyId", "secretAccessKey", "sessionToken"]) delete value[field]; };

export const rootAwsExecutable = productionAwsExecutable;

export function loadRootSource(exec = execFileSync, fsOps, processEnv = process.env) {
  const executable = rootAwsExecutable(fsOps);
  const env = createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: brokerPolicySuccessorRootMfaSource.profile, region: identityBootstrap.region, env: processEnv });
  let credentials;
  try { credentials = JSON.parse(exec(executable, ["configure", "export-credentials", "--format", "process"], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })); }
  catch { throw new Error("Long-term root credential source is unavailable"); }
  try {
    const serial = exec(executable, ["configure", "get", "mfa_serial", "--profile", brokerPolicySuccessorRootMfaSource.profile], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
    return { credentials, serial };
  } catch { clear(credentials); throw new Error("Root MFA device configuration is unavailable"); }
}

function transport(value) {
  const { STSClient, GetCallerIdentityCommand, GetSessionTokenCommand } = sdk("@aws-sdk/client-sts");
  const commands = { GetCallerIdentity: GetCallerIdentityCommand, GetSessionToken: GetSessionTokenCommand };
  const client = new STSClient({ region: identityBootstrap.region, endpoint: `https://sts.${identityBootstrap.region}.amazonaws.com`, credentials: secret(value), maxAttempts: 1 });
  return { send: (operation, input = {}) => client.send(new commands[operation](input)), close: () => client.destroy() };
}

export async function createBrokerPolicySuccessorRootMfaSession({ load = loadRootSource, sts = transport,
  mfa = () => promptProductionMfaCode({ prompt: "Production root MFA code: " }), now = Date.now } = {}) {
  let source, base, issued, sessionClient, code = "";
  try {
    source = await load();
    assert(source?.credentials?.AccessKeyId && source.credentials.SecretAccessKey, "Long-term root credential source is unavailable");
    assert(!source.credentials.SessionToken && !source.credentials.Expiration, "Temporary root credentials cannot issue the required MFA session");
    assert.match(source.serial || "", new RegExp(`^arn:aws:iam::${identityBootstrap.account}:mfa/[A-Za-z0-9+=,.@_/-]{1,128}$`), "Exact root MFA device ARN is required");
    base = sts(source.credentials); const identity = await base.send("GetCallerIdentity");
    assert.deepEqual({ Account: identity.Account, Arn: identity.Arn }, { Account: identityBootstrap.account, Arn: rootArn }, "Long-term source must be account root");
    try { code = String(await mfa()).trim(); } catch { throw new Error("Interactive root MFA entry failed"); }
    assert(/^\d{6,8}$/.test(code), "Interactive root MFA entry failed");
    const request = { DurationSeconds: brokerPolicySuccessorRootMfaSource.durationSeconds, SerialNumber: source.serial, TokenCode: code };
    try { issued = (await base.send("GetSessionToken", request)).Credentials; } finally { code = ""; delete request.TokenCode; base.close(); base = null; clear(source.credentials); }
    assert(issued?.AccessKeyId && issued.SecretAccessKey && issued.SessionToken, "Root MFA session issuance failed");
    const expires = Date.parse(issued.Expiration); assert(Number.isFinite(expires) && now() + 120000 < expires && expires <= now() + 3601000, "Root MFA session lifetime is invalid");
    sessionClient = sts(issued); const sessionIdentity = await sessionClient.send("GetCallerIdentity");
    assert.deepEqual({ Account: sessionIdentity.Account, Arn: sessionIdentity.Arn }, { Account: identityBootstrap.account, Arn: rootArn }, "Issued MFA session is not account root");
    const credentials = secret(issued);
    return { credentials, expiresAt: new Date(expires).toISOString(), mfaSerial: source.serial, durationSeconds: brokerPolicySuccessorRootMfaSource.durationSeconds,
      close() { clear(credentials); sessionClient?.close(); sessionClient = null; clear(issued); } };
  } catch (error) { base?.close(); sessionClient?.close(); clear(source?.credentials); clear(issued); throw error; }
  finally { code = ""; }
}
