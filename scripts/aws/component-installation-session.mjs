import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { promptProductionMfaCode } from "../security/production-interactive-mfa-provider.mjs";
import { createProductionAwsCredentialEnvironment, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { identityBootstrap, componentBrokerArn } from "./component-installation-identity-contract.mjs";
import { sessionProofBinding } from "./component-session-proof.mjs";

const requireSdk = createRequire(new URL("../../infra/aws/terraform/production-component-deployment-state/broker-package/package.json", import.meta.url));
const operator = "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator";
const roles = { INSTALL: identityBootstrap.installationRole, CLEANUP: identityBootstrap.cleanupRole };
const credentialsForSdk = (value) => ({ accessKeyId: value.AccessKeyId, secretAccessKey: value.SecretAccessKey, ...(value.SessionToken ? { sessionToken: value.SessionToken } : {}) });
const options = (credentials, service) => ({ region: identityBootstrap.region, credentials: credentialsForSdk(credentials), endpoint: `https://${service}.eu-west-2.amazonaws.com`, maxAttempts: 1 });
function stsTransport(credentials) {
  const sdk = requireSdk("@aws-sdk/client-sts");
  const client = new sdk.STSClient(options(credentials, "sts"));
  return { send: (operation, input = {}) => client.send(new sdk[`${operation}Command`](input)), close: () => client.destroy() };
}
function loadOperator() {
  const env = createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-bootstrap-operator", region: identityBootstrap.region });
  return JSON.parse(execFileSync("aws", ["configure", "export-credentials", "--format", "process"], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
}

// The caller must authenticate explicit authorization before issuance. This
// client exposes only fixed broker operations; no AWS/IAM client or credentials
// are returned to the normal controller, output files, evidence or child env.
export async function establishComponentSession(binding, { loadUser = loadOperator, sts = stsTransport, mfa = () => promptProductionMfaCode({ prompt: "Component installation operator MFA code: " }), invoke, now = Date.now } = {}) {
  const fixedBinding = structuredClone(binding);
  sessionProofBinding(fixedBinding);
  assert(Object.hasOwn(roles, fixedBinding.purpose));
  let base;
  let human;
  let code = "";
  const transports = [];
  const transport = (credentials) => { const value = sts(credentials); transports.push(value); return value; };
  try {
    base = await loadUser();
    for (const key of ["AccessKeyId", "SecretAccessKey"]) assert(typeof base[key] === "string" && base[key], "Operator credentials missing");
    const user = transport(base);
    const caller = await user.send("GetCallerIdentity");
    assert.equal(caller.Account, identityBootstrap.account);
    assert.equal(caller.Arn, operator, "Only the exact human bootstrap user may issue component sessions");
    if (base.SessionToken) human = base;
    else {
      code = String(await mfa()).trim();
      assert(/^\d{6,8}$/.test(code), "Invalid interactive MFA input");
      human = (await user.send("GetSessionToken", { DurationSeconds: 900, SerialNumber: "arn:aws:iam::368992683803:mfa/mscqr-production-bootstrap-operator", TokenCode: code })).Credentials;
      code = "";
    }
    assert(human?.SessionToken, "MFA-backed user session required");
    const issued = await transport(human).send("AssumeRole", { RoleArn: `arn:aws:iam::368992683803:role/${roles[fixedBinding.purpose]}`, RoleSessionName: `component-${fixedBinding.transitionId}`, DurationSeconds: 900 });
    const scoped = issued.Credentials;
    const expires = new Date(scoped?.Expiration).getTime();
    assert(Number.isFinite(expires) && expires > now() && expires <= now() + 901000, "Unexpected AWS session expiration");
    for (const key of ["AccessKeyId", "SecretAccessKey", "SessionToken"]) assert(typeof scoped[key] === "string" && scoped[key], "Scoped session missing");
    const principal = `arn:aws:sts::368992683803:assumed-role/${roles[fixedBinding.purpose]}/component-${fixedBinding.transitionId}`;
    assert.equal(issued.AssumedRoleUser?.Arn, principal);
    const assumed = await transport(scoped).send("GetCallerIdentity");
    assert.equal(assumed.Account, identityBootstrap.account);
    assert.equal(assumed.Arn, principal);
    assert.equal(assumed.UserId, issued.AssumedRoleUser.AssumedRoleId);
    const { SignatureV4 } = requireSdk("@smithy/signature-v4");
    const { Sha256 } = requireSdk("@aws-crypto/sha256-js");
    const signer = new SignatureV4({ credentials: credentialsForSdk(scoped), region: identityBootstrap.region, service: "sts", sha256: Sha256 });
    return Object.freeze({
      principal, expiresAt: new Date(expires).toISOString(),
      async invoke(operation) {
        assert((fixedBinding.purpose === "INSTALL" ? ["INSTALL", "INSPECT"] : ["CLOSE"]).includes(operation), "Unsupported session operation");
        assert(now() < expires, "AWS session expired");
        const signed = await signer.presign({ protocol: "https:", hostname: "sts.eu-west-2.amazonaws.com", method: "GET", path: "/", headers: { host: "sts.eu-west-2.amazonaws.com", "x-mscqr-component-binding": sessionProofBinding(fixedBinding) }, query: { Action: "GetCallerIdentity", Version: "2011-06-15" } }, { expiresIn: 60, signingDate: new Date(now()) });
        const payload = { operation, transitionId: fixedBinding.transitionId, authorizationSha256: fixedBinding.authorizationSha256, proof: { query: signed.query } };
        const input = { FunctionName: `${componentBrokerArn}:${fixedBinding.purpose === "INSTALL" ? "1" : "2"}`, InvocationType: "RequestResponse", Payload: Buffer.from(JSON.stringify(payload)) };
        let result;
        if (invoke) result = await invoke(input);
        else {
          const sdk = requireSdk("@aws-sdk/client-lambda");
          const client = new sdk.LambdaClient(options(scoped, "lambda"));
          try { result = await client.send(new sdk.InvokeCommand(input)); }
          finally { client.destroy(); }
        }
        assert.equal(result.StatusCode, 200);
        assert(!result.FunctionError, "Broker rejected the request; authenticate live evidence before retry");
        assert.equal(result.ExecutedVersion, fixedBinding.purpose === "INSTALL" ? "1" : "2");
        return JSON.parse(Buffer.from(result.Payload).toString("utf8"));
      },
    });
  } finally {
    code = "";
    for (const value of new Set([base, human])) if (value) for (const field of ["AccessKeyId", "SecretAccessKey", "SessionToken"]) delete value[field];
    for (const client of transports) client.close();
  }
}
