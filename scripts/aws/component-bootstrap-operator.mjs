import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { promptProductionMfaCode } from "../security/production-interactive-mfa-provider.mjs";
import { createProductionAwsCredentialEnvironment, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { authenticateComponentSession, sessionProofBinding } from "./component-session-proof.mjs";

const sdk = createRequire(new URL("../../infra/aws/terraform/production-component-deployment-state/broker-package/package.json", import.meta.url));
const operator = "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator";
const credentials = value => ({ accessKeyId: value.AccessKeyId, secretAccessKey: value.SecretAccessKey, ...(value.SessionToken ? { sessionToken: value.SessionToken } : {}) });
function loadUser() {
  return JSON.parse(execFileSync("aws", ["configure", "export-credentials", "--format", "process"], {
    env: createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-bootstrap-operator", region: "eu-west-2" }),
    encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
  }));
}
function transport(value) {
  const { STSClient, GetCallerIdentityCommand, GetSessionTokenCommand, AssumeRoleCommand } = sdk("@aws-sdk/client-sts");
  const commands = { GetCallerIdentity: GetCallerIdentityCommand, GetSessionToken: GetSessionTokenCommand, AssumeRole: AssumeRoleCommand };
  const client = new STSClient({ region: "eu-west-2", endpoint: "https://sts.eu-west-2.amazonaws.com", credentials: credentials(value), maxAttempts: 1 });
  return { send: (operation, input = {}) => client.send(new commands[operation](input)), close: () => client.destroy() };
}

// Bootstrap-only human proof through the already-existing release-role trust.
// The release session performs no installation mutation and is never returned.
// Root GetSessionToken is neither requested nor accepted here.
export async function authenticateBootstrapOperator(binding, { issuanceEvents, load = loadUser, sts = transport,
  mfa = () => promptProductionMfaCode({ prompt: "Identity bootstrap operator MFA code: " }), verify, now = Date.now, sleep = delay } = {}) {
  assert(["IDENTITY_BOOTSTRAP", "BROKER_CHANGE"].includes(binding.purpose), "Unsupported exceptional operator purpose"); sessionProofBinding(binding);
  assert.equal(typeof issuanceEvents, "function");
  const clients = [], secrets = [];
  const client = value => { secrets.push(value); const instance = sts(value); clients.push(instance); return instance; };
  let code = "";
  try {
    const base = await load(), user = client(base);
    const identity = await user.send("GetCallerIdentity");
    assert.equal(identity.Account, "368992683803");
    assert.equal(identity.Arn, operator, "Exact existing human operator required");
    assert(!base.SessionToken, "First bootstrap requires a fresh interactive MFA issuance");
    code = String(await mfa()).trim(); assert(/^\d{6,8}$/.test(code));
    const human = (await user.send("GetSessionToken", { DurationSeconds: 900, SerialNumber: "arn:aws:iam::368992683803:mfa/mscqr-production-bootstrap-operator", TokenCode: code })).Credentials;
    code = "";
    assert(human?.SessionToken);
    const issued = await client(human).send("AssumeRole", { RoleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", RoleSessionName: `component-${binding.transitionId}`, DurationSeconds: 900 });
    const session = issued.Credentials;
    assert(session?.SessionToken);
    const caller = await client(session).send("GetCallerIdentity");
    assert.equal(caller.Account, "368992683803"); assert.equal(caller.Arn, issued.AssumedRoleUser?.Arn);
    assert.equal(caller.UserId, issued.AssumedRoleUser?.AssumedRoleId);
    const expires = new Date(session.Expiration).getTime();
    assert(expires > now() + 120000 && expires <= now() + 901000);
    const { SignatureV4 } = sdk("@smithy/signature-v4"), { Sha256 } = sdk("@aws-crypto/sha256-js");
    const signer = new SignatureV4({ credentials: credentials(session), region: "eu-west-2", service: "sts", sha256: Sha256 });
    const deadline = Math.min(now() + 300000, expires - 120000);
    for (let attempt = 0; attempt < 60 && now() < deadline; attempt++) {
      const proof = await signer.presign({ protocol: "https:", hostname: "sts.eu-west-2.amazonaws.com", method: "GET", path: "/", headers: { host: "sts.eu-west-2.amazonaws.com", "x-mscqr-component-binding": sessionProofBinding(binding) }, query: { Action: "GetCallerIdentity", Version: "2011-06-15" } }, { expiresIn: 60, signingDate: new Date(now()) });
      try {
        const evidence = await authenticateComponentSession({ query: proof.query }, binding, { issuanceEvents, ...(verify ? { sts: verify } : {}), now: now() });
        assert.equal(Date.parse(evidence.expiresAt), expires);
        return evidence;
      } catch { if (now() + 5000 >= deadline) break; await sleep(5000); }
    }
    throw new Error("Bootstrap MFA issuance evidence unavailable");
  } finally {
    code = "";
    for (const value of secrets) if (value) for (const field of ["AccessKeyId", "SecretAccessKey", "SessionToken"]) delete value[field];
    for (const instance of clients) instance.close();
  }
}
