import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { promptProductionMfaCode } from "../security/production-interactive-mfa-provider.mjs";
import { createProductionAwsCredentialEnvironment, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { identityBootstrap, componentBrokerArn } from "./component-installation-identity-contract.mjs";
import { brokerEntryPointCandidates } from "./component-broker-configuration.mjs";
import { sessionProofBinding, assertComponentSessionRecord } from "./component-session-proof.mjs";
import { executeIsolatedTerraform } from "./component-terraform-runner.mjs";
import { createTerraformStateBoundary } from "./component-terraform-state.mjs";

const requireSdk = createRequire(new URL("../../infra/aws/terraform/production-component-deployment-state/broker-package/package.json", import.meta.url));
const operator = "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator";
const roles = { INSTALL: identityBootstrap.installationRole, CLEANUP: identityBootstrap.cleanupRole, TERRAFORM: "mscqr-production-component-table-installer" };
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
export async function establishComponentSession(binding, dependencies = {}) {
  sessionProofBinding(binding);
  return establish(binding, dependencies);
}

// Cleanup retrieves its original coordinates from the fixed broker-owned AWS
// archive, not a retained GitHub artifact or caller-selected authorization file.
export async function establishComponentCleanupSession(transitionId, dependencies = {}) {
  assert.match(transitionId || "", /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
  return establish({ transitionId, purpose: "CLEANUP" }, dependencies, "CLEANUP");
}

export async function establishComponentTerraformSession(binding, dependencies = {}) {
  assert.deepEqual(Object.keys(binding).sort(), ["sourceSha", "transitionId"]);
  assert.match(binding.sourceSha || "", /^[a-f0-9]{40}$/);
  assert.match(binding.transitionId || "", /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
  return establish({ ...binding, purpose: "TERRAFORM" }, dependencies, "TERRAFORM");
}

async function establish(binding, { loadUser = loadOperator, sts = stsTransport, mfa = () => promptProductionMfaCode({ prompt: "Component installation operator MFA code: " }), invoke, isolated = executeIsolatedTerraform, state = createTerraformStateBoundary, now = Date.now, sleep = delay } = {}, discovery = null) {
  const fixedBinding = structuredClone(binding);
  if (!discovery) sessionProofBinding(fixedBinding);
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
    const send = async (payload) => {
      assert(now() < expires, "AWS session expired");
      const versions = brokerEntryPointCandidates(fixedBinding.purpose === "CLEANUP" ? "CLEANUP" : "INSTALL");
      let result, version;
      for (const candidate of versions) {
        const input = { FunctionName: `${componentBrokerArn}:${candidate}`, InvocationType: "RequestResponse", Payload: Buffer.from(JSON.stringify(payload)) };
        try {
          if (invoke) result = await invoke(input);
          else {
            const sdk = requireSdk("@aws-sdk/client-lambda");
            const client = new sdk.LambdaClient(options(scoped, "lambda"));
            try { result = await client.send(new sdk.InvokeCommand(input)); }
            finally { client.destroy(); }
          }
          version = candidate;
          break;
        } catch (error) {
          if (candidate !== versions[0] || error?.name !== "AccessDeniedException") throw error;
        }
      }
      assert(result && version, "No authorized fixed broker entry point");
      assert.equal(result.StatusCode, 200);
      assert(!result.FunctionError, "Broker rejected the request; authenticate live evidence before retry");
      assert.equal(result.ExecutedVersion, version);
      return JSON.parse(Buffer.from(result.Payload).toString("utf8"));
    };
    if (discovery) {
      const archived = await send(discovery === "TERRAFORM"
        ? { operation: "TERRAFORM_CONTEXT", transitionId: fixedBinding.transitionId }
        : { operation: "CLEANUP_CONTEXT" });
      sessionProofBinding(archived);
      assert.equal(archived.purpose, discovery);
      assert.equal(archived.transitionId, fixedBinding.transitionId, "Different cleanup transition");
      // The executing fixed broker authenticates its exact effective trust
      // anchor before returning this archive-owned predecessor binding. The
      // local source argument still fences the current activation workflow;
      // the signed STS proof must bind the historical installation receipt.
      Object.assign(fixedBinding, archived);
    }
    const signedPayload = async operation => {
      const signed = await signer.presign({ protocol: "https:", hostname: "sts.eu-west-2.amazonaws.com", method: "GET", path: "/", headers: { host: "sts.eu-west-2.amazonaws.com", "x-mscqr-component-binding": sessionProofBinding(fixedBinding) }, query: { Action: "GetCallerIdentity", Version: "2011-06-15" } }, { expiresIn: 60, signingDate: new Date(now()) });
      return { operation, transitionId: fixedBinding.transitionId, authorizationSha256: fixedBinding.authorizationSha256, proof: { query: signed.query } };
    };
    const prove = async () => {
        assert(now() < expires, "AWS session expired");
        const deadline = Math.min(now() + 300000, expires - 120000);
        for (let attempt = 0; attempt < 60 && now() < deadline; attempt++) {
          try {
            const proof = await send(await signedPayload({ INSTALL: "PROVE_INSTALL_SESSION", CLEANUP: "PROVE_CLEANUP_SESSION", TERRAFORM: "PROVE_TERRAFORM_SESSION" }[fixedBinding.purpose]));
            const { session, ...envelope } = proof;
            if (fixedBinding.purpose === "TERRAFORM") {
              assertComponentSessionRecord(session); assert.equal(session.purpose, "TERRAFORM");
              for (const field of ["sourceSha", "transitionId", "authorizationSha256"]) assert.equal(session[field], fixedBinding[field]);
              assert.equal(session.principal, principal); assert.equal(session.expiresAt, new Date(expires).toISOString());
            } else assert.equal(session, undefined);
            assert.deepEqual(envelope, { state: "SESSION_VERIFIED", principal, expiresAt: new Date(expires).toISOString(), sourceSha: fixedBinding.sourceSha,
              transitionId: fixedBinding.transitionId, authorizationSha256: fixedBinding.authorizationSha256 });
            return session;
          } catch {
            // Only read-only proof probes are retried, never INSTALL or CLOSE.
            if (now() + 5000 >= deadline) break;
            await sleep(5000);
          }
        }
        throw new Error("AWS issuance proof unavailable before the bounded deadline");
    };
    if (fixedBinding.purpose === "TERRAFORM") {
      let consumed = false, applying = false, recovering = false, reserved = false, activeSession;
      const boundary = state(scoped, fixedBinding);
      const close = () => { applying = false; recovering = false; boundary.close(); for (const field of ["AccessKeyId", "SecretAccessKey", "SessionToken"]) delete scoped[field]; };
      return Object.freeze({ principal, expiresAt: new Date(expires).toISOString(),
        close,
        async inspect() { await prove(); return boundary.inspect(); },
        async inspectPartialActivationRecovery() { await prove(); return boundary.inspectPartialActivationRecovery(); },
        async inspectPartialActivationRecoveryContinuation(preparation, preparationSha256) { await prove(); return boundary.inspectPartialActivationRecoveryContinuation(preparation, preparationSha256); },
        activatePartialActivationRecovery() { assert(!consumed && !applying && !recovering && now() < expires, "No fresh recovery session"); recovering = true; },
        async releasePartialActivationLock(lock, claimEtag, record, preparation, preparationSha256) { assert(recovering && now() < expires, "No active recovery authorization"); return boundary.releasePartialActivationLock(lock, claimEtag, record, preparation, preparationSha256); },
        async readRecoveredTerraformState() { assert(recovering && now() < expires, "No active recovery authorization"); return boundary.readRecoveredTerraformState(); },
        async beginPartialActivationRecovery(record, preparation, preparationSha256, continuation) { assert(recovering && now() < expires, "No active recovery authorization"); return boundary.beginPartialActivationRecovery(record, preparation, preparationSha256, continuation); },
        async reserve(record) {
          assert(applying && !reserved && now() < expires, "No active unconsumed apply authorization");
          reserved = true; return boundary.reserve({ ...record, session: activeSession });
        },
        async execute({ mode, plan }, { checkpoint }) {
          assert(!consumed, "Terraform session execution already consumed"); consumed = true;
          assert(["prepare", "apply", "recover", "recover-verify"].includes(mode)); assert.equal(typeof checkpoint, "function");
          try {
            const session = await prove();
            activeSession = session;
            applying = mode === "apply"; recovering = mode.startsWith("recover");
            return { session, result: await isolated({ mode, plan, expiresAt: session.expiresAt,
              credentials: { AccessKeyId: scoped.AccessKeyId, SecretAccessKey: scoped.SecretAccessKey, SessionToken: scoped.SessionToken } }, { checkpoint: async value => {
                await checkpoint(value);
                if (value.stage === "apply") assert(reserved, "Exact one-time activation reservation required");
              } }) };
          } finally { close(); }
        },
      });
    }
    return Object.freeze({
      principal, expiresAt: new Date(expires).toISOString(),
      async invoke(operation) {
        assert((fixedBinding.purpose === "INSTALL" ? ["INSTALL", "INSPECT"] : ["CLOSE"]).includes(operation), "Unsupported session operation");
        await prove();
        return send(await signedPayload(operation));
      },
    });
  } finally {
    code = "";
    for (const value of new Set([base, human])) if (value) for (const field of ["AccessKeyId", "SecretAccessKey", "SessionToken"]) delete value[field];
    for (const client of transports) client.close();
  }
}
