#!/usr/bin/env node
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { cleanSource } from "./component-iam-installation.mjs";
import { buildComponentBrokerPackage } from "./component-broker-package.mjs";
import { authenticateBrokerPolicySuccessorPublication } from "./component-iam-authorization.mjs";
import { executeBrokerPolicySuccessor } from "./component-broker-policy-successor.mjs";
import { brokerPolicySuccessor, brokerPolicySuccessorCapabilitySet, brokerPolicySuccessorConfigurations } from "./component-broker-policy-successor-contract.mjs";
import { authenticateBootstrapOperator } from "./component-bootstrap-operator.mjs";
import { brokerPolicySuccessorManagedIdentities, componentBrokerArn, identityBootstrap } from "./component-installation-identity-contract.mjs";
import { canonical, installationIdentity } from "./component-iam-installation-contract.mjs";
import { createBrokerPolicySuccessorRootMfaSession } from "./component-broker-policy-successor-root-mfa.mjs";

const sdk = createRequire(new URL("../../infra/aws/terraform/production-component-deployment-state/broker-package/package.json", import.meta.url));
const rootArn = `arn:aws:iam::${identityBootstrap.account}:root`;
const expiration = value => /^\d{4}-\d{2}-\d{2}T/.test(value || "") ? Date.parse(value) : Date.parse(`${value} UTC`);

export function assertBrokerPolicySuccessorIamRequest(operation, input) {
  const identity = brokerPolicySuccessorManagedIdentities().find(({ role }) => role === input.RoleName);
  assert(identity, "Alternate broker identity forbidden");
  if (input.PolicyName !== undefined) assert.equal(input.PolicyName, identity.policyName);
  if (operation === "PutRolePolicy") {
    assert([installationIdentity.provisionerRole, installationIdentity.terraformRole, identityBootstrap.installationRole, identityBootstrap.cleanupRole, identityBootstrap.authorizationRole].includes(identity.role), "Non-successor policy mutation forbidden");
    assert.equal(input.PolicyDocument, canonical(identity.policy));
  }
}

export async function convergeRootMfaIssuance({ events, accessKeyId, rootExpires, rootArn: expectedRootArn = rootArn, now = Date.now, sleep = delay, maxWaitMs = 300000 }) {
  const deadline = Math.min(now() + maxWaitMs, rootExpires - 120000);
  while (now() < deadline) {
    const matches = (await events("GetSessionToken")).filter(value => value.responseElements?.credentials?.accessKeyId === accessKeyId);
    assert(matches.length <= 1, "Unique root MFA GetSessionToken issuance required");
    if (matches.length === 1) {
      const event = matches[0]; assert.equal(event.userIdentity?.type, "Root"); assert.equal(event.userIdentity?.arn, expectedRootArn); assert.equal(event.userIdentity?.sessionContext?.attributes?.mfaAuthenticated, "true"); assert.equal(event.errorCode, undefined);
      const expires = expiration(event.responseElements?.credentials?.expiration); assert.equal(expires, rootExpires, "Root MFA issuance expiration differs"); return event;
    }
    if (now() + 5000 >= deadline) break; await sleep(5000);
  }
  throw new Error("Root MFA GetSessionToken issuance evidence unavailable");
}

export async function lookupCloudTrailEvents({ lookup, eventName, now = Date.now }) {
  const EndTime = new Date(now()), invariant = Object.freeze({
    LookupAttributes: Object.freeze([Object.freeze({ AttributeKey: "EventName", AttributeValue: eventName })]),
    StartTime: new Date(EndTime.getTime() - 3600000), EndTime,
  });
  const values = [], seen = new Set(); let NextToken;
  do {
    const page = await lookup("LookupEvents", { ...invariant, ...(NextToken ? { NextToken } : {}) });
    for (const event of page.Events || []) values.push(JSON.parse(event.CloudTrailEvent));
    NextToken = page.NextToken;
    if (NextToken) { assert(!seen.has(NextToken) && seen.size < 20); seen.add(NextToken); }
  } while (NextToken);
  return values;
}

export async function administrativeAdapter(packageEvidence, { root = createBrokerPolicySuccessorRootMfaSession, now = Date.now, sleep = delay } = {}) {
  const session = await root(), credentials = session.credentials;
  const clients = [], create = (service, name, endpoint, region = identityBootstrap.region) => { const library = sdk(`@aws-sdk/client-${service}`), client = new library[`${name}Client`]({ credentials, region, endpoint, maxAttempts: 1 }); clients.push(client); return async (operation, input = {}) => client.send(new library[`${operation}Command`](input)); };
  try {
    assert.deepEqual(Object.keys(credentials || {}).sort(), ["accessKeyId", "secretAccessKey", "sessionToken"]); assert(Object.values(credentials).every(value => typeof value === "string" && value), "Fresh MFA-backed root session credentials required");
    const sts = create("sts", "STS", "https://sts.eu-west-2.amazonaws.com"), caller = await sts("GetCallerIdentity"); assert.deepEqual({ Account: caller.Account, Arn: caller.Arn }, { Account: identityBootstrap.account, Arn: rootArn });
    const cloudtrail = create("cloudtrail", "CloudTrail", "https://cloudtrail.eu-west-2.amazonaws.com"), accessKeyId = credentials.accessKeyId;
    const events = eventName => lookupCloudTrailEvents({ lookup: cloudtrail, eventName, now });
    const rootExpires = Date.parse(session.expiresAt); assert(Number.isFinite(rootExpires) && now() + 120000 < rootExpires && rootExpires <= now() + 3601000, "Root MFA session is not fresh");
    await convergeRootMfaIssuance({ events, accessKeyId, rootExpires, now, sleep });
    const permitted = new Set(brokerPolicySuccessorCapabilitySet().Statement.flatMap(({ Action }) => [].concat(Action)));
    const configurations = Object.values(brokerPolicySuccessorConfigurations(packageEvidence));
    const confined = (service, name, endpoint, region) => { const send = create(service, name, endpoint, region); return (operation, input = {}) => {
      const action = `${service}:${service === "s3" && operation === "ListObjectsV2" ? "ListBucket" : operation}`; assert(permitted.has(action), "Unsupported broker-policy successor API");
      if (service === "lambda") {
        assert.equal(input.FunctionName, installationIdentity.functionName); if (input.Qualifier !== undefined) assert(["1", "2", "3", "4", "5", "6", "7", "8", "9"].includes(input.Qualifier));
        if (operation === "UpdateFunctionCode") { assert.deepEqual(Object.keys(input).sort(), ["FunctionName", "Publish", "RevisionId", "ZipFile"]); assert.equal(input.Publish, false); assert.equal(createHash("sha256").update(input.ZipFile).digest("hex"), packageEvidence.packageSha256); }
        if (operation === "UpdateFunctionConfiguration") assert(configurations.some(configuration => canonical(input) === canonical({ FunctionName: installationIdentity.functionName, Description: configuration.Description, RevisionId: input.RevisionId })), "Unreviewed successor configuration");
        if (operation === "PublishVersion") assert(configurations.some(configuration => canonical(input) === canonical({ FunctionName: installationIdentity.functionName, Description: configuration.Description, CodeSha256: configuration.CodeSha256, RevisionId: input.RevisionId })), "Unreviewed successor publication");
      } else if (service === "iam") assertBrokerPolicySuccessorIamRequest(operation, input);
      else {
        assert.equal(input.Bucket, identityBootstrap.bucket); assert([`${identityBootstrap.prefix}identity-bootstrap.json`, brokerPolicySuccessor.reservationKey].includes(input.Key || input.Prefix));
      }
      return send(operation, input);
    }; };
    return { iam: confined("iam", "IAM", "https://iam.amazonaws.com", "us-east-1"), lambda: confined("lambda", "Lambda", "https://lambda.eu-west-2.amazonaws.com"), s3: confined("s3", "S3", "https://s3.eu-west-2.amazonaws.com"), authenticate: async () => { assert(now() + 120000 < rootExpires, "Root MFA session expired"); const value = await sts("GetCallerIdentity"); assert.equal(value.Arn, rootArn); }, issuanceEvents: () => events("AssumeRole"),
      close() { for (const client of clients) client.destroy(); session.close(); } };
  } catch (error) { for (const client of clients) client.destroy(); session.close(); throw error; }
}

export async function run(argv = process.argv.slice(2), { source = cleanSource, build = buildComponentBrokerPackage, authorize = authenticateBrokerPolicySuccessorPublication, admin = administrativeAdapter, human = authenticateBootstrapOperator, execute = executeBrokerPolicySuccessor } = {}) {
  const [mode, runId, transitionId] = argv; assert.deepEqual([mode, argv.length], ["execute", 3]); assert.match(runId || "", /^[1-9][0-9]*$/); assert.match(transitionId || "", /^[a-f0-9-]{36}$/);
  const sourceSha = source(), packageEvidence = await build(); assert.equal(packageEvidence.manifest.sourceSha, sourceSha);
  const approved = authorize({ runId, transitionId, sourceSha }, packageEvidence), { authorizationSha256, ...authorization } = approved; assert.equal(source(), sourceSha);
  const authority = await admin(packageEvidence);
  try { const operatorProof = await human({ sourceSha, transitionId, authorizationSha256, purpose: "BROKER_POLICY_SUCCESSOR" }, { issuanceEvents: authority.issuanceEvents }); const result = await execute({ authorization, packageEvidence, operatorProof }, { ...authority, authenticate: async () => { assert.equal(source(), sourceSha); await authority.authenticate(); } }); return { state: result.brokerPolicySuccessor.state, sourceSha, transitionId, authorizationSha256 }; }
  finally { authority.close(); }
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) run().then(result => process.stdout.write(`${JSON.stringify(result)}\n`)).catch(() => { process.stderr.write("Component broker-policy successor rejected; preserve both journals and reconcile exact generation state.\n"); process.exitCode = 1; });
