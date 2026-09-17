import assert from "node:assert/strict";
import crypto from "node:crypto";
import { identityBootstrap, assertExpiredSession } from "./component-installation-identity-contract.mjs";
import { canonical, digest } from "./component-iam-installation-contract.mjs";

const host = "sts.eu-west-2.amazonaws.com";
const queryNames = ["Action", "Version", "X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires", "X-Amz-Security-Token", "X-Amz-Signature", "X-Amz-SignedHeaders"].sort();
const roles = { INSTALL: identityBootstrap.installationRole, CLEANUP: identityBootstrap.cleanupRole };
function awsExpiration(value) {
  assert(typeof value === "string", "AWS expiration missing");
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) return Date.parse(value);
  // CloudTrail also serializes STS expiration without a zone. Its value is UTC,
  // not the operator machine's local timezone. Reject other implicit formats.
  assert(/^[A-Z][a-z]{2} \d{1,2}, \d{4},? \d{1,2}:\d{2}:\d{2} (?:AM|PM)$/.test(value), "Unexpected AWS expiration format");
  return Date.parse(`${value} UTC`);
}
export function sessionProofBinding(binding) {
  assert.deepEqual(Object.keys(binding).sort(), ["authorizationSha256", "purpose", "sourceSha", "transitionId"]);
  const { sourceSha, transitionId, authorizationSha256, purpose } = binding;
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  assert.match(transitionId || "", /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
  assert.match(authorizationSha256 || "", /^[a-f0-9]{64}$/);
  assert(Object.hasOwn(roles, purpose));
  return crypto.createHash("sha256").update(JSON.stringify([sourceSha, transitionId, authorizationSha256, purpose])).digest("hex");
}

// A presigned GetCallerIdentity proves possession of this session, not merely
// knowledge of its ARN. AWS validates the signature at a fixed STS endpoint.
// CloudTrail then supplies the matching AWS-issued expiration and MFA chain.
// Request/query credentials are transient and must never enter durable evidence.
export async function authenticateComponentSession(proof, binding, { sts = verifyPresignedCaller, issuanceEvents, now = Date.now() }) {
  const bindingHash = sessionProofBinding(binding);
  assert.deepEqual(Object.keys(proof).sort(), ["query"]);
  assert(proof.query && typeof proof.query === "object" && !Array.isArray(proof.query));
  assert.deepEqual(Object.keys(proof.query).sort(), queryNames);
  const q = proof.query;
  for (const value of Object.values(q)) assert(typeof value === "string");
  assert.equal(q.Action, "GetCallerIdentity");
  assert.equal(q.Version, "2011-06-15");
  assert.equal(q["X-Amz-Algorithm"], "AWS4-HMAC-SHA256");
  assert.equal(q["X-Amz-Expires"], "60");
  assert.equal(q["X-Amz-SignedHeaders"], "host;x-mscqr-component-binding");
  assert.match(q["X-Amz-Signature"], /^[a-f0-9]{64}$/);
  assert(q["X-Amz-Security-Token"].length >= 16 && q["X-Amz-Security-Token"].length <= 8192);
  assert.match(q["X-Amz-Date"], /^\d{8}T\d{6}Z$/);
  const date = q["X-Amz-Date"];
  const signedAt = Date.parse(`${date.slice(0, 4)}-${date.slice(4, 6)}-${date.slice(6, 8)}T${date.slice(9, 11)}:${date.slice(11, 13)}:${date.slice(13, 15)}Z`);
  assert(Number.isFinite(now) && Number.isFinite(signedAt) && signedAt <= now && now < signedAt + 60000, "Session proof expired or future dated");
  const credential = q["X-Amz-Credential"].split("/");
  assert.equal(credential.length, 5);
  assert.match(credential[0], /^[A-Z0-9]{16,128}$/);
  assert.deepEqual(credential.slice(1), [date.slice(0, 8), "eu-west-2", "sts", "aws4_request"]);
  // Transport is injected only in offline tests. The runtime uses the fixed
  // HTTPS endpoint and refuses redirects; no caller URL/header/body is accepted.
  const caller = await sts({ host, query: q, headers: { "x-mscqr-component-binding": bindingHash } });
  const principal = `arn:aws:sts::${identityBootstrap.account}:assumed-role/${roles[binding.purpose]}/component-${binding.transitionId}`;
  assert.equal(caller.Account, identityBootstrap.account);
  assert.equal(caller.Arn, principal);
  assert(typeof caller.UserId === "string" && caller.UserId.length > 0);
  const events = await issuanceEvents();
  const matches = events.filter((event) => event.responseElements?.credentials?.accessKeyId === credential[0]);
  assert.equal(matches.length, 1, "Unique AWS issuance event required");
  const event = matches[0];
  assert.equal(event.eventSource, "sts.amazonaws.com");
  assert.equal(event.eventName, "AssumeRole");
  assert.equal(event.awsRegion, identityBootstrap.region);
  assert.equal(event.recipientAccountId, identityBootstrap.account);
  assert.equal(event.errorCode, undefined);
  assert.equal(event.userIdentity?.type, "IAMUser");
  assert.equal(event.userIdentity?.accountId, identityBootstrap.account);
  const operatorArn = `arn:aws:iam::${identityBootstrap.account}:user/mscqr-production-bootstrap-operator`;
  assert.equal(event.userIdentity?.arn, operatorArn);
  assert.equal(event.userIdentity?.sessionContext?.attributes?.mfaAuthenticated, "true");
  assert.equal(event.requestParameters?.roleArn, `arn:aws:iam::${identityBootstrap.account}:role/${roles[binding.purpose]}`);
  assert.equal(event.requestParameters?.roleSessionName, `component-${binding.transitionId}`);
  assert.equal(event.requestParameters?.durationSeconds, identityBootstrap.sessionSeconds);
  assert.equal(event.responseElements?.assumedRoleUser?.arn, principal);
  assert.equal(event.responseElements?.assumedRoleUser?.assumedRoleId, caller.UserId);
  assert.match(event.eventID || "", /^[a-f0-9-]{36}$/);
  const eventTime = Date.parse(event.eventTime);
  const expires = awsExpiration(event.responseElements.credentials.expiration);
  // CloudTrail eventTime has second precision; tolerate that rounding only.
  assert(Number.isFinite(eventTime) && Number.isFinite(expires) && eventTime <= now && expires > now);
  assert(expires > eventTime && expires - eventTime <= 901000, "Unexpected issuance duration");
  return { account: identityBootstrap.account, region: identityBootstrap.region, ...binding,
    principal, issuedAt: new Date(expires - identityBootstrap.sessionSeconds * 1000).toISOString(), expiresAt: new Date(expires).toISOString(),
    issuanceEventId: event.eventID, issuanceEventTime: new Date(eventTime).toISOString(), operatorArn, mfaAuthenticated: true };
}

async function verifyPresignedCaller({ host: requestedHost, query, headers }) {
  assert.equal(requestedHost, host);
  const url = new URL(`https://${host}/`);
  url.search = new URLSearchParams(query).toString();
  const response = await fetch(url, { headers: { ...headers, Accept: "application/json" }, redirect: "error", signal: AbortSignal.timeout(10000) });
  assert(response.ok, "AWS session proof rejected");
  const body = await response.text();
  assert(body.length < 32768, "Unexpected STS response size");
  const caller = JSON.parse(body).GetCallerIdentityResponse?.GetCallerIdentityResult;
  assert(caller && typeof caller === "object", "STS identity response missing");
  return { Account: caller.Account, Arn: caller.Arn, UserId: caller.UserId };
}

// Only broker-authenticated session records reach this function in production.
// S3 owns serialization; actual AWS session expiration fences old authority.
export function assertComponentSessionRecord(session) {
  assert.deepEqual(Object.keys(session).sort(), ["account", "region", "sourceSha", "transitionId", "authorizationSha256", "purpose", "principal", "issuedAt", "expiresAt", "issuanceEventId", "issuanceEventTime", "operatorArn", "mfaAuthenticated"].sort());
  sessionProofBinding({ sourceSha: session.sourceSha, transitionId: session.transitionId, authorizationSha256: session.authorizationSha256, purpose: session.purpose });
  assert.equal(session.account, identityBootstrap.account);
  assert.equal(session.region, identityBootstrap.region);
  assert.equal(session.mfaAuthenticated, true);
  assert.match(session.issuanceEventId || "", /^[a-f0-9-]{36}$/);
  assert.equal(session.principal, `arn:aws:sts::${identityBootstrap.account}:assumed-role/${roles[session.purpose]}/component-${session.transitionId}`);
  assert.equal(session.operatorArn, `arn:aws:iam::${identityBootstrap.account}:user/mscqr-production-bootstrap-operator`);
  assert.equal(Date.parse(session.expiresAt) - Date.parse(session.issuedAt), identityBootstrap.sessionSeconds * 1000);
  for (const field of ["issuedAt", "expiresAt", "issuanceEventTime"]) assert.equal(new Date(Date.parse(session[field])).toISOString(), session[field]);
  return true;
}

export async function claimComponentSession({ session, s3, now = Date.now }) {
  assertComponentSessionRecord(session);
  assert.equal(session.purpose, "INSTALL");
  const key = `${identityBootstrap.prefix}installation-session.json`;
  const read = async () => {
    const list = await s3("ListObjectsV2", { Bucket: identityBootstrap.bucket, Prefix: key });
    assert.equal(list.IsTruncated, false);
    assert((list.Contents || []).length <= 1 && (list.Contents || []).every(({ Key }) => Key === key));
    if (!list.Contents?.length) return null;
    const response = await s3("GetObject", { Bucket: identityBootstrap.bucket, Key: key });
    assert(response.ETag);
    const record = JSON.parse(await response.Body.transformToString());
    assert.deepEqual(Object.keys(record).sort(), ["history", "schemaVersion", "session"]);
    assert.equal(record.schemaVersion, 1);
    assert(Array.isArray(record.history) && record.history.length <= 100, "Unexpected session history");
    for (const item of [...record.history, record.session]) assertComponentSessionRecord(item);
    assert.equal(record.session.sourceSha, session.sourceSha);
    assert.equal(record.session.transitionId, session.transitionId);
    return { record, etag: response.ETag };
  };
  const prior = await read();
  const sessionHash = digest(session);
  const same = prior && digest(prior.record.session) === sessionHash;
  if (prior && !same) {
    assertExpiredSession(prior.record.session, now());
    assert(Date.parse(session.issuedAt) > Date.parse(prior.record.session.expiresAt) + identityBootstrap.expiryMarginSeconds * 1000, "Replacement session was issued before old authority was safely expired");
    for (const previous of [...prior.record.history, prior.record.session]) {
      assert.notEqual(previous.authorizationSha256, session.authorizationSha256, "Fresh explicit authorization required");
      assert.notEqual(previous.issuanceEventId, session.issuanceEventId, "Consumed session issuance");
    }
  }
  if (!same) {
    assert(now() < Date.parse(session.expiresAt), "Session expired before claim");
    const record = { schemaVersion: 1, session, history: prior ? [...prior.record.history, prior.record.session] : [] };
    assert(record.history.length <= 100, "Session history requires separate reviewed recovery");
    try {
      await s3("PutObject", { Bucket: identityBootstrap.bucket, Key: key, Body: canonical(record), ServerSideEncryption: "AES256", ...(prior ? { IfMatch: prior.etag } : { IfNoneMatch: "*" }) });
    } catch (error) {
      if (["PreconditionFailed", "ConditionalRequestConflict"].includes(error.name)) throw error;
      const observed = await read();
      if (!observed || canonical(observed.record) !== canonical(record)) throw error;
    }
  }
  const guard = async () => {
    assert(now() < Date.parse(session.expiresAt), "AWS mutation session expired");
    const current = await read();
    assert(current && digest(current.record.session) === sessionHash, "Session ownership changed");
  };
  await guard();
  return guard;
}
