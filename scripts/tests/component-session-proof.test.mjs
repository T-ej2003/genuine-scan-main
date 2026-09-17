import test from "node:test";
import assert from "node:assert/strict";
import { authenticateComponentSession, sessionProofBinding } from "../aws/component-session-proof.mjs";
import { identityBootstrap, assertExpiredSession } from "../aws/component-installation-identity-contract.mjs";

function fixture(purpose = "INSTALL") {
  const now = Date.parse("2026-09-17T12:00:01Z");
  const binding = { sourceSha: "a".repeat(40), transitionId: "12345678-1234-4234-8234-123456789abc", authorizationSha256: "b".repeat(64), purpose };
  const key = ["A", "S", "I", "A"].join("") + "0".repeat(16);
  const query = { Action: "GetCallerIdentity", Version: "2011-06-15", "X-Amz-Algorithm": "AWS4-HMAC-SHA256", "X-Amz-Credential": `${key}/20260917/eu-west-2/sts/aws4_request`,
    "X-Amz-Date": "20260917T120000Z", "X-Amz-Expires": "60", "X-Amz-Security-Token": "disposable-test-session", "X-Amz-Signature": "c".repeat(64), "X-Amz-SignedHeaders": "host;x-mscqr-component-binding" };
  const role = purpose === "INSTALL" ? identityBootstrap.installationRole : identityBootstrap.cleanupRole;
  const principal = `arn:aws:sts::368992683803:assumed-role/${role}/component-${binding.transitionId}`;
  const caller = { Account: "368992683803", Arn: principal, UserId: "role-id:session" };
  const event = { eventID: "12345678-1234-4234-8234-123456789def", eventTime: "2026-09-17T12:00:00Z", eventSource: "sts.amazonaws.com", eventName: "AssumeRole", awsRegion: "eu-west-2", recipientAccountId: "368992683803",
    userIdentity: { type: "IAMUser", accountId: "368992683803", arn: "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator", sessionContext: { attributes: { mfaAuthenticated: "true" } } },
    requestParameters: { roleArn: `arn:aws:iam::368992683803:role/${role}`, roleSessionName: `component-${binding.transitionId}`, durationSeconds: 900 },
    responseElements: { credentials: { accessKeyId: key, expiration: "2026-09-17T12:15:00Z" }, assumedRoleUser: { arn: principal, assumedRoleId: caller.UserId } } };
  const f = { binding, proof: { query }, caller, events: [event], now, verified: false };
  const signedBinding = sessionProofBinding(binding);
  f.authenticate = () => authenticateComponentSession(f.proof, f.binding, { now: f.now,
    sts: async (request) => {
      assert.equal(request.host, "sts.eu-west-2.amazonaws.com");
      assert.deepEqual(request.headers, { "x-mscqr-component-binding": signedBinding });
      assert.deepEqual(request.query, query);
      f.verified = true; return f.caller;
    }, issuanceEvents: async () => { assert(f.verified); return f.events; } });
  return f;
}

test("AWS signature validation plus unique MFA issuance evidence supplies non-secret actual session expiry", async () => {
  for (const purpose of ["INSTALL", "CLEANUP"]) {
    const f = fixture(purpose);
    const record = await f.authenticate();
    assert.equal(record.expiresAt, "2026-09-17T12:15:00.000Z");
    assert.equal(record.mfaAuthenticated, true);
    assert.equal(record.purpose, purpose);
    for (const value of [f.proof.query["X-Amz-Security-Token"], f.events[0].responseElements.credentials.accessKeyId]) assert(!JSON.stringify(record).includes(value));
    if (purpose === "INSTALL") {
      assert.throws(() => assertExpiredSession(record, Date.parse(record.expiresAt) + 120000));
      assert(assertExpiredSession(record, Date.parse(record.expiresAt) + 120001));
    }
  }
});

for (const [name, mutate] of Object.entries({
  "caller-selected endpoint": (f) => { f.proof.url = "https://other.invalid"; },
  "unsigned binding": (f) => { f.proof.query["X-Amz-SignedHeaders"] = "host"; },
  "different action": (f) => { f.proof.query.Action = "AssumeRole"; },
  "different service": (f) => { f.proof.query["X-Amz-Credential"] = f.proof.query["X-Amz-Credential"].replace("/sts/", "/iam/"); },
  "different region": (f) => { f.proof.query["X-Amz-Credential"] = f.proof.query["X-Amz-Credential"].replace("eu-west-2", "us-east-1"); },
  "expired signature": (f) => { f.now += 60000; },
  "future signature": (f) => { f.now -= 2000; },
  "proof lifetime extended": (f) => { f.proof.query["X-Amz-Expires"] = "900"; },
  "wrong caller": (f) => { f.caller.Arn = "arn:aws:iam::368992683803:root"; },
  "wrong account": (f) => { f.caller.Account = "000000000000"; },
  "unknown binding field": (f) => { f.binding.secret = "must-not-be-archived"; },
  "source substitution after signing": (f) => { f.binding.sourceSha = "d".repeat(40); },
  "authorization substitution after signing": (f) => { f.binding.authorizationSha256 = "d".repeat(64); },
  "transition substitution after signing": (f) => { f.binding.transitionId = "12345678-1234-4234-8234-123456789def"; },
  "cleanup/install proof substitution": (f) => { f.binding.purpose = "CLEANUP"; },
  "missing issuance": (f) => { f.events = []; },
  "ambiguous issuance": (f) => { f.events.push(structuredClone(f.events[0])); },
  "OIDC issuance": (f) => { f.events[0].eventName = "AssumeRoleWithWebIdentity"; },
  "non-human provenance": (f) => { f.events[0].userIdentity.type = "AssumedRole"; },
  "MFA absent": (f) => { f.events[0].userIdentity.sessionContext.attributes.mfaAuthenticated = "false"; },
  "wrong role issuance": (f) => { f.events[0].requestParameters.roleArn += "-other"; },
  "long session requested": (f) => { f.events[0].requestParameters.durationSeconds = 3600; },
  "wrong response principal": (f) => { f.events[0].responseElements.assumedRoleUser.arn += "-other"; },
  "expired AWS session": (f) => { f.events[0].responseElements.credentials.expiration = "2026-09-17T12:00:00Z"; },
  "invalid expiry": (f) => { f.events[0].responseElements.credentials.expiration = "invalid"; },
  "extended expiry": (f) => { f.events[0].responseElements.credentials.expiration = "2026-09-17T13:00:00Z"; },
})) test(`session authentication rejects ${name}`, async () => {
  const f = fixture(); mutate(f); await assert.rejects(f.authenticate());
});

test("AWS rejection never falls back to ARN-only provenance or local issuance metadata", async () => {
  const f = fixture();
  await assert.rejects(authenticateComponentSession(f.proof, f.binding, { now: f.now, sts: async () => { throw new Error("SignatureDoesNotMatch"); }, issuanceEvents: async () => { assert.fail("Must not use CloudTrail before AWS signature authentication"); } }), /SignatureDoesNotMatch/);
});

test("CloudTrail legacy expiration is interpreted as UTC, never the host timezone", async () => {
  for (const expiration of ["Sep 17, 2026, 12:15:00 PM", "Sep 17, 2026 12:15:00 PM"]) {
    const f = fixture();
    f.events[0].responseElements.credentials.expiration = expiration;
    assert.equal((await f.authenticate()).expiresAt, "2026-09-17T12:15:00.000Z");
  }
});
