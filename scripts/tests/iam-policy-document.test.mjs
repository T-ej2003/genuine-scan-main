import assert from "node:assert/strict";
import test from "node:test";
import { normalizeIamPolicyDocument } from "../aws/iam-policy-document.mjs";

const document = { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "kms:GetPublicKey", Resource: "*" }] };

test("normalizes the AWS CLI parsed-object PolicyVersion.Document representation", () => {
  assert.deepEqual(normalizeIamPolicyDocument(document), document);
});

test("normalizes raw JSON and RFC3986-encoded policy documents", () => {
  assert.deepEqual(normalizeIamPolicyDocument(JSON.stringify(document)), document);
  assert.deepEqual(normalizeIamPolicyDocument(encodeURIComponent(JSON.stringify(document))), document);
});

test("rejects malformed, null, array, and primitive policy documents", () => {
  for (const value of ["{bad", "%7Bbad%ZZ", null, [], 1, true]) {
    assert.throws(() => normalizeIamPolicyDocument(value), /policy document/);
  }
});
