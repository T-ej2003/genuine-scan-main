import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { installationDocuments, documentBindings, digest } from "./component-iam-installation-contract.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { assertComponentSessionRecord } from "./component-session-proof.mjs";

const sdk = createRequire(new URL("../../infra/aws/terraform/production-component-deployment-state/broker-package/package.json", import.meta.url));
const bucket = "mscqr-production-terraform-state-368992683803-eu-west-2";
const key = "mscqr/production/component-deployment-state/terraform.tfstate";
const receiptKey = "mscqr/production/component-deployment-state/iam-installation.json";
const sha = bytes => createHash("sha256").update(bytes).digest("hex");

// A private adapter used only with the freshly authenticated table session.
// It exposes no caller-selected AWS action, resource, object key or document.
export function createTerraformStateBoundary(credentials, binding, { send, describe, createClient } = {}) {
  const value = { accessKeyId: credentials.AccessKeyId, secretAccessKey: credentials.SecretAccessKey, sessionToken: credentials.SessionToken };
  const call = async (service, operation, input, consume) => {
    if (send) {
      const response = await send(service, operation, input);
      return consume ? await consume(response) : response;
    }
    const library = sdk(`@aws-sdk/client-${service}`);
    const name = { iam: "IAM", s3: "S3" }[service]; assert(name);
    const options = { credentials: value, region: service === "iam" ? "us-east-1" : "eu-west-2",
      endpoint: service === "iam" ? "https://iam.amazonaws.com" : "https://s3.eu-west-2.amazonaws.com", maxAttempts: 1 };
    const client = createClient ? createClient(service, options) : new library[`${name}Client`](options);
    try {
      const response = await client.send(new library[`${operation}Command`](input));
      return consume ? await consume(response) : response;
    } finally { client.destroy(); }
  };
  const table = async () => {
    if (describe) return describe();
    // One fixed read API; reuse the already locked signer rather than adding a
    // DynamoDB mutation-capable SDK dependency to the broker package.
    const { SignatureV4 } = sdk("@smithy/signature-v4"), { Sha256 } = sdk("@aws-crypto/sha256-js");
    const signer = new SignatureV4({ credentials: value, region: "eu-west-2", service: "dynamodb", sha256: Sha256 });
    const host = "dynamodb.eu-west-2.amazonaws.com";
    const request = await signer.sign({ protocol: "https:", hostname: host, path: "/", method: "POST",
      headers: { host, "content-type": "application/x-amz-json-1.0", "x-amz-target": "DynamoDB_20120810.DescribeTable" },
      body: JSON.stringify({ TableName: "mscqr-production-component-deployment-state" }) });
    const response = await fetch(`https://${host}/`, { method: request.method, headers: request.headers, body: request.body, redirect: "error", signal: AbortSignal.timeout(10000) });
    const bytes = await response.text(); assert(bytes.length < 1024 * 1024);
    const data = JSON.parse(bytes);
    if (!response.ok) { assert.equal(response.status, 400); assert.equal(data.__type?.split("#").at(-1), "ResourceNotFoundException"); return null; }
    return data.Table;
  };
  return Object.freeze({
    async inspect() {
      assert.equal((await call("s3", "GetBucketVersioning", { Bucket: bucket })).Status, "Enabled");
      const objects = await call("s3", "ListObjectsV2", { Bucket: bucket, Prefix: key });
      assert.equal(objects.IsTruncated, false);
      assert(!(objects.Contents || []).some(object => [key, `${key}.tflock`, `${key}.initial-activation-attempt`].includes(object.Key)), "State, lock or consumed attempt already exists");
      const history = await call("s3", "ListObjectVersions", { Bucket: bucket, Prefix: key });
      assert.equal(history.IsTruncated, false);
      assert(![...(history.Versions || []), ...(history.DeleteMarkers || [])].some(object => [key, `${key}.initial-activation-attempt`].includes(object.Key)), "Historical state or activation attempt exists");
      assert.equal(await table(), null, "Component table already exists");
      // GetObject.Body is a live Node stream: consume it before its owning
      // client closes the underlying HTTPS agent.
      const bytes = await call("s3", "GetObject", { Bucket: bucket, Key: receiptKey }, received => received.Body.transformToString());
      assert(bytes.length < 1024 * 1024);
      const receipt = JSON.parse(bytes);
      assert.deepEqual(Object.keys(receipt).sort(), ["authorizationSha256", "documentBindingsSha256", "live", "schemaVersion", "sourceSha", "state", "transitionId"]);
      assert.equal(receipt.schemaVersion, 1); assert.equal(receipt.state, "IAM_VERIFIED");
      for (const field of ["sourceSha", "transitionId", "authorizationSha256"]) assert.equal(receipt[field], binding[field]);
      assert.equal(receipt.documentBindingsSha256, digest(documentBindings()));
      const targets = installationDocuments();
      assert.deepEqual(receipt.live, targets.map(({ arn }) => ({ arn, role: "EXPECTED", policy: "EXPECTED" })));
      for (const target of targets) {
        const { Role: role } = await call("iam", "GetRole", { RoleName: target.role });
        assert.equal(role.RoleName, target.role); assert.equal(role.Arn, target.arn);
        if (target.trust) {
          assert.equal(role.Path, "/"); assert.equal(role.MaxSessionDuration, 3600); assert.equal(role.PermissionsBoundary, undefined);
          assert.equal(digest(normalizeIamPolicyDocument(role.AssumeRolePolicyDocument)), target.trustSha256);
          assert.equal(role.Tags?.length, 3);
          assert.deepEqual(Object.fromEntries(role.Tags.map(({ Key, Value }) => [Key, Value])), { ManagedBy: "GuardedComponentInstaller", Environment: "production", Transition: binding.transitionId });
          const inline = await call("iam", "ListRolePolicies", { RoleName: target.role });
          assert.equal(inline.IsTruncated, false); assert.deepEqual(inline.PolicyNames, [target.policyName]);
          const attached = await call("iam", "ListAttachedRolePolicies", { RoleName: target.role });
          assert.equal(attached.IsTruncated, false); assert.deepEqual(attached.AttachedPolicies, []);
        }
        const policy = await call("iam", "GetRolePolicy", { RoleName: target.role, PolicyName: target.policyName });
        assert.equal(policy.RoleName, target.role); assert.equal(policy.PolicyName, target.policyName);
        assert.equal(digest(normalizeIamPolicyDocument(policy.PolicyDocument)), target.policySha256);
      }
      return { stateIdentity: "ABSENT", iamInstallation: { receiptSha256: sha(bytes), sourceSha: receipt.sourceSha, transitionId: binding.transitionId, authorizationSha256: binding.authorizationSha256, documentBindingsSha256: receipt.documentBindingsSha256 } };
    },
    async reserve(record) {
      assert.deepEqual(Object.keys(record).sort(), ["authorizationRunId", "iamReceiptSha256", "planSha256", "preparationSha256", "session", "sourceSha", "transitionId"]);
      assertComponentSessionRecord(record.session); assert.equal(record.session.purpose, "TERRAFORM");
      for (const field of ["sourceSha", "transitionId", "authorizationSha256"]) assert.equal(record.session[field], binding[field]);
      assert.equal(record.sourceSha, binding.sourceSha); assert.equal(record.transitionId, binding.transitionId);
      for (const field of ["planSha256", "preparationSha256", "iamReceiptSha256"]) assert.match(record[field] || "", /^[a-f0-9]{64}$/);
      assert.match(record.authorizationRunId || "", /^[1-9][0-9]*$/);
      // An ambiguous result deliberately stops. There is no second apply or
      // attempt-record deletion in this first-install path.
      const response = await call("s3", "PutObject", { Bucket: bucket, Key: `${key}.initial-activation-attempt`, Body: JSON.stringify(record), ServerSideEncryption: "AES256", IfNoneMatch: "*" });
      assert(typeof response.ETag === "string" && response.ETag, "Activation reservation response is ambiguous");
    },
    close() { for (const field of Object.keys(value)) delete value[field]; },
  });
}
