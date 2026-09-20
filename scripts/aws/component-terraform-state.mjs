import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { installationDocuments, documentBindings, digest } from "./component-iam-installation-contract.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { assertComponentSessionRecord, assertExpiredComponentSession } from "./component-session-proof.mjs";
import { assertPartialActivationHistoricalActivation, assertPartialActivationRecoveryCheckpoint, assertPartialActivationRecoveryPreparation, partialActivationRecoveryTarget } from "./component-infrastructure-partial-activation-recovery-contract.mjs";

const sdk = createRequire(new URL("../../infra/aws/terraform/production-component-deployment-state/broker-package/package.json", import.meta.url));
const bucket = "mscqr-production-terraform-state-368992683803-eu-west-2";
const key = "mscqr/production/component-deployment-state/terraform.tfstate";
const receiptKey = "mscqr/production/component-deployment-state/iam-installation.json";
const sha = bytes => createHash("sha256").update(bytes).digest("hex");
const tableName = partialActivationRecoveryTarget.id;
const tableTags = { ManagedBy: "Terraform", Environment: "production", Stack: "production-component-deployment-state" };

function assertRecoveredTable(value) {
  assert.equal(value?.TableName, tableName); assert.equal(value?.TableStatus, "ACTIVE");
  assert.equal(value?.BillingModeSummary?.BillingMode, "PAY_PER_REQUEST");
  assert.deepEqual(value?.KeySchema, [{ AttributeName: "stateKey", KeyType: "HASH" }]);
  assert.deepEqual(value?.AttributeDefinitions, [{ AttributeName: "stateKey", AttributeType: "S" }]);
  assert.equal(value?.SSEDescription?.Status, "ENABLED"); assert.equal(value?.DeletionProtectionEnabled, false);
  assert.equal(value?.StreamSpecification?.StreamEnabled, false); assert.deepEqual(value?.Replicas || [], []);
}

function assertRecoveredTableMetadata({ backups, ttl, tags }) {
  assert.equal(backups?.ContinuousBackupsDescription?.PointInTimeRecoveryDescription?.PointInTimeRecoveryStatus, "ENABLED");
  assert.equal(ttl?.TimeToLiveDescription?.TimeToLiveStatus, "DISABLED");
  assert.deepEqual(Object.fromEntries((tags?.Tags || []).map(({ Key, Value }) => [Key, Value])), tableTags);
}

function assertLock(value) {
  assert(value && typeof value === "object" && !Array.isArray(value));
  for (const field of ["ID", "Operation", "Who", "Version", "Created", "Path"]) assert(typeof value[field] === "string" && value[field], `Malformed Terraform lock ${field}`);
  assert.equal(typeof value.Info, "string", "Malformed Terraform lock Info");
  assert.equal(value.Path, `${bucket}/${key}`); return value;
}

function assertRecoveredTerraformState(bytes) {
  const value = JSON.parse(bytes);
  assert(typeof value.lineage === "string" && value.lineage); assert(Number.isSafeInteger(value.serial) && value.serial >= 1);
  assert.deepEqual((value.resources || []).map(({ mode, type, name }) => ({ mode, type, name })), [{ mode: "managed", type: "aws_dynamodb_table", name: "component_deployment_state" }]);
  const resource = value.resources[0]; assert.equal(resource.instances?.length, 1); assert.equal(resource.instances[0]?.attributes?.id, tableName);
  return { lineage: value.lineage, serial: value.serial, managedAddresses: [partialActivationRecoveryTarget.address] };
}

function assertHistoricalActivationReservation(value, historicalActivation, iamInstallation, now) {
  const historical = assertPartialActivationHistoricalActivation(historicalActivation);
  assert.deepEqual(Object.keys(value || {}).sort(), ["authorizationRunId", "iamReceiptSha256", "planSha256", "preparationSha256", "session", "sourceSha", "transitionId"]);
  assert.equal(value.authorizationRunId, historical.authorizationRunId);
  assert.equal(value.sourceSha, historical.sourceSha); assert.equal(value.planSha256, historical.planSha256);
  assert.equal(value.preparationSha256, historical.preparationSha256); assert.equal(value.transitionId, historical.transitionId);
  assert.equal(value.iamReceiptSha256, iamInstallation.receiptSha256);
  assertComponentSessionRecord(value.session); assert.equal(value.session.purpose, "TERRAFORM");
  for (const field of ["sourceSha", "transitionId", "authorizationSha256"]) assert.equal(value.session[field], iamInstallation[field]);
  assertExpiredComponentSession(value.session, now);
  return Object.freeze(structuredClone(value));
}

// A private adapter used only with the freshly authenticated table session.
// It exposes no caller-selected AWS action, resource, object key or document.
export function createTerraformStateBoundary(credentials, binding, { send, describe, recoveryDescribe, createClient, now = Date.now } = {}) {
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
  const dynamo = async (operation, payload) => {
    if (recoveryDescribe) return recoveryDescribe(operation, payload);
    const { SignatureV4 } = sdk("@smithy/signature-v4"), { Sha256 } = sdk("@aws-crypto/sha256-js");
    const signer = new SignatureV4({ credentials: value, region: "eu-west-2", service: "dynamodb", sha256: Sha256 });
    const host = "dynamodb.eu-west-2.amazonaws.com";
    const request = await signer.sign({ protocol: "https:", hostname: host, path: "/", method: "POST",
      headers: { host, "content-type": "application/x-amz-json-1.0", "x-amz-target": `DynamoDB_20120810.${operation}` }, body: JSON.stringify(payload) });
    const response = await fetch(`https://${host}/`, { method: request.method, headers: request.headers, body: request.body, redirect: "error", signal: AbortSignal.timeout(10000) });
    const bytes = await response.text(); assert(bytes.length < 1024 * 1024); assert(response.ok, `DynamoDB ${operation} failed`);
    return JSON.parse(bytes);
  };
  const authenticateInstallation = async () => {
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
      assert.equal(policy.RoleName, target.role); assert.equal(policy.PolicyName, target.policyName); assert.equal(digest(normalizeIamPolicyDocument(policy.PolicyDocument)), target.policySha256);
    }
    return { receiptSha256: sha(bytes), sourceSha: receipt.sourceSha, transitionId: binding.transitionId, authorizationSha256: binding.authorizationSha256, documentBindingsSha256: receipt.documentBindingsSha256 };
  };
  const recoveryLock = async (version, preparation, preparationSha256) => {
    const text = await call("s3", "GetObject", { Bucket: bucket, Key: partialActivationRecoveryTarget.lockKey, VersionId: version.VersionId }, received => received.Body.transformToString());
    const value = assertLock(JSON.parse(text));
    if (value.Operation !== "OperationTypeRecovery") return { version, value, checkpoint: null, sha256: sha(text) };
    return { version, value, checkpoint: assertPartialActivationRecoveryCheckpoint(JSON.parse(value.Info), preparation, preparationSha256), sha256: sha(text) };
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
      return { stateIdentity: "ABSENT", iamInstallation: await authenticateInstallation() };
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
    async inspectPartialActivationRecovery(historicalActivation) {
      const historical = assertPartialActivationHistoricalActivation(historicalActivation);
      assert.equal((await call("s3", "GetBucketVersioning", { Bucket: bucket })).Status, "Enabled");
      const objects = await call("s3", "ListObjectsV2", { Bucket: bucket, Prefix: key }); assert.equal(objects.IsTruncated, false);
      const current = new Map((objects.Contents || []).map(object => [object.Key, object]));
      assert(current.has(partialActivationRecoveryTarget.attemptKey), "Historical activation reservation is absent");
      assert(current.has(partialActivationRecoveryTarget.lockKey), "Historical native lock is absent");
      assert(!current.has(key), "Remote Terraform state already exists");
      const history = await call("s3", "ListObjectVersions", { Bucket: bucket, Prefix: key }); assert.equal(history.IsTruncated, false);
      const versions = history.Versions || [], markers = history.DeleteMarkers || [];
      assert.equal(versions.filter(({ Key }) => Key === key).length, 0, "Terraform state history exists");
      assert.equal(markers.filter(({ Key }) => Key === key).length, 0, "Terraform state delete marker exists");
      const lockVersion = versions.find(({ Key, IsLatest }) => Key === partialActivationRecoveryTarget.lockKey && IsLatest);
      assert(lockVersion?.VersionId && lockVersion.ETag, "Exact current lock version is required");
      assert.equal(markers.filter(({ Key }) => Key === partialActivationRecoveryTarget.lockKey).length, 0, "Lock delete-marker topology is unsafe");
      const lockBytes = await call("s3", "GetObject", { Bucket: bucket, Key: partialActivationRecoveryTarget.lockKey, VersionId: lockVersion.VersionId }, received => received.Body.transformToString());
      assertLock(JSON.parse(lockBytes));
      const observedTable = await table(); assertRecoveredTable(observedTable);
      assertRecoveredTableMetadata({ backups: await dynamo("DescribeContinuousBackups", { TableName: tableName }), ttl: await dynamo("DescribeTimeToLive", { TableName: tableName }), tags: await dynamo("ListTagsOfResource", { ResourceArn: observedTable.TableArn }) });
      const iamInstallation = await authenticateInstallation();
      const attemptVersion = versions.find(({ Key, IsLatest }) => Key === partialActivationRecoveryTarget.attemptKey && IsLatest);
      assert(attemptVersion?.VersionId && attemptVersion.ETag, "Exact immutable activation reservation version is required");
      const attemptText = await call("s3", "GetObject", { Bucket: bucket, Key: partialActivationRecoveryTarget.attemptKey, VersionId: attemptVersion.VersionId }, received => received.Body.transformToString());
      const attempt = assertHistoricalActivationReservation(JSON.parse(attemptText), historical, iamInstallation, now());
      return Object.freeze({ stateIdentity: "INFRASTRUCTURE_CREATED_STATE_INCOMPLETE", lock: { key: partialActivationRecoveryTarget.lockKey, sha256: sha(lockBytes), etag: lockVersion.ETag, versionId: lockVersion.VersionId }, attempt: { versionId: attemptVersion.VersionId, etag: attemptVersion.ETag, sha256: sha(attemptText), authorizationRunId: attempt.authorizationRunId }, table: partialActivationRecoveryTarget, iamInstallation });
    },
    async inspectPartialActivationRecoveryContinuation(preparation, preparationSha256) {
      assertPartialActivationRecoveryPreparation(preparation); assert.match(preparationSha256 || "", /^[a-f0-9]{64}$/); assert.equal((await call("s3", "GetBucketVersioning", { Bucket: bucket })).Status, "Enabled");
      const objects = await call("s3", "ListObjectsV2", { Bucket: bucket, Prefix: key }); assert.equal(objects.IsTruncated, false);
      const current = new Map((objects.Contents || []).map(object => [object.Key, object])); assert(current.has(partialActivationRecoveryTarget.attemptKey), "Historical activation reservation is absent");
      const history = await call("s3", "ListObjectVersions", { Bucket: bucket, Prefix: key }); assert.equal(history.IsTruncated, false);
      const versions = history.Versions || [], markers = history.DeleteMarkers || [];
      const stateVersions = versions.filter(({ Key }) => Key === key), stateMarkers = markers.filter(({ Key }) => Key === key);
      assert.equal(stateMarkers.length, 0, "Terraform state delete marker exists"); assert(stateVersions.length <= 1, "Terraform state history is ambiguous");
      const lockVersions = versions.filter(({ Key }) => Key === partialActivationRecoveryTarget.lockKey); assert(lockVersions.length > 0, "Incident lock history is absent");
      assert(lockVersions.some(({ VersionId, ETag }) => VersionId === preparation.lock.versionId && ETag === preparation.lock.etag), "Original incident lock changed");
      const iamInstallation = await authenticateInstallation();
      const attemptVersion = versions.find(({ Key, IsLatest }) => Key === partialActivationRecoveryTarget.attemptKey && IsLatest);
      assert(attemptVersion?.VersionId && attemptVersion.ETag, "Exact immutable activation reservation version is required");
      const attemptText = await call("s3", "GetObject", { Bucket: bucket, Key: partialActivationRecoveryTarget.attemptKey, VersionId: attemptVersion.VersionId }, received => received.Body.transformToString());
      const attempt = assertHistoricalActivationReservation(JSON.parse(attemptText), preparation.historicalActivation, iamInstallation, now());
      assert.deepEqual({ authorizationRunId: attempt.authorizationRunId, etag: attemptVersion.ETag, sha256: sha(attemptText), versionId: attemptVersion.VersionId }, preparation.attempt, "Historical activation reservation changed");
      const inspected = await Promise.all(lockVersions.map(version => recoveryLock(version, preparation, preparationSha256)));
      const checkpoints = inspected.filter(({ checkpoint }) => checkpoint).map(({ checkpoint, version }) => ({ checkpoint, version }));
      const latest = checkpoints[0]; assert(latest, "Recovery checkpoint is absent");
      for (const { checkpoint } of checkpoints) { assert.equal(checkpoint.recoveryTransitionId, preparation.recoveryTransitionId); assert.equal(checkpoint.preparationSha256, preparationSha256); }
      assert.notEqual(latest.checkpoint.state, "RECOVERY_CLOSED", "Recovery is already closed");
      const active = current.has(partialActivationRecoveryTarget.lockKey) ? inspected.find(({ version }) => version.IsLatest) : null;
      let retainedNativeLock = null;
      if (active) {
        if (active.checkpoint) assert.deepEqual(active.checkpoint, latest.checkpoint, "Recovery lock is not the latest checkpoint");
        else {
          assert(["OperationTypeApply", "OperationTypePlan"].includes(active.value.Operation), "Unexpected active native lock operation");
          assert.equal(active.value.Path, `${bucket}/${key}`);
          assert.match(active.value.ID, /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i, "Unexpected native import lock ID");
          assert.equal(active.value.Info, "", "Unexpected native import lock info"); assert.equal(active.value.Version, "1.15.8", "Unexpected native import lock version");
          assert.equal(active.version.IsLatest, true); const currentIndex = lockVersions.findIndex(({ VersionId }) => VersionId === active.version.VersionId);
          assert.equal(currentIndex, 0, "Native lock version ordering is ambiguous"); const predecessor = inspected[currentIndex + 1]; assert(predecessor?.checkpoint, "Native import lock has no recovery predecessor");
          const expectedCheckpoint = active.value.Operation === "OperationTypeApply" ? "RECOVERY_EXECUTING" : "RESOURCE_ADOPTED";
          assert.equal(predecessor.checkpoint.state, expectedCheckpoint, "Native lock is not bound to its recovery checkpoint");
          assert.equal(predecessor.checkpoint.recoveryTransitionId, preparation.recoveryTransitionId);
          const nativeCreated = Date.parse(active.value.Created), checkpointCreated = Date.parse(predecessor.value.Created), expiresAt = Date.parse(predecessor.checkpoint.expiresAt);
          assert(Number.isFinite(nativeCreated) && Number.isFinite(checkpointCreated) && Number.isFinite(expiresAt));
          assert(nativeCreated >= checkpointCreated, "Native import lock predates recovery checkpoint"); assert(nativeCreated < expiresAt, "Native import lock is outside the authorized recovery lifetime");
          retainedNativeLock = { key: partialActivationRecoveryTarget.lockKey, etag: active.version.ETag, versionId: active.version.VersionId, id: active.value.ID, operation: active.value.Operation, who: active.value.Who, version: active.value.Version, created: active.value.Created, path: active.value.Path };
        }
      }
      const observedTable = await table(); assertRecoveredTable(observedTable);
      assertRecoveredTableMetadata({ backups: await dynamo("DescribeContinuousBackups", { TableName: tableName }), ttl: await dynamo("DescribeTimeToLive", { TableName: tableName }), tags: await dynamo("ListTagsOfResource", { ResourceArn: observedTable.TableArn }) });
      const state = stateVersions.length ? await this.readRecoveredTerraformState() : null;
      return Object.freeze({ recovery: latest.checkpoint, currentRecoveryLock: active?.checkpoint ? { etag: active.version.ETag, versionId: active.version.VersionId } : null, retainedNativeLock, state, stateExists: state !== null, table: partialActivationRecoveryTarget, iamInstallation });
    },
    async releasePartialActivationLock(lock, claimEtag, record, preparation, preparationSha256) {
      assert.deepEqual(Object.keys(lock || {}).sort(), ["etag", "key", "sha256", "versionId"]); assert.equal(lock.key, partialActivationRecoveryTarget.lockKey); assert(typeof claimEtag === "string" && claimEtag);
      const checkpoint = assertPartialActivationRecoveryCheckpoint(record, preparation, preparationSha256);
      const marker = await call("s3", "GetObject", { Bucket: bucket, Key: lock.key }, async received => ({ etag: received.ETag, text: await received.Body.transformToString() }));
      assert.equal(marker.etag, claimEtag, "Recovery lock ownership changed"); const value = assertLock(JSON.parse(marker.text));
      assert.equal(value.ID, checkpoint.recoveryTransitionId); assert.equal(value.Operation, "OperationTypeRecovery"); assert.deepEqual(JSON.parse(value.Info), checkpoint);
      const response = await call("s3", "DeleteObject", { Bucket: bucket, Key: lock.key }); assert.equal(response.DeleteMarker, true, "Recovery lock must retain a versioned incident trail");
      const objects = await call("s3", "ListObjectsV2", { Bucket: bucket, Prefix: key }); assert(!(objects.Contents || []).some(({ Key }) => Key === lock.key), "Recovery lock remains");
    },
    async beginPartialActivationRecovery(record, preparation, preparationSha256, continuation = false) {
      const checkpoint = assertPartialActivationRecoveryCheckpoint(record, preparation, preparationSha256); assert.equal(typeof continuation, "boolean");
      const marker = { ID: checkpoint.recoveryTransitionId, Operation: "OperationTypeRecovery", Info: JSON.stringify(checkpoint), Who: checkpoint.owner.principal, Version: "1.15.8", Created: new Date().toISOString(), Path: `${bucket}/${key}` };
      const response = await call("s3", "PutObject", { Bucket: bucket, Key: partialActivationRecoveryTarget.lockKey, Body: JSON.stringify(marker), ServerSideEncryption: "AES256", ...(continuation ? { IfNoneMatch: "*" } : { IfMatch: checkpoint.lock.etag }) });
      assert(typeof response.ETag === "string" && response.ETag, "Recovery lock claim is ambiguous");
      return response.ETag;
    },
    async capturePartialActivationNativeLock(lock, record, preparation, preparationSha256) {
      assert.deepEqual(Object.keys(lock || {}).sort(), ["created", "etag", "id", "key", "operation", "path", "version", "versionId", "who"]);
      assert.equal(lock.key, partialActivationRecoveryTarget.lockKey); assert(["OperationTypeApply", "OperationTypePlan"].includes(lock.operation)); assert.equal(lock.path, `${bucket}/${key}`);
      const checkpoint = assertPartialActivationRecoveryCheckpoint(record, preparation, preparationSha256);
      assert.equal(checkpoint.state, lock.operation === "OperationTypeApply" ? "IMPORT_LOCK_CAPTURED" : "PLAN_LOCK_CAPTURED");
      const marker = await call("s3", "GetObject", { Bucket: bucket, Key: lock.key }, async received => ({ etag: received.ETag, text: await received.Body.transformToString() }));
      assert.equal(marker.etag, lock.etag, "Retained native import lock changed"); const native = assertLock(JSON.parse(marker.text));
      for (const field of ["ID", "Operation", "Who", "Version", "Created", "Path"]) assert.equal(native[field], lock[{ ID: "id", Operation: "operation", Who: "who", Version: "version", Created: "created", Path: "path" }[field]], "Retained native import lock changed");
      const recovery = { ID: checkpoint.recoveryTransitionId, Operation: "OperationTypeRecovery", Info: JSON.stringify(checkpoint), Who: checkpoint.owner.principal, Version: "1.15.8", Created: new Date().toISOString(), Path: `${bucket}/${key}` };
      const response = await call("s3", "PutObject", { Bucket: bucket, Key: lock.key, Body: JSON.stringify(recovery), ServerSideEncryption: "AES256", IfMatch: lock.etag });
      assert(typeof response.ETag === "string" && response.ETag, "Native import lock capture is ambiguous"); return response.ETag;
    },
    async readRecoveredTerraformState() {
      const bytes = await call("s3", "GetObject", { Bucket: bucket, Key: key }, received => received.Body.transformToString());
      return assertRecoveredTerraformState(bytes);
    },
    close() { for (const field of Object.keys(value)) delete value[field]; },
  });
}
