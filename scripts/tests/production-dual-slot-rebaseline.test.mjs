import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import test from "node:test";
import {
  PRODUCTION_DUAL_SLOT_REBASELINE, REBASELINE_SLOT_ORDER, BASELINE_COMPLETE,
  buildAbandonmentEvidence, buildRebaselineIdentity, buildRebaselinePayloads, buildRebaselineWritePlan,
  buildRebaselinePreparation, assertRebaselinePreconditions, assertRebaselinePreparation,
  createProductionDualSlotRebaselineAuthorization, deterministicWriteIdentity, executeProductionDualSlotRebaseline,
  generateRebaselineMaterial, assertBaselineCompletion, canonicalSha256, historicalSlotIdentity,
  REBASELINE_HISTORICAL_SOURCE_SHAS, REBASELINE_SLOTS, assertRebaselineRotationBindings, assertProductionDualSlotRebaselineAuthorization, resolveProductionDualSlotRebaselineAuthorizationArtifact, readBoundBaselineCompletion, readRebaselineMaterialJournal, writeRebaselineMaterialJournal, persistExactPrivateJson, rebaselineWritePayloadIdentities, verifyLiveProductionDualSlotRebaselineWithRunner, sha256, coordinatorTransitionSlotIdentity, buildAuthenticatedPreCutoverCoordinatorTransition, assertAuthenticatedPreCutoverCoordinatorTransition, coordinatorTransitionVersionId,
  assertAuthenticatedPartialRebaselineRecovery, createPartialRebaselineRecoveryAuthorization, assertPartialRebaselineRecoveryAuthorization, classifyAuthenticatedPartialRebaselineRecoveryProgress, resolvePartialRebaselineRecoveryAuthorizationArtifact, buildProductionDualSlotRebaselineDurableEvidence, assertProductionDualSlotRebaselineDurableEvidence, resolveProductionDualSlotRebaselineDurableEvidenceArtifact, PARTIAL_REBASELINE_RECOVERY_BASE_SOURCE_SHA,
} from "../aws/production-dual-slot-rebaseline-contract.mjs";
import { auditLiveProductionDualSlotReferences, readAuthenticatedRebaselineCheckout, readDualSlotTopology, readPreparedDualSlotTopology, runProductionDualSlotRebaselineCli, verifyLiveProductionDualSlotRebaseline } from "../aws/rebaseline-production-dual-slot.mjs";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { assertBindings, buildInitialMigrationSourceAdvance, buildProductionRotationConfig } from "../aws/production-cutover-runtime-bootstrap.mjs";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "../aws/production-cutover-production-adapters.mjs";
import { createProductionGithubCommandRunner } from "../aws/production-credential-source-contract.mjs";
import { productionSupersessionEvidenceIdentity } from "../security/production-initial-migration-source-advance.mjs";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";
import { persistProductionDualSlotRebaselineDurableEvidence } from "../aws/persist-production-dual-slot-rebaseline-durable-evidence.mjs";
import { assertStageBCanonicalRepositoryUrl } from "../aws/stage-b-deployment-identity.mjs";

const sourceSha = "a".repeat(40);
// Non-secret, production-safe recovery identity fixture.  The production validator
// must still compare it to its literal protected-source anchor; recomputing this
// envelope's own digest is deliberately insufficient.
const recoveryEnvelopeFixture = () => JSON.parse(zlib.gunzipSync(Buffer.from("H4sIAAAAAAAAE91bW3NcuY1+n1+h0nNUIXEj6TdFVna1O2M5kuzJZmtLBQKg3WNZLbdadrxT89+3TutiWbfJTGSXN499DgmAOPgI8AP75+/W1tZP7XW81ZexOJ3Nj9efrOU/TE/fzI59/cna+vO93acvtg52dp8dPn2x+f3h/ve7B4d723/a3N/+fufZ9uH+i62t7f393b3Dve2t3Zfbe/+1vpq/CD1diVt/vrt/cPjj3s7B9uHe9ubTw63dZy+39/5t+9nW9uH+7ou9re3DP+/89XzWfDF7NTvWo/352cJi/7VOAqJLYS2jJukl12DMTYaiW+6DKnE3qwX0UrHN38fi45/0ND4XQz2VRm4Du2Tt0AkN6xgItaCkBiqRwS7EzJe6nM2Pd1ZeuPy1AQkkVWgpM+a8UYStapbPrX++iBNdrCbsv1ZgmUSgdsUavTXLRdGjFhINHaRFARX7kNLUsQm2hMFdR2JEF821pPS5ih90GYuZHv3H/Gwx+etKTdJaDCF30srWkSBnk+aqnakqcdEO0LxY7cIdR29Dx/CUQ8y8f65m82z5er6Y/e9qLetP1n7+bm1tbW39w3zxZhzNP+ydXfgHEaACS0VYCfh8zOZyGW9PltPAfPlar0v+ZD4VaxU859IHEGHL1MI11Q7R2Gp3qIQN+yhR+hAdlsNUEjjkCrr+3draL6slvJ6dLueLmV0tYvlx89hezxeflFUIxMHInRGYjDGb9S6Z84imETmLI6XshVNzKuDKJCDWW+eaLgPudBVmp5/889OH5fM49tnxq0mNLo6f6IfTJ6dhi1ievtVjfRWLJ3G28SFOlxvwBKW2BlKxJrwY9eTtqb1b/PFkMfc/XgbfH3/6sNw4OZe7kbeOf/zh5NKb7xbPF7P3uowvofbdYuPkXPqV9u//9tqYrmk/60cz+1LKV8KvdJ/9CZ/nv1zqnly9iPez+dnp4/v6QvCGLP6yePfTreV+Cb3X1nupffH93z7YXz9p3zpbLOJ4+WnHflTtdi594/25+I06nu2+3L4eaOdmfSH1V6u+1P/86Z/PjuAuXB/MT+ZH81cfrwE6hSVrrbDkkTEoC0SeNtmWEd25BnVWpTRqdOWeMQKpEEOdxq3f0LB/NF/ueBwvZ8vZvfg+f3ZfIj1/czRf7X7X5n16t3LH5uJxPXnvVrG2tn7h2fOdu2AZTr0pl9EiUuIxPCwgVYAUlaBWHNBGyiKeSi+CLp1ZiKKlem0hS321ctJ/XzxZW1vf/HF/68Xe3vazg/WLh/9zNf5EPx7N1fdXXptM2Xm2c7Cz+f31OmP3YHNVerzM6zfn/ed5gfLzJ2VD386OPl74+fDChVfzrn2GkxvfYG1tfXY8W8706IfZq8Vlrht6dBoXI3650j7vp7F4H773YH0gSZIgbPQ8pVi+Zv3l/M9KE+Yk1gNbAYWipRjkPKC2XFgMeyseJbdyywmfQn/wcGJOVslaiJFjr5m0B1LXAQIB2H1Ic6xNG5USU3VANQ/FwZ9Ev70oLf48O34Vi5PF7HjlNBI2M+vZmApeVFvnvjtHyDUcFrJoxGDZ1TtQ99Ei14FaIBzdIrSViNqLBObhrbTqhlgsg9V6Hiy/3J/cfgPmbs3+wsj7tWx5E4CaBqRB0II7ONSmUsQzBoZiNE+t1kKBVioySXCzqeppDAE9d/0mAfhucXg6e3U8O351+CY+PgTCS2f9S4GRjBgGp6TUEVuJxoLDEKxJwTEAUFyhNOwJBiFza9xrBR0QmORXwcjAyElg1NGAS/o04U18vJaZjbJpE+2JijvwQ6DFYSEtlwRcDDTaEHaCqRKmkoV9OA5Q9iEuDQdZDGPmbuBV2W+B9kZN+Nsw+9nkrwDZB2rMm4id1ms9oCbyBsO1YBMtuWYsxbWUUUsp7F7LqDmzQpbaSs85YhDH/3vErnz1LwVYwBTVUoNMxDys4OiZRiAg9GrESCFDtE7yW3Wvbq7cQke2fr0Kugew9wPx9wM2Q0lpeJIpWfReOxXrJTm2AdlATFsHBCDSPqpMuT8noFpMklXFzwH7+UHqHwDrJUO0+eLg37efHexsbR5sPz18vrd9uPXiYGKCDrd2d/ee7jzbPNjdOzzY23y2vzNF5votuF9X/TXq4juPdTdRnqyCu+NAH56KWeosSMSUsBeQKKIjae7eR+0tc6too0aloUz+mCi/7scrfK8Ytb3HrowvP8OjI/cW5PpEUfWquRemTNbUpBjXxCWDgydnK0V7FG7KKdWkbaLsoDEiuv0q5EaqCasOKnWMYvYQlAAUhjfmPH1zG4BJFay1RI2yireEzcrQUSyJoKMCiBdAikC/XbDeJAh+T/L7SpD4NcbhJjD6IASXFEgTNQnEo2NUVlGYUmBYaEEbDEVqDFDx8FahYsLK9GVPjBeE8ubTl5sTv/z4SXAiMj/+Su5bLs7uT32Pnrp6YxYdrAaSo48s1Vx7TpKjehbu4tJbMLEgQtJWM1Hz0JylPHyOS9gza8ZcKkX2VgOHZueiOh3UGnYQEfM8AKmMYo7Ohpyxi2O5CYtbzNVXTTO39H95YD1Ipt0ElgzJzFZapSi9dO7kPiKNWqfTRHfBFGy1OmLLnRKQQsIiBtK7pW8z47xbTFg6vFjpnZi68NLjJ507MdcGNs9GQ0hISiaZSIfEtQwv6lx54IicHsBcqpRQBlWxBNLUW7B0pSSOLdt0BuhonAemHAqlQEcUD6zqwlofo/or5NAVmo8mqeBAke4AWisNlMDedGTElEttrCBcWzJVAOiC0uI2x3KT1/2NJMvn078Gy3I3U3w3uGKM0tFNTKfavWtY6yUwpZpzqCS0mrGrkHgdwoS1hkw7p9TBgd921vo1hF356ptLX0nCsJak5N2iF6ndkTVRTa21jimgj85JqzazKCWDpKxdtVMv+UGIjEjeAjubJqVgkawltIsMMck5acFEdWACmooZj9qEs6YSSQrBBUSuWg+XXdEfF7NlPD/S46sg+PkmIL4Npt+OZnG83It3Z3G6PJi/iZVq6lmERh5SHQWcJXh4a8Hm0YZ7hTKoonbz2qxzCJTKYlaxQscHviZTc9aAZlUTJaTuNWl1txzOmUqhrIDeQyNZAmRHdaGKmLUJ3S7qDz6exOpbLuL09carOI6FLsNv2XDRpvn4OUi+nIG/wcSb2/zx2dHRJb6ub8K3gugbpK7vjiiBIEwEIynWIXUQdapu0Rh7y81K6Q6mEzeWCyVn6sWKomaHhvBARJWsKY3UE9dhWEC4B0/kS0o9IlMdQDHxMblPpGRBsZwbTeeRbIj9i0fUoxn4T0TUerJsEdCVREbDWP9H4+vbolnvji4bAVPDAxtW0gacKBE2cRGWUkUSNy+1eCOK2gM0IrSQtSQxQB7KPkNaJ1SM6Dimplgll+BCnVpJVhG4da1RO+Vwsshs1HoAUtZ8R9fskaPr0Qz8+tH1rbB69wRVjjqaCyWZbltJGwxNoNmoWnpNgrkV9IgiPU30URcgriqJw9jpgaByyQrDSmLnaQvUjC27GY2OUIlbLtlTI+tTcxQ6R8/afGJQclD1+4NqVb1tdD2No9lxbLzVxZtY/N7QejQzf7Oh/0xC/NaosXtKLBBRJK+ZcgbIKWVJ3QtF8TQStYwK0zF/ODbAzsjhIzuVLq3YQ9GVkREL9BZSQKR6HbWn0V1bYylEVFkwQAaZ56YZEkHi1qBoDLmjt/hFouvRzPya0fXN8UN3R1dNnKf9mKpCCWyUrbUGLtaAc5m6FBN8rcDUq4DB7M2UsWaIZskeiK6wTAKJ1frUAOtNgGqIxiBnZJ9Ih+Ho2tkiVdCeoFvppuhVFe+PLvX5yTJ8Y7r4OUWQTTln4yheqX3cUFvO3sfG5RHu9wbdo1n/WPb/U6X/N0eo3B2NjjWmK9UFkZR68pyaBLsMFa0dUppSRlUg64kzltYjkbTszVrut0ujaykKYbqT29ETM1kKrpW0pqgt5cbCwiVAO6UKpVRolcV75UxVSD19rUz6WGZ+gb3uuwsqat3mb0+OYhk+XWr8RF9dZyquxi7irc6mNsiNsfccSO85SNxRAd6Xwe/be+/AwR1GrqL6pR6dxYqZmQyW1ZD4+0nYtOTViKcxrX96m/5w858CO2/1VZybduOu++nv/g/BfRflW6OEcHVRXhfL2VBbXmuNKthIbE6RuYE4D0FRkAylGmirNpQQJ1IrTZddG1plrM443Z67pNvWZ28vmMqr7aWrvYnzfsrpSt0TGA2s54LaCEqnagW1Tr3vFGqVCbESTdcHepuuygbVxiVpb6yS9FqlMq01FtdFe6KAKAIyWDFjZDJU4hEOvUgDJa9tkEuLkihPDfTBqjnXEtI+iV4cnW7/PexsOb8uH8sILt0CU552mVaKWHLJg5g6hESlMgCtZSjZW57YiEJWchvgzT+Tv6XHuvh4TXriKr0UxsS1Tpc+UKLLdB9EJzcTQrEhA8NzhV56m0JgqEiQZOt8kzy8jLZr2SoSinm3ksKGkYULjzL9wcWSSk42xFOUjgGRHEubnIOl52HSNda/++W7/wMQe1tLwjMAAA==", "base64")).toString("utf8"));
const historicalRotationId = "rotation-20260826060632-b15b3f51";
const rotationId = "rotation-20260828000000-rebase";
const resources = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot, index) => [slot, `arn:aws:secretsmanager:eu-west-2:${PRODUCTION_DUAL_SLOT_REBASELINE.accountId}:secret:fixture/${REBASELINE_SLOTS[slot]}-${index}`]));
const currentVersionIds = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, sha256(`fixture-version:${slot}`)]));
const historicalTopologySha256 = canonicalSha256({ resources, versionIds: currentVersionIds });
const legacyBaseline = { jwtCurrent: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:legacy-jwt", qrPrivateCurrent: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:legacy-qr-private", qrPublicCurrent: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:legacy-qr-public", qrCurrentVersion: "legacy-v1" };
const shapes = { jwtPending: ["jwt_secrets", "pending"], qrPrivatePending: ["qr_signing_keys", "pending-private"], qrPublicPending: ["qr_signing_keys", "pending-public"], jwtPrevious: ["jwt_secrets", "empty"], qrPublicPrevious: ["qr_signing_keys", "empty"], qrCurrentVersion: ["qr_key_versions", "current"], qrPreviousVersion: ["qr_key_versions", "previous-empty"] };
function historicalPayload(slot, { source = REBASELINE_HISTORICAL_SOURCE_SHAS[0], rotation = historicalRotationId, value = `historical-${slot}` } = {}) { const [family, payloadSlot] = shapes[slot]; return { value, family, slot: payloadSlot, initialMigration: true, ...(rotation === undefined ? {} : { rotationId: rotation }), ...(source === undefined ? {} : { sourceSha: source }) }; }
const observedSlotIdentities = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, historicalSlotIdentity({ slot, secretArn: resources[slot], versionId: currentVersionIds[slot], stages: ["AWSCURRENT"], payload: historicalPayload(slot, { source: slot === "qrPublicPending" ? REBASELINE_HISTORICAL_SOURCE_SHAS[1] : slot === "qrPreviousVersion" ? undefined : undefined }) })]));
const audit = Object.freeze({ status: "PASS", dualSlotReferences: 0, legacyRuntimeAuthoritative: true, liveLegacyBaselineCount: 1, databaseDependencies: 0, externalConsumers: 0, auditSha256: canonicalSha256({ observation: "fixture", resources, tasks: ["task-a"] }), stableAuditSha256: canonicalSha256({ stable: "fixture", resources, taskDefinitions: ["mscqr-backend:50"] }) });
const abandoned = buildAbandonmentEvidence({ sourceSha, historicalRotationId, historicalSourceShas: REBASELINE_HISTORICAL_SOURCE_SHAS, resources, currentVersionIds, historicalTopologySha256, observedSlotIdentities, liveReferenceAudit: "PASS", liveReferenceAuditSha256: audit.stableAuditSha256, legacyRuntimeAuthoritative: true, observedAt: "2026-08-28T10:00:00.000Z" });
const preconditions = { environment: "production", accountId: PRODUCTION_DUAL_SLOT_REBASELINE.accountId, region: PRODUCTION_DUAL_SLOT_REBASELINE.region, sourceSha, sourceCas: true, cleanWorktree: true, existingSecretResources: true, liveReferenceAudit: "PASS", liveReferenceAuditSha256: audit.stableAuditSha256, legacyRuntimeAuthoritative: true, liveLegacyBaselineCount: 1, databaseDependencies: 0, externalConsumers: 0, dualSlotReferences: 0, runningTasks: 2, pendingTasks: 0, activeTaskDefinition: "mscqr-backend:50", resources, historicalTopologySha256, abandonmentEvidence: abandoned };
const material = generateRebaselineMaterial();
const identity = buildRebaselineIdentity({ sourceSha, rotationId, resources, abandonmentEvidenceSha256: abandoned.evidenceSha256, legacyBaseline });
const payloads = buildRebaselinePayloads({ sourceSha, rotationId, generatedMaterial: material, legacyBaseline });
const writePlan = buildRebaselineWritePlan({ sourceSha, rotationId, resources, baselineIdentitySha256: identity.identitySha256, payloads });
const preparation = buildRebaselinePreparation({ preconditions, sourceSha, rotationId, baselineIdentity: identity, writePlan });
const temporary = () => { const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rebaseline-test-")); chmodSync(directory, 0o700); return { directory, completionFile: path.join(directory, "completion.json"), bindingsFile: path.join(directory, "rotation-bindings.json") }; };
const protectedCheckout = (sha = sourceSha, overrides = {}) => ({ mode: "production", toolingSha: sha, currentHead: sha, originMainHead: sha, isAncestor: true, porcelainStatus: "", repositoryState: { remoteDefaultBranch: "main", shallow: false, mergeInProgress: false, rebaseInProgress: false, cherryPickInProgress: false }, ...overrides });

function environmentEvidence() { return createProductionEnvironmentApprovalEvidence({ environmentConfig: { name: "production", id: 17, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 7, login: "checker" } }] }] }, repository: PRODUCTION_DUAL_SLOT_REBASELINE.repository, environment: "production", sourceSha, workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.dualSlotRebaselineWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "123456", workflowRunAttempt: "1", executionActor: "operator", observedAt: "2026-08-28T10:01:00.000Z", actualApproval: { state: "approved", environmentId: 17, environmentName: "production", userId: 7, userLogin: "checker" } }); }
const verifyInitialBindingOrigin = () => { throw new Error("fixture is not an initial binding"); };
function authorization({ baselineIdentitySha256 = identity.identitySha256, writePayloadIdentities = rebaselineWritePayloadIdentities(writePlan), materialJournalSha256 = "b".repeat(64), materialJournalFileSha256 = "c".repeat(64) } = {}) { return createProductionDualSlotRebaselineAuthorization({ protectedEnvironmentApprovalEvidence: environmentEvidence(), sourceSha, historicalRotationId, rotationId, abandonmentEvidenceSha256: abandoned.evidenceSha256, baselineIdentitySha256, resources, writeIdentities: Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, deterministicWriteIdentity({ sourceSha, rotationId, slot, secretArn: resources[slot], baselineIdentitySha256 })])), writePayloadIdentities, materialJournalSha256, materialJournalFileSha256, expectedSecretValueWrites: 7, expectedSecretDeletes: 0, liveReferenceAudit: "PASS", liveReferenceAuditSha256: audit.stableAuditSha256, observedSlotIdentitiesSha256: abandoned.observedSlotIdentitiesSha256, reason: "Abandon pre-cutover state and establish a clean baseline", approvedBy: "checker", approverRole: "production-independent-checker", verificationRef: "ticket-rebaseline-1" }); }
function executionAdapters({ failAt = -1, liveReferenceAudit = audit, postWriteHistoricalReadLag = 0 } = {}) {
  const store = new Map(REBASELINE_SLOT_ORDER.map((slot) => [slot, [{
    versionId: currentVersionIds[slot], stages: ["AWSCURRENT"],
    payloadSha256: observedSlotIdentities[slot].payloadSha256,
  }]]));
  const historical = new Map([...store].map(([slot, versions]) => [slot, structuredClone(versions)]));
  let calls = 0; let staleReads = 0; const operations = [];
  return {
    store,
    operations,
    readReferenceAudit: async () => typeof liveReferenceAudit === "function" ? liveReferenceAudit() : liveReferenceAudit,
    readSlot: async (slot, secretArn) => {
      operations.push({ operation: "read", slot });
      const versions = staleReads > 0 ? historical.get(slot) : store.get(slot); if (staleReads > 0) staleReads -= 1;
      const current = versions.find(({ stages }) => stages.includes("AWSCURRENT"));
      return { arn: secretArn, versions, currentVersionId: current?.versionId, currentStages: current?.stages, currentPayloadSha256: current?.payloadSha256 };
    },
    writeSlot: async ({ slot, secretArn, clientRequestToken, payload, payloadSha256 }) => {
      operations.push({ operation: "write", slot });
      const entry = { versionId: clientRequestToken, stages: ["AWSCURRENT"], payloadSha256: payloadSha256 || canonicalSha256(payload) };
      store.set(slot, store.get(slot).map((version) => ({ ...version, stages: version.stages.includes("AWSCURRENT") ? ["AWSPREVIOUS"] : version.stages })).concat(entry));
      calls += 1;
      staleReads = postWriteHistoricalReadLag;
      if (calls === failAt) throw new Error("injected interruption after remote write");
      return { arn: secretArn, versionId: clientRequestToken };
    },
  };
}
function execute(adapters, outputs, extra = {}) { return executeProductionDualSlotRebaseline({ preconditions, sourceSha, rotationId, baselineIdentity: identity, writePlan, authorization: authorization(), completionFile: outputs.completionFile, bindingsFile: outputs.bindingsFile, repositoryRoot: process.cwd(), ...adapters, ...extra }); }

function cliTopologyClient(completedSlots = [], overrides = {}) {
  const completed = new Set(completedSlots);
  return { send: async (command) => {
    const input = command.input;
    const slot = Object.entries(REBASELINE_SLOTS).find(([, name]) => name === input.SecretId)?.[0] || Object.entries(resources).find(([, arn]) => arn === input.SecretId)?.[0];
    if (!slot) throw new Error("unexpected secret identity");
    const expected = writePlan.find((entry) => entry.slot === slot);
    const oldVersionId = currentVersionIds[slot];
    const currentVersionId = overrides[slot]?.versionId || (completed.has(slot) ? expected.clientRequestToken : oldVersionId);
    const payload = overrides[slot]?.payload || (completed.has(slot) ? expected.payload : historicalPayload(slot, { source: slot === "qrPublicPending" ? REBASELINE_HISTORICAL_SOURCE_SHAS[1] : slot === "qrPreviousVersion" ? undefined : REBASELINE_HISTORICAL_SOURCE_SHAS[0] }));
    const name = command.constructor.name;
    if (name === "DescribeSecretCommand") return { Name: input.SecretId, ARN: overrides[slot]?.arn || resources[slot], VersionIdsToStages: { [currentVersionId]: overrides[slot]?.stages || ["AWSCURRENT"], ...(currentVersionId === oldVersionId ? {} : { [oldVersionId]: ["AWSPREVIOUS"] }) } };
    if (name === "GetSecretValueCommand") return { SecretString: JSON.stringify(payload), VersionId: input.VersionId };
    throw new Error(`unexpected command ${name}`);
  } };
}

function cliTopologyRunner(completedSlots = [], overrides = {}) {
  const completed = new Set(completedSlots);
  return (args) => {
    const secretArn = args[args.indexOf("--secret-id") + 1];
    const slot = Object.entries(resources).find(([, arn]) => arn === secretArn)?.[0];
    if (!slot) throw new Error("unexpected secret identity");
    const expected = writePlan.find((entry) => entry.slot === slot);
    const currentVersionId = overrides[slot]?.versionId || (completed.has(slot) ? expected.clientRequestToken : currentVersionIds[slot]);
    const payload = overrides[slot]?.payload || (completed.has(slot) ? expected.payload : historicalPayload(slot, { source: slot === "qrPublicPending" ? REBASELINE_HISTORICAL_SOURCE_SHAS[1] : slot === "qrPreviousVersion" ? undefined : REBASELINE_HISTORICAL_SOURCE_SHAS[0] }));
    if (args[0] === "secretsmanager" && args[1] === "describe-secret") return JSON.stringify({ ARN: overrides[slot]?.arn || secretArn, VersionIdsToStages: { [currentVersionId]: overrides[slot]?.stages || ["AWSCURRENT"] } });
    if (args[0] === "secretsmanager" && args[1] === "get-secret-value") return JSON.stringify({ VersionId: args[args.indexOf("--version-id") + 1], SecretString: JSON.stringify(payload) });
    throw new Error("unexpected command");
  };
}

function coordinatorPayload(slot) {
  if (slot === "jwtPrevious") return { value: "coordinator-jwt-previous-fixture", family: "jwt_secrets", slot: "previous", rotationId: historicalRotationId, materialFingerprint: sha256("coordinator-jwt-previous-fixture").slice(0, 16) };
  return { value: "coordinator-qr-version-fixture", family: "qr_key_versions", slot: "current", rotationId: historicalRotationId, sourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[1], keyVersion: "coordinator-v1" };
}

const coordinatorResourceSuffixes = { jwtPending: "1CnWMp", qrPrivatePending: "LZhc54", qrPublicPending: "uB3P1Q", jwtPrevious: "6rQrqj", qrPublicPrevious: "rLZwcX", qrCurrentVersion: "8fNOVE", qrPreviousVersion: "PDFul2" };
const coordinatorResources = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, `arn:aws:secretsmanager:${PRODUCTION_DUAL_SLOT_REBASELINE.region}:${PRODUCTION_DUAL_SLOT_REBASELINE.accountId}:secret:${REBASELINE_SLOTS[slot]}-${coordinatorResourceSuffixes[slot]}`]));
const coordinatorPredecessorVersionIds = {
  jwtPending: "737fd4b9a57f9ee005ffdece208220e842883f29f0166d07b763d6b55644e908",
  qrPrivatePending: "a0f20f429e5b2d289a676d13e3ea3e9d098874e3c783546e59c6afc952e2b1ba",
  qrPublicPending: "c2d8cbe2804d92fda7396a7181377da77f87775dd87f8115a216897b11eef45e",
  jwtPrevious: "61e8a3601210b8e7df43138088132fb1dedcdcd1b5c6e161d7af0285575355fc",
  qrPublicPrevious: "bf432d60e346a18245fb3e85a6a28137ecea73cf52768ef2a6ded98283038548",
  qrCurrentVersion: "11ce28ae6f806270413faabef2d055bd97db30fb75f53bd59b59cdb121ca30d4",
  qrPreviousVersion: "eff7b3dc6ca8dcdbaec9b7e300811ea603c813ba646d8f654388e66d6b68f5e3",
};

const coordinatorPredecessorPayloadIdentities = {
  jwtPending: { payloadSchema: "INITIAL_DUAL_SLOT_ROTATION_V1", payloadKind: { family: "jwt_secrets", slot: "pending", initialMigration: false }, observedRotationId: historicalRotationId, observedSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], payloadSha256: "f5fd4550c84c9e6c4d3b814abe34baf262e23bdf69d389a9477eb342481fa3f5", materialFingerprint: "465ccccb1c54732a", keyVersion: null },
  qrPrivatePending: { payloadSchema: "INITIAL_DUAL_SLOT_ROTATION_V1", payloadKind: { family: "qr_signing_keys", slot: "pending-private", initialMigration: false }, observedRotationId: historicalRotationId, observedSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], payloadSha256: "4c452f500a4b3397e9563fc32c9673ff2236da2793b02f4355995b882af2e306", materialFingerprint: "52535062f8f92570", keyVersion: "c41ca96ab047dd25" },
  qrPublicPending: { payloadSchema: "INITIAL_DUAL_SLOT_ROTATION_V1", payloadKind: { family: "qr_signing_keys", slot: "pending-public", initialMigration: false }, observedRotationId: historicalRotationId, observedSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], payloadSha256: "230e8c09214455fc73fb14fe3232b8c4534e6f6a827a798dd8dcda59eaf1cb08", materialFingerprint: "c41ca96ab047dd25", keyVersion: "c41ca96ab047dd25" },
  jwtPrevious: { payloadSchema: "INITIAL_DUAL_SLOT_SOURCE_ADVANCE_V1", payloadKind: { family: "jwt_secrets", slot: "empty", initialMigration: true }, observedRotationId: null, observedSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], payloadSha256: "6142323165b798617aa7c16d01bce85be1598f304a5d8f1615fcae4cd8ce0442", materialFingerprint: null, keyVersion: null },
  qrPublicPrevious: { payloadSchema: "INITIAL_DUAL_SLOT_SOURCE_ADVANCE_V1", payloadKind: { family: "qr_signing_keys", slot: "empty", initialMigration: true }, observedRotationId: null, observedSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], payloadSha256: "2b9556af5ac261ebf168cdab1061e8d165b6d6b9e54563320a981449dea1167a", materialFingerprint: null, keyVersion: null },
  qrCurrentVersion: { payloadSchema: "INITIAL_DUAL_SLOT_SOURCE_ADVANCE_V1", payloadKind: { family: "qr_key_versions", slot: "current", initialMigration: true }, observedRotationId: null, observedSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], payloadSha256: "46248c1e25e4825213ac2c9260a5c129296fb7acf531a0c6438690cfbc5d444e", materialFingerprint: null, keyVersion: null },
  qrPreviousVersion: { payloadSchema: "INITIAL_DUAL_SLOT_SOURCE_ADVANCE_V1", payloadKind: { family: "qr_key_versions", slot: "previous-empty", initialMigration: true }, observedRotationId: null, observedSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], payloadSha256: "06ec3870a4dbceb768bd35a0480999b30e2bfb50a8a9cce7712601abaab4b715", materialFingerprint: null, keyVersion: null },
};
const coordinatorPostPayloadIdentities = {
  ...coordinatorPredecessorPayloadIdentities,
  jwtPrevious: { payloadSchema: "COORDINATOR_ROTATION_WRITER_V1", payloadKind: { family: "jwt_secrets", slot: "previous" }, observedRotationId: historicalRotationId, observedSourceSha: null, payloadSha256: "b1b4ab8a1b75414c9ac67c5805712d2d0d5c77abe759a50080a92b43295333dc", materialFingerprint: "f08038af478ff7cc", keyVersion: null },
  qrCurrentVersion: { payloadSchema: "COORDINATOR_ROTATION_WRITER_V1", payloadKind: { family: "qr_key_versions", slot: "current" }, observedRotationId: historicalRotationId, observedSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[1], payloadSha256: "084036f486c0269ad9e56ba406d391cda77b3c51f301ea2772b336de38ad65a8", materialFingerprint: null, keyVersion: "c41ca96ab047dd25" },
};

function safeHistoricalSlotIdentity(slot, secretArn, versionId, safe) {
  const body = { schemaVersion: 1, slot, secretArn, versionId, stages: ["AWSCURRENT"], payloadSchema: safe.payloadSchema, payloadKind: safe.payloadKind, ...(safe.observedRotationId ? { observedRotationId: safe.observedRotationId } : {}), ...(safe.observedSourceSha ? { observedSourceSha: safe.observedSourceSha } : {}), payloadSha256: safe.payloadSha256, ...(safe.materialFingerprint ? { materialFingerprint: safe.materialFingerprint } : {}), ...(safe.keyVersion ? { keyVersion: safe.keyVersion } : {}) };
  return { ...body, identitySha256: canonicalSha256(body) };
}

function safeCoordinatorSlotIdentity(slot, secretArn, versionId, safe) {
  const body = { schemaVersion: 1, kind: "AUTHENTICATED_PRE_CUTOVER_COORDINATOR_TRANSITION", slot, secretArn, versionId, stages: ["AWSCURRENT"], payloadSchema: safe.payloadSchema, payloadKind: safe.payloadKind, observedRotationId: safe.observedRotationId, ...(safe.observedSourceSha ? { observedSourceSha: safe.observedSourceSha } : {}), payloadSha256: safe.payloadSha256, ...(safe.materialFingerprint ? { materialFingerprint: safe.materialFingerprint } : {}), ...(safe.keyVersion ? { keyVersion: safe.keyVersion } : {}) };
  return { ...body, identitySha256: canonicalSha256(body) };
}

function remintSlotIdentity(identity, patch = {}) {
  const { identitySha256, ...body } = { ...identity, ...patch };
  return { ...body, identitySha256: canonicalSha256(body) };
}

function remintCoordinatorTransition(transition, { resources: nextResources = coordinatorResources, mutate = () => {} } = {}) {
  const forged = structuredClone(transition);
  mutate(forged, nextResources);
  for (const key of ["predecessorSlotIdentities", "postSlotIdentities"]) forged[key] = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, remintSlotIdentity(forged[key][slot]) ]));
  forged.originalSupersessionEvidence = { ...forged.originalSupersessionEvidence, evidenceIdentitySha256: productionSupersessionEvidenceIdentity(Object.fromEntries(Object.entries(forged.originalSupersessionEvidence).filter(([key]) => key !== "evidenceIdentitySha256"))) };
  forged.originalSupersessionEvidenceSha256 = forged.originalSupersessionEvidence.evidenceIdentitySha256;
  const { evidenceSha256, ...authorizationBody } = forged.authorization;
  forged.authorization = { ...authorizationBody, evidenceSha256: canonicalSha256(authorizationBody) };
  const { stateSha256, ...stateBody } = forged.rotationState;
  forged.rotationState = { ...stateBody, stateSha256: canonicalSha256(stateBody) };
  const { transitionSha256, ...body } = forged;
  forged.transitionSha256 = canonicalSha256(body);
  return forged;
}

function authenticatedCoordinatorTransitionFixture() {
  const predecessorVersionIds = coordinatorPredecessorVersionIds;
  const supersessionResourceOrder = ["jwtPrevious", "jwtPending", "qrPrivatePending", "qrPublicPrevious", "qrPublicPending", "qrCurrentVersion", "qrPreviousVersion"];
  const supersessionBody = { schemaVersion: 1, transition: "SUPERSEDE_STALE_PENDING", sourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0], staleSourceSha: "ee9b68a6677be49e5449c428b65b5308d81757f0", rotationId: historicalRotationId, staleRotationId: "rotation-20260812143547-53433751", generatedAt: "2026-08-26T06:18:48.828Z", resources: Object.fromEntries(supersessionResourceOrder.map((slot) => [slot, { arn: coordinatorResources[slot], versionId: predecessorVersionIds[slot], stages: ["AWSCURRENT"] }])) };
  const originalSupersessionEvidence = { ...supersessionBody, evidenceIdentitySha256: productionSupersessionEvidenceIdentity(supersessionBody) };
  const predecessorSlotIdentities = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, safeHistoricalSlotIdentity(slot, coordinatorResources[slot], predecessorVersionIds[slot], coordinatorPredecessorPayloadIdentities[slot])]));
  const postVersionIds = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, ["jwtPrevious", "qrCurrentVersion"].includes(slot) ? coordinatorTransitionVersionId({ slot }) : predecessorVersionIds[slot]]));
  const postSlotIdentities = Object.fromEntries(REBASELINE_SLOT_ORDER.map((slot) => [slot, ["jwtPrevious", "qrCurrentVersion"].includes(slot) ? safeCoordinatorSlotIdentity(slot, coordinatorResources[slot], postVersionIds[slot], coordinatorPostPayloadIdentities[slot]) : safeHistoricalSlotIdentity(slot, coordinatorResources[slot], postVersionIds[slot], coordinatorPostPayloadIdentities[slot])]));
  const authorizationBody = { reference: "GH-ISSUE-391", sourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[1], rotationId: historicalRotationId, resourcesSha256: canonicalSha256(coordinatorResources) };
  const authorization = { ...authorizationBody, evidenceSha256: canonicalSha256(authorizationBody) };
  const rotationStateBody = { stateVersion: 4, sourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[1], rotationId: historicalRotationId, phase: "overlap-deploy-required", initialMigrationSourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[0] };
  const rotationState = { ...rotationStateBody, stateSha256: canonicalSha256(rotationStateBody) };
  return buildAuthenticatedPreCutoverCoordinatorTransition({ resources: coordinatorResources, originalSupersessionEvidence, predecessorSlotIdentities, postSlotIdentities, authorization, rotationState, liveReferenceAuditSha256: audit.stableAuditSha256, liveLegacyBaselineIdentitySha256: canonicalSha256(legacyBaseline) });
}

function coordinatorTopologyClient(transition, overrides = {}) {
  return { send: async (command) => {
    const input = command.input;
    const slot = Object.entries(REBASELINE_SLOTS).find(([, name]) => name === input.SecretId)?.[0] || Object.entries(coordinatorResources).find(([, arn]) => arn === input.SecretId)?.[0];
    if (!slot) throw new Error("unexpected secret identity");
    const currentVersionId = overrides[slot]?.versionId || transition.postVersionIds[slot];
    const payload = overrides[slot]?.payload || (slot === "jwtPrevious" || slot === "qrCurrentVersion" ? coordinatorPayload(slot) : historicalPayload(slot, { source: REBASELINE_HISTORICAL_SOURCE_SHAS[0] }));
    const name = command.constructor.name;
    if (name === "DescribeSecretCommand") return { Name: input.SecretId, ARN: overrides[slot]?.arn || coordinatorResources[slot], VersionIdsToStages: { [currentVersionId]: overrides[slot]?.stages || ["AWSCURRENT"] } };
    if (name === "GetSecretValueCommand") return { SecretString: JSON.stringify(payload), VersionId: input.VersionId };
    throw new Error(`unexpected command ${name}`);
  } };
}

test("post-supersession coordinator topology requires its authenticated transition evidence", async () => {
  const transition = authenticatedCoordinatorTransitionFixture();
  await assert.rejects(() => readDualSlotTopology({ client: coordinatorTopologyClient(transition) }), /kind|historical|authentic/i);
});

test("authenticated coordinator transition accepts the exact protected seven-slot topology", () => {
  const transition = authenticatedCoordinatorTransitionFixture();
  assert.doesNotThrow(() => assertAuthenticatedPreCutoverCoordinatorTransition(transition, { resources: coordinatorResources, observedVersionIds: transition.postVersionIds, observedSlotIdentities: transition.postSlotIdentities }));
  const evidence = buildAbandonmentEvidence({ sourceSha, historicalRotationId, historicalSourceShas: REBASELINE_HISTORICAL_SOURCE_SHAS, resources: coordinatorResources, currentVersionIds: transition.postVersionIds, historicalTopologySha256: "80ec0c997561f13e4162e1aeaf9133dd58e4b5aa40f8eba5b13ee3474528e1ae", observedSlotIdentities: transition.postSlotIdentities, historicalTransitionEvidence: transition, liveReferenceAudit: "PASS", liveReferenceAuditSha256: audit.stableAuditSha256, liveLegacyBaselineIdentitySha256: canonicalSha256(legacyBaseline), legacyRuntimeAuthoritative: true, observedAt: "2026-08-28T10:00:00.000Z" });
  assert.equal(evidence.schemaVersion, 3);
  assert.doesNotThrow(() => assertRebaselinePreconditions({ ...preconditions, resources: coordinatorResources, currentVersionIds: undefined, abandonmentEvidence: evidence, historicalTopologySha256: "80ec0c997561f13e4162e1aeaf9133dd58e4b5aa40f8eba5b13ee3474528e1ae" }));
});

test("coordinator transition rejects mutated resource, version, payload, source, rotation, fingerprint, predecessor, writer, authorization, or live evidence", () => {
  const transition = authenticatedCoordinatorTransitionFixture();
  const mutations = [
    ["resource", () => ({ ...transition, predecessorSlotIdentities: { ...transition.predecessorSlotIdentities, jwtPrevious: { ...transition.predecessorSlotIdentities.jwtPrevious, secretArn: resources.qrPublicPending } } })],
    ["post version", () => ({ ...transition, postVersionIds: { ...transition.postVersionIds, jwtPrevious: sha256("wrong-version") } })],
    ["payload identity", () => ({ ...transition, postSlotIdentities: { ...transition.postSlotIdentities, qrCurrentVersion: { ...transition.postSlotIdentities.qrCurrentVersion, keyVersion: "wrong-v1" } } })],
    ["source", () => ({ ...transition, coordinatorSourceSha: "c".repeat(40) })],
    ["rotation", () => ({ ...transition, historicalRotationId: "rotation-other" })],
    ["writer", () => ({ ...transition, writer: { ...transition.writer, operation: "other" } })],
    ["authorization", () => ({ ...transition, authorization: { ...transition.authorization, reference: "GH-OTHER" } })],
    ["supersession", () => ({ ...transition, originalSupersessionEvidenceSha256: sha256("wrong-evidence") })],
    ["live reference", () => ({ ...transition, liveReferenceAuditSha256: sha256("changed-audit") })],
    ["legacy baseline", () => ({ ...transition, liveLegacyBaselineIdentitySha256: sha256("changed-baseline") })],
  ];
  for (const [label, mutate] of mutations) assert.throws(() => assertAuthenticatedPreCutoverCoordinatorTransition(mutate(), { resources: coordinatorResources, observedVersionIds: transition.postVersionIds, observedSlotIdentities: transition.postSlotIdentities }), /invalid|authentic|exact|hash|bound|duplicate|deterministic|protected/i, label);
});

test("coordinator transition requires both changed slots to form one authenticated topology", () => {
  const transition = authenticatedCoordinatorTransitionFixture();
  for (const [slot, patch] of [["jwtPrevious", { materialFingerprint: "0123456789abcdef", payloadSha256: sha256("wrong-jwt-payload") }], ["qrCurrentVersion", { keyVersion: "wrong-v1", payloadSha256: sha256("wrong-qr-payload") }]]) {
    const forged = remintCoordinatorTransition(transition, { mutate: (value) => { value.postSlotIdentities[slot] = safeCoordinatorSlotIdentity(slot, coordinatorResources[slot], value.postVersionIds[slot], { ...coordinatorPostPayloadIdentities[slot], ...patch }); } });
    assert.throws(() => assertAuthenticatedPreCutoverCoordinatorTransition(forged, { resources: coordinatorResources, observedVersionIds: forged.postVersionIds, observedSlotIdentities: forged.postSlotIdentities }), /protected historical authority anchor/i);
  }
});

test("self-minted coordinator transition evidence is rejected without independent live observations", () => {
  const forged = structuredClone(authenticatedCoordinatorTransitionFixture());
  forged.postSlotIdentities.jwtPrevious.materialFingerprint = "0123456789abcdef";
  const { identitySha256, ...slotBody } = forged.postSlotIdentities.jwtPrevious;
  forged.postSlotIdentities.jwtPrevious.identitySha256 = canonicalSha256(slotBody);
  const { transitionSha256, ...transitionBody } = forged;
  forged.transitionSha256 = canonicalSha256(transitionBody);
  assert.equal(forged.postSlotIdentities.jwtPrevious.identitySha256, canonicalSha256(slotBody));
  assert.equal(forged.transitionSha256, canonicalSha256(transitionBody));
  assert.throws(() => assertAuthenticatedPreCutoverCoordinatorTransition(forged), /exact live resource/i);
  assert.throws(() => assertAuthenticatedPreCutoverCoordinatorTransition(forged, { resources: coordinatorResources, observedVersionIds: authenticatedCoordinatorTransitionFixture().postVersionIds, observedSlotIdentities: authenticatedCoordinatorTransitionFixture().postSlotIdentities }), /exact|protected|authentic/i);
});

test("protected anchor rejects internally consistent arbitrary transitioned payload identities", () => {
  const transition = authenticatedCoordinatorTransitionFixture();
  const forgedPayloads = {
    jwtPrevious: { value: "attacker-controlled-jwt-previous", family: "jwt_secrets", slot: "previous", rotationId: historicalRotationId, materialFingerprint: sha256("attacker-controlled-jwt-previous").slice(0, 16) },
    qrCurrentVersion: { value: "attacker-controlled-qr-current-version", family: "qr_key_versions", slot: "current", rotationId: historicalRotationId, sourceSha: REBASELINE_HISTORICAL_SOURCE_SHAS[1], keyVersion: "attacker-controlled-v1" },
  };
  const forged = remintCoordinatorTransition(transition, { mutate: (value) => {
    for (const slot of ["jwtPrevious", "qrCurrentVersion"]) {
      const safe = coordinatorPostPayloadIdentities[slot];
      value.postSlotIdentities[slot] = safeCoordinatorSlotIdentity(slot, coordinatorResources[slot], value.postVersionIds[slot], { ...safe, payloadSha256: canonicalSha256(forgedPayloads[slot]), ...(slot === "jwtPrevious" ? { materialFingerprint: sha256(forgedPayloads[slot].value).slice(0, 16) } : { keyVersion: forgedPayloads[slot].keyVersion }) });
    }
  } });
  assert.throws(() => assertAuthenticatedPreCutoverCoordinatorTransition(forged, { resources: coordinatorResources, observedVersionIds: forged.postVersionIds, observedSlotIdentities: forged.postSlotIdentities }), /protected historical authority anchor/i);
});

test("protected historical anchor binds all seven predecessor payload identities", () => {
  const transition = authenticatedCoordinatorTransitionFixture();
  const baseline = { sourceSha, historicalRotationId, historicalSourceShas: REBASELINE_HISTORICAL_SOURCE_SHAS, resources: coordinatorResources, currentVersionIds: transition.predecessorVersionIds, historicalTopologySha256: "80ec0c997561f13e4162e1aeaf9133dd58e4b5aa40f8eba5b13ee3474528e1ae", liveReferenceAudit: "PASS", liveReferenceAuditSha256: audit.stableAuditSha256, legacyRuntimeAuthoritative: true, observedAt: "2026-08-28T10:00:00.000Z" };
  assert.doesNotThrow(() => buildAbandonmentEvidence({ ...baseline, observedSlotIdentities: transition.predecessorSlotIdentities }));
  for (const slot of REBASELINE_SLOT_ORDER) assert.throws(() => buildAbandonmentEvidence({ ...baseline, observedSlotIdentities: { ...transition.predecessorSlotIdentities, [slot]: remintSlotIdentity(transition.predecessorSlotIdentities[slot], { payloadSha256: sha256(`forged-predecessor:${slot}`) }) } }), /protected historical authority anchor/i, slot);
});

test("seven-slot mutation matrix rejects recomputed transition evidence", () => {
  const transition = authenticatedCoordinatorTransitionFixture();
  const assertRejected = (forged, resources = coordinatorResources, label = "mutation") => assert.throws(() => assertAuthenticatedPreCutoverCoordinatorTransition(forged, { resources, observedVersionIds: forged.postVersionIds, observedSlotIdentities: forged.postSlotIdentities }), /protected|authentic|exact|deterministic|invalid/i, label);
  for (const slot of REBASELINE_SLOT_ORDER) {
    assertRejected(remintCoordinatorTransition(transition, { mutate: (value) => { value.postSlotIdentities[slot].payloadSha256 = sha256(`forged-post:${slot}`); } }), coordinatorResources, `${slot} payload`);
    assertRejected(remintCoordinatorTransition(transition, { mutate: (value) => { value.postSlotIdentities[slot].stages = ["AWSPREVIOUS"]; } }), coordinatorResources, `${slot} stage`);
    assertRejected(remintCoordinatorTransition(transition, { mutate: (value) => { value.postVersionIds[slot] = sha256(`forged-version:${slot}`); value.postSlotIdentities[slot].versionId = value.postVersionIds[slot]; } }), coordinatorResources, `${slot} VersionId`);
    assertRejected(remintCoordinatorTransition(transition, { mutate: (value) => { value.postSlotIdentities[slot].payloadKind.family = "forged-family"; } }), coordinatorResources, `${slot} family`);
    assertRejected(remintCoordinatorTransition(transition, { mutate: (value) => { value.postSlotIdentities[slot].payloadKind.slot = "forged-slot"; } }), coordinatorResources, `${slot} payload slot`);
    assertRejected(remintCoordinatorTransition(transition, { mutate: (value) => {
      if (value.postSlotIdentities[slot].observedSourceSha === undefined) value.postSlotIdentities[slot].observedSourceSha = "f".repeat(40);
      else value.postSlotIdentities[slot].observedSourceSha = "e".repeat(40);
    } }), coordinatorResources, `${slot} source provenance`);
    assertRejected(remintCoordinatorTransition(transition, { mutate: (value) => { value.postSlotIdentities[slot].observedRotationId = "rotation-forged"; } }), coordinatorResources, `${slot} rotation provenance`);
    const alteredResources = { ...coordinatorResources, [slot]: `arn:aws:secretsmanager:eu-west-2:${PRODUCTION_DUAL_SLOT_REBASELINE.accountId}:secret:fixture/forged-${slot}` };
    assertRejected(remintCoordinatorTransition(transition, { resources: alteredResources, mutate: (value) => { value.originalSupersessionEvidence.resources[slot].arn = alteredResources[slot]; value.predecessorSlotIdentities[slot].secretArn = alteredResources[slot]; value.postSlotIdentities[slot].secretArn = alteredResources[slot]; value.authorization.resourcesSha256 = canonicalSha256(alteredResources); } }), alteredResources, `${slot} ARN`);
  }
  for (const [slot, field] of [["jwtPrevious", "materialFingerprint"], ["qrPrivatePending", "materialFingerprint"], ["qrPublicPending", "materialFingerprint"], ["qrCurrentVersion", "keyVersion"]]) assertRejected(remintCoordinatorTransition(transition, { mutate: (value) => { value.postSlotIdentities[slot][field] = `forged-${field}`; } }), coordinatorResources, `${slot} ${field}`);
  for (const [first, second] of [["jwtPrevious", "qrCurrentVersion"], ["jwtPending", "qrPrivatePending"], ["jwtPrevious", "jwtPending"]]) assertRejected(remintCoordinatorTransition(transition, { mutate: (value) => { for (const slot of [first, second]) value.postSlotIdentities[slot].payloadSha256 = sha256(`forged-pair:${slot}`); } }), coordinatorResources, `${first}/${second} pair`);
  assertRejected(remintCoordinatorTransition(transition, { mutate: (value) => { for (const slot of REBASELINE_SLOT_ORDER) value.postSlotIdentities[slot].payloadSha256 = sha256(`forged-all:${slot}`); } }), coordinatorResources, "all seven payloads");
});

test("builder can create an integrity envelope but cannot mint anchored historical authority", () => {
  const transition = authenticatedCoordinatorTransitionFixture();
  const forged = remintCoordinatorTransition(transition, { mutate: (value) => { value.postSlotIdentities.jwtPrevious.payloadSha256 = sha256("builder-forged-jwt-previous"); } });
  assert.equal(forged.transitionSha256, canonicalSha256(Object.fromEntries(Object.entries(forged).filter(([key]) => key !== "transitionSha256"))));
  assert.throws(() => buildAuthenticatedPreCutoverCoordinatorTransition({
    resources: coordinatorResources,
    originalSupersessionEvidence: forged.originalSupersessionEvidence,
    predecessorSlotIdentities: forged.predecessorSlotIdentities,
    postSlotIdentities: forged.postSlotIdentities,
    authorization: forged.authorization,
    rotationState: forged.rotationState,
    liveReferenceAuditSha256: forged.liveReferenceAuditSha256,
    liveLegacyBaselineIdentitySha256: forged.liveLegacyBaselineIdentitySha256,
  }), /protected historical authority anchor/i);
});

test("one-transition successor recovery keeps literal historical authority separate from fresh execution authority", () => {
  const envelope = recoveryEnvelopeFixture();
  assert.doesNotThrow(() => assertAuthenticatedPartialRebaselineRecovery(envelope));
  const forged = structuredClone(envelope);
  forged.originalWritePlan[0].payloadSha256 = "f".repeat(64);
  forged.originalWritePlan[0].payloadIdentity.payloadSha256 = forged.originalWritePlan[0].payloadSha256;
  forged.recoverySha256 = canonicalSha256(Object.fromEntries(Object.entries(forged).filter(([key]) => key !== "recoverySha256")));
  assert.throws(() => assertAuthenticatedPartialRebaselineRecovery(forged), /protected-source|anchor/i);

  const successorSource = PARTIAL_REBASELINE_RECOVERY_BASE_SOURCE_SHA;
  const image = makeCanonicalImageAuthorization({ sourceSha: successorSource, imageReleaseSha: successorSource });
  const approval = createProductionEnvironmentApprovalEvidence({ environmentConfig: { name: "production", id: 17, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 7, login: "checker" } }] }] }, repository: PRODUCTION_DUAL_SLOT_REBASELINE.repository, environment: "production", sourceSha: successorSource, workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.dualSlotRebaselineRecoveryWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "987654", workflowRunAttempt: "1", executionActor: "operator", observedAt: image.now, actualApproval: { state: "approved", environmentId: 17, environmentName: "production", userId: 7, userLogin: "checker" } });
  const liveCas = { liveReferenceAuditSha256: sha256("recovery-audit"), liveLegacyBaselineIdentitySha256: sha256("recovery-legacy"), observedSlotIdentitiesSha256: sha256("recovery-slots") };
  const authorization = createPartialRebaselineRecoveryAuthorization({ protectedEnvironmentApprovalEvidence: approval, sourceSha: successorSource, recoveryEnvelope: envelope, imageAuthorization: image.authorization, imageAuthorizationValidation: { now: image.now, verifyImageEvidence: image.verifyImageEvidence }, ...liveCas, reason: "Resume the exact interrupted deterministic transition", approverRole: "production-independent-checker", verificationRef: "recovery-fixture", proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === PARTIAL_REBASELINE_RECOVERY_BASE_SOURCE_SHA && descendantSha === successorSource });
  assert.doesNotThrow(() => assertPartialRebaselineRecoveryAuthorization(authorization, { sourceSha: successorSource, recoveryEnvelope: envelope, imageAuthorization: image.authorization, imageAuthorizationValidation: { now: image.now, verifyImageEvidence: image.verifyImageEvidence }, liveCas, proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === PARTIAL_REBASELINE_RECOVERY_BASE_SOURCE_SHA && descendantSha === successorSource }));
  const remintAuthorization = (mutate) => { const forgedAuthorization = structuredClone(authorization); mutate(forgedAuthorization); const { authorizationSha256: ignored, ...body } = forgedAuthorization; forgedAuthorization.authorizationSha256 = canonicalSha256(body); return forgedAuthorization; };
  const verify = (candidate, options = {}) => assertPartialRebaselineRecoveryAuthorization(candidate, { sourceSha: successorSource, recoveryEnvelope: envelope, imageAuthorization: image.authorization, imageAuthorizationValidation: { now: image.now, verifyImageEvidence: image.verifyImageEvidence }, liveCas, proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === PARTIAL_REBASELINE_RECOVERY_BASE_SOURCE_SHA && descendantSha === successorSource, ...options });
  assert.throws(() => verify(remintAuthorization((value) => { value.sourceSha = "f".repeat(40); })), /source|transition/i);
  assert.throws(() => verify(remintAuthorization((value) => { value.liveReferenceAuditSha256 = "f".repeat(64); })), /CAS|live/i);
  assert.throws(() => verify(remintAuthorization((value) => { value.currentImageAuthorization.images.backend = "sha256:" + "f".repeat(64); })), /image/i);
  assert.throws(() => verify(remintAuthorization((value) => { value.authorizationInitialRemainingSlots = []; })), /transition/i);
  assert.throws(() => verify(authorization, { proveDescendant: () => false }), /descendant/i);
  assert.throws(() => assertPartialRebaselineRecoveryAuthorization(authorization, { sourceSha: "e".repeat(40), recoveryEnvelope: envelope, imageAuthorization: image.authorization, imageAuthorizationValidation: { now: image.now, verifyImageEvidence: image.verifyImageEvidence }, liveCas, proveDescendant: () => true }), /source|transition/i);
  assert.throws(() => createPartialRebaselineRecoveryAuthorization({ protectedEnvironmentApprovalEvidence: approval, sourceSha: successorSource, recoveryEnvelope: envelope, imageAuthorization: image.authorization, imageAuthorizationValidation: { now: image.now, verifyImageEvidence: image.verifyImageEvidence }, ...liveCas, reason: "fixture", approverRole: "checker", verificationRef: "fixture", proveDescendant: () => false }), /descendant/i);
});

test("successor recovery progress permits only exact H-to-T states at every N-of-7 boundary", () => {
  const historical = abandoned.observedSlotIdentities;
  for (let completed = 0; completed <= REBASELINE_SLOT_ORDER.length; completed += 1) {
    const completedSlots = new Set(REBASELINE_SLOT_ORDER.slice(0, completed));
    const snapshots = writePlan.map((expected) => completedSlots.has(expected.slot)
      ? { slot: expected.slot, arn: expected.secretArn, currentVersionId: expected.clientRequestToken, currentStages: ["AWSCURRENT"], currentPayloadSha256: expected.payloadSha256, versions: [{ versionId: expected.clientRequestToken, stages: ["AWSCURRENT"], payloadSha256: expected.payloadSha256 }] }
      : { slot: expected.slot, arn: expected.secretArn, currentVersionId: currentVersionIds[expected.slot], currentStages: ["AWSCURRENT"], currentPayloadSha256: historical[expected.slot].payloadSha256, versions: [{ versionId: currentVersionIds[expected.slot], stages: ["AWSCURRENT"], payloadSha256: historical[expected.slot].payloadSha256 }] });
    if (completed === 0) assert.throws(() => classifyAuthenticatedPartialRebaselineRecoveryProgress({ writePlan, historicalSlotIdentities: historical, snapshots, authorizationInitialCompletedSlots: ["jwtPending"], maximumRemainingSecretValueWrites: 6 }), /topology/i);
    else {
      const progress = classifyAuthenticatedPartialRebaselineRecoveryProgress({ writePlan, historicalSlotIdentities: historical, snapshots, authorizationInitialCompletedSlots: ["jwtPending"], maximumRemainingSecretValueWrites: 6 });
      assert.equal(progress.completedSlots.length, completed);
      assert.equal(progress.remainingSlots.length, 7 - completed);
    }
  }
  const snapshots = writePlan.map((expected) => ({ slot: expected.slot, arn: expected.secretArn, currentVersionId: expected.clientRequestToken, currentStages: ["AWSCURRENT"], currentPayloadSha256: expected.payloadSha256, versions: [{ versionId: expected.clientRequestToken, stages: ["AWSCURRENT"], payloadSha256: expected.payloadSha256 }] }));
  snapshots[2] = { ...snapshots[2], currentPayloadSha256: "0".repeat(64), versions: [{ ...snapshots[2].versions[0], payloadSha256: "0".repeat(64) }] };
  assert.throws(() => classifyAuthenticatedPartialRebaselineRecoveryProgress({ writePlan, historicalSlotIdentities: historical, snapshots, authorizationInitialCompletedSlots: ["jwtPending"], maximumRemainingSecretValueWrites: 6 }), /payload|version|topology/i);
  const thirdCurrent = writePlan.map((expected) => ({ slot: expected.slot, arn: expected.secretArn, currentVersionId: expected.clientRequestToken, currentStages: ["AWSCURRENT"], currentPayloadSha256: expected.payloadSha256, versions: [{ versionId: expected.clientRequestToken, stages: ["AWSCURRENT"], payloadSha256: expected.payloadSha256 }] }));
  thirdCurrent[0].versions.push({ versionId: sha256("competing-current-version"), stages: ["AWSCURRENT"], payloadSha256: sha256("competing-current-payload") });
  assert.throws(() => classifyAuthenticatedPartialRebaselineRecoveryProgress({ writePlan, historicalSlotIdentities: historical, snapshots: thirdCurrent, authorizationInitialCompletedSlots: ["jwtPending"], maximumRemainingSecretValueWrites: 6 }), /exactly one|AWSCURRENT/i);
  const wrongStage = writePlan.map((expected) => ({ slot: expected.slot, arn: expected.secretArn, currentVersionId: expected.clientRequestToken, currentStages: ["AWSCURRENT"], currentPayloadSha256: expected.payloadSha256, versions: [{ versionId: expected.clientRequestToken, stages: ["AWSCURRENT"], payloadSha256: expected.payloadSha256 }] }));
  wrongStage[0] = { ...wrongStage[0], currentStages: ["AWSPREVIOUS"], versions: [{ ...wrongStage[0].versions[0], stages: ["AWSPREVIOUS"] }] };
  assert.throws(() => classifyAuthenticatedPartialRebaselineRecoveryProgress({ writePlan, historicalSlotIdentities: historical, snapshots: wrongStage, authorizationInitialCompletedSlots: ["jwtPending"], maximumRemainingSecretValueWrites: 6 }), /exactly one|AWSCURRENT/i);
});

test("recover-execute passes the reader's canonical journal identity, never its wrapper field", () => {
  const directory = temporary();
  try {
    const journalFile = path.join(directory.directory, "material-journal.json");
    const written = writeRebaselineMaterialJournal({ filePath: journalFile, repositoryRoot: process.cwd(), sourceSha, rotationId, baselineIdentitySha256: identity.identitySha256, generatedMaterial: material });
    const readerResult = readRebaselineMaterialJournal({ filePath: journalFile, repositoryRoot: process.cwd(), sourceSha, rotationId, baselineIdentitySha256: identity.identitySha256 });
    assert.equal(readerResult.journalSha256, undefined);
    assert.equal(readerResult.journal.journalSha256, written.sha256);
    assert.notEqual(readerResult.sha256, written.sha256);
    const caller = readFileSync(path.join(process.cwd(), "scripts/aws/rebaseline-production-dual-slot.mjs"), "utf8");
    assert.match(caller, /materialJournalSha256: journal\.journal\.journalSha256/);
    assert.doesNotMatch(caller, /materialJournalSha256: journal\.journalSha256/);
  } finally { rmSync(directory.directory, { recursive: true, force: true }); }
});

test("observed abandonment identities bind exact payloads without plaintext", () => {
  const preparation = buildRebaselinePreparation({ preconditions, sourceSha, rotationId, baselineIdentity: identity, writePlan });
  assert.equal(preparation.writePlan.length, 7); assertRebaselinePreparation(preparation, { sourceSha, rotationId }); assert.equal(JSON.stringify(abandoned).includes(material.jwt), false);
  assert.throws(() => historicalSlotIdentity({ slot: "jwtPending", secretArn: resources.jwtPending, versionId: currentVersionIds.jwtPending, stages: ["AWSCURRENT"], payload: historicalPayload("jwtPending", { rotation: "rotation-wrong" }) }), /provenance/);
  assert.throws(() => historicalSlotIdentity({ slot: "jwtPending", secretArn: resources.jwtPending, versionId: currentVersionIds.jwtPending, stages: ["AWSCURRENT"], payload: historicalPayload("jwtPending", { source: "b".repeat(40) }) }), /source provenance/);
  assert.throws(() => historicalSlotIdentity({ slot: "jwtPending", secretArn: resources.jwtPending, versionId: currentVersionIds.jwtPending, stages: ["AWSCURRENT"], payload: { ...historicalPayload("jwtPending"), family: "unrelated_json" } }), /kind/);
  assert.throws(() => historicalSlotIdentity({ slot: "jwtPending", secretArn: resources.jwtPending, versionId: currentVersionIds.jwtPending, stages: ["AWSCURRENT"], payload: { ...historicalPayload("jwtPending"), materialFingerprint: "tampered" } }), /fingerprint/);
  assert.throws(() => historicalSlotIdentity({ slot: "jwtPending", secretArn: resources.jwtPending, versionId: currentVersionIds.jwtPending, stages: ["AWSPREVIOUS"], payload: historicalPayload("jwtPending") }), /stages/);
  assert.throws(() => buildAbandonmentEvidence({ sourceSha, historicalRotationId, historicalSourceShas: REBASELINE_HISTORICAL_SOURCE_SHAS, resources, currentVersionIds: { ...currentVersionIds, jwtPending: "changed-version" }, observedSlotIdentities, liveReferenceAudit: "PASS", liveReferenceAuditSha256: audit.stableAuditSha256, legacyRuntimeAuthoritative: true }), /exact|identity/);
  assert.doesNotThrow(() => historicalSlotIdentity({ slot: "qrPreviousVersion", secretArn: resources.qrPreviousVersion, versionId: currentVersionIds.qrPreviousVersion, stages: ["AWSCURRENT"], payload: historicalPayload("qrPreviousVersion", { source: undefined }) }));
  assert.doesNotThrow(() => historicalSlotIdentity({ slot: "qrPublicPending", secretArn: resources.qrPublicPending, versionId: currentVersionIds.qrPublicPending, stages: ["AWSCURRENT"], payload: historicalPayload("qrPublicPending", { source: REBASELINE_HISTORICAL_SOURCE_SHAS[1] }) }));
  const tampered = structuredClone(abandoned); tampered.observedSlotIdentities.jwtPending.payloadSha256 = "0".repeat(64);
  assert.throws(() => assertRebaselinePreconditions({ ...preconditions, abandonmentEvidence: tampered }), /hash/);
});

test("authorization binds observed historical and complete ECS audit identities", () => {
  const value = authorization(); assert.equal(value.operation, PRODUCTION_DUAL_SLOT_REBASELINE.kind);
  assert.throws(() => assertProductionDualSlotRebaselineAuthorization({ ...value, observedSlotIdentitiesSha256: "0".repeat(64) }, { sourceSha, rotationId, resources }), /hash|identity/);
  assert.throws(() => assertRebaselinePreconditions({ ...preconditions, liveReferenceAuditSha256: "0".repeat(64) }), /bound|safe/);
});

test("shared executor independently binds the authorization baseline and all seven deterministic writes", async () => {
  const outputs = temporary(); const adapters = executionAdapters(); const auth = authorization();
  await assert.rejects(() => executeProductionDualSlotRebaseline({ preconditions, sourceSha, rotationId, baselineIdentity: identity, writePlan, authorization: authorization({ baselineIdentitySha256: sha256("other-authorized-baseline") }), completionFile: outputs.completionFile, bindingsFile: outputs.bindingsFile, repositoryRoot: process.cwd(), ...adapters }), /baseline identity/i);
  await assert.rejects(() => executeProductionDualSlotRebaseline({ preconditions, sourceSha, rotationId, baselineIdentity: identity, writePlan, authorization: { ...auth, writeIdentities: { ...auth.writeIdentities, jwtPending: sha256("cross-slot-token") } }, completionFile: outputs.completionFile, bindingsFile: outputs.bindingsFile, repositoryRoot: process.cwd(), ...adapters }), /writeIdentities|identity|hash/i);
  assert.equal([...adapters.store.values()].every((versions) => versions.length === 1), true); rmSync(outputs.directory, { recursive: true, force: true });
});

test("production CLI topology reader resumes every authenticated H-to-N boundary", async () => {
  for (let completed = 0; completed <= REBASELINE_SLOT_ORDER.length; completed += 1) {
    const completedSlots = REBASELINE_SLOT_ORDER.slice(0, completed);
    const topology = await readPreparedDualSlotTopology({ client: cliTopologyClient(completedSlots), preparation, writePlan });
    assert.deepEqual(Object.values(topology.classifications).filter((value) => value === "REBASELINE_WRITE_ALREADY_COMPLETE").length, completed);
    assert.deepEqual(Object.values(topology.classifications).filter((value) => value === "HISTORICAL_NOT_YET_WRITTEN").length, 7 - completed);
  }
});

test("production rebaseline binding relabeled as initial cannot bypass the rebaseline gate", async () => {
  const outputs = temporary();
  try {
    const result = await execute(executionAdapters(), outputs);
    const relabeled = { ...result.bindings, kind: "PRODUCTION_INITIAL_DUAL_SLOT_ROTATION_BINDINGS", producer: "scripts/aws/production-initial-dual-slot-bootstrap.mjs:bootstrapInitialDualSlotRotation" };
    assert.throws(() => assertBindings(relabeled, { verifyInitialBindingOrigin }), /origin|provenance|binding/i);
  } finally { rmSync(outputs.directory, { recursive: true, force: true }); }
});

test("binding discriminator mutations cannot choose a weaker runtime validator", async () => {
  const outputs = temporary();
  try {
    const result = await execute(executionAdapters(), outputs);
    const auth = authorization();
    const live = () => ({ kind: "PRODUCTION_DUAL_SLOT_REBASELINE_LIVE_POST_WRITE", sourceSha, rotationId, authorizationSha256: auth.authorizationSha256, resources, versionIds: auth.writeIdentities, payloadIdentities: auth.writePayloadIdentities, livePostWriteSha256: canonicalSha256({ kind: "PRODUCTION_DUAL_SLOT_REBASELINE_LIVE_POST_WRITE", sourceSha, rotationId, authorizationSha256: auth.authorizationSha256, resources, versionIds: auth.writeIdentities, payloadIdentities: auth.writePayloadIdentities }) });
    const mutations = [
      { kind: "PRODUCTION_INITIAL_DUAL_SLOT_ROTATION_BINDINGS" }, { producer: "initial-bootstrap" }, { operation: "initial" }, { schemaVersion: 1 },
      { sourceSha: "b".repeat(40) }, { rotationId: "rotation-foreign" }, { historicalRotationId: "rotation-foreign" },
      { baselineCompletionSha256: "b".repeat(64) }, { authorizationSha256: "c".repeat(64) }, { abandonmentEvidenceSha256: "d".repeat(64) },
    ];
    for (const mutation of mutations) assert.throws(() => assertBindings({ ...result.bindings, ...mutation }, { rebaselineAuthorization: auth, verifyRebaselineLivePostWrite: live, verifyInitialBindingOrigin }), /origin|schema|authorization|rebaseline|hash/i);
    const hybrid = { ...result.bindings, kind: "PRODUCTION_INITIAL_DUAL_SLOT_ROTATION_BINDINGS", producer: "scripts/aws/production-initial-dual-slot-bootstrap.mjs:bootstrapInitialDualSlotRotation" };
    assert.throws(() => assertBindings(hybrid, { rebaselineAuthorization: auth, verifyRebaselineLivePostWrite: live, verifyInitialBindingOrigin }), /origin|schema|binding/i);
  } finally { rmSync(outputs.directory, { recursive: true, force: true }); }
});

test("production CLI rejects every third topology state during resume", async () => {
  const slot = REBASELINE_SLOT_ORDER[0];
  const cases = [
    { versionId: writePlan[0].clientRequestToken, payload: { ...writePlan[0].payload, value: "wrong-prepared-material" } },
    { versionId: sha256("unexpected-version"), payload: writePlan[0].payload },
    { versionId: writePlan[0].clientRequestToken, payload: { ...writePlan[0].payload, sourceSha: "b".repeat(40) } },
    { versionId: writePlan[0].clientRequestToken, payload: writePlan[1].payload },
    { versionId: currentVersionIds[slot], payload: { ...historicalPayload(slot), value: "replaced-historical-material" } },
  ];
  for (const value of cases) await assert.rejects(() => readPreparedDualSlotTopology({ client: cliTopologyClient([], { [slot]: value }), preparation, writePlan }), /authenticate|identity|historical|prepared|version/i);
});

test("runtime consumes a rebaseline completion only after independent live seven-slot authentication", async () => {
  const outputs = temporary();
  try {
    const result = await execute(executionAdapters(), outputs);
    const forged = structuredClone(result.bindings);
    forged.baselineCompletion.versionIds.jwtPending = sha256("forged-version");
    const forgedCompletionIdentity = { ...forged.baselineCompletion }; delete forgedCompletionIdentity.baselineBindingSha256;
    forged.baselineCompletion.baselineBindingSha256 = canonicalSha256(forgedCompletionIdentity);
    forged.baselineCompletionSha256 = forged.baselineCompletion.baselineBindingSha256;
    assert.throws(() => assertRebaselineRotationBindings(forged, { authorization: authorization() }), /version identities/i);
    for (let completed = 0; completed < REBASELINE_SLOT_ORDER.length; completed += 1) {
      await assert.rejects(() => verifyLiveProductionDualSlotRebaseline({ client: cliTopologyClient(REBASELINE_SLOT_ORDER.slice(0, completed)), bindings: result.bindings, authorization: authorization() }), /exact completed|payload/i);
    }
    const verified = await verifyLiveProductionDualSlotRebaseline({ client: cliTopologyClient(REBASELINE_SLOT_ORDER), bindings: result.bindings, authorization: authorization() });
    assert.equal(verified.livePostWriteSha256.length, 64);
    const slot = REBASELINE_SLOT_ORDER[0];
    await assert.rejects(() => verifyLiveProductionDualSlotRebaseline({ client: cliTopologyClient(REBASELINE_SLOT_ORDER, { [slot]: { payload: { ...writePlan[0].payload, value: "wrong-material" } } }), bindings: result.bindings, authorization: authorization() }), /payload/i);
    await assert.rejects(() => verifyLiveProductionDualSlotRebaseline({ client: cliTopologyClient(REBASELINE_SLOT_ORDER, { [slot]: { versionId: sha256("competing-current"), payload: writePlan[0].payload } }), bindings: result.bindings, authorization: authorization() }), /exact completed/i);
    await assert.rejects(() => verifyLiveProductionDualSlotRebaseline({ client: cliTopologyClient(REBASELINE_SLOT_ORDER, { [slot]: { stages: ["AWSCURRENT", "AWSPREVIOUS"] } }), bindings: result.bindings, authorization: authorization() }), /exact completed/i);
  } finally { rmSync(outputs.directory, { recursive: true, force: true }); }
});

test("the runtime CLI verifier grounds completion claims in live Secrets Manager reads", async () => {
  const outputs = temporary();
  try {
    const result = await execute(executionAdapters(), outputs);
    for (let completed = 0; completed < REBASELINE_SLOT_ORDER.length; completed += 1) assert.throws(() => verifyLiveProductionDualSlotRebaselineWithRunner({ run: cliTopologyRunner(REBASELINE_SLOT_ORDER.slice(0, completed)), bindings: result.bindings, authorization: authorization() }), /exact completed|payload/i);
    assert.doesNotThrow(() => verifyLiveProductionDualSlotRebaselineWithRunner({ run: cliTopologyRunner(REBASELINE_SLOT_ORDER), bindings: result.bindings, authorization: authorization() }));
  } finally { rmSync(outputs.directory, { recursive: true, force: true }); }
});

test("runtime call graph propagates independently resolved rebaseline authorization", async () => {
  const outputs = temporary();
  try {
    const auth = authorization();
    const result = await execute(executionAdapters(), outputs);
    const liveLegacyBaseline = { ...legacyBaseline };
    assert.equal(buildInitialMigrationSourceAdvance({ currentSourceSha: sourceSha, rotationBindings: result.bindings, rebaselineAuthorization: auth, liveLegacyBaseline, verifyRebaselineLivePostWrite: () => ({ kind: "PRODUCTION_DUAL_SLOT_REBASELINE_LIVE_POST_WRITE", sourceSha, rotationId, authorizationSha256: auth.authorizationSha256, resources, versionIds: auth.writeIdentities, payloadIdentities: auth.writePayloadIdentities, livePostWriteSha256: canonicalSha256({ kind: "PRODUCTION_DUAL_SLOT_REBASELINE_LIVE_POST_WRITE", sourceSha, rotationId, authorizationSha256: auth.authorizationSha256, resources, versionIds: auth.writeIdentities, payloadIdentities: auth.writePayloadIdentities }) }), verifyInitialBindingOrigin }), undefined);
    assert.throws(() => buildInitialMigrationSourceAdvance({ currentSourceSha: sourceSha, rotationBindings: result.bindings, liveLegacyBaseline, verifyInitialBindingOrigin }), /authorization|origin/i);
    assert.throws(() => buildInitialMigrationSourceAdvance({ currentSourceSha: sourceSha, rotationBindings: result.bindings, rebaselineAuthorization: { ...auth, sourceSha: "b".repeat(40) }, liveLegacyBaseline, verifyRebaselineLivePostWrite: () => ({}), verifyInitialBindingOrigin }), /authorization|hash|source|origin/i);
    assert.throws(() => buildInitialMigrationSourceAdvance({ currentSourceSha: sourceSha, rotationBindings: result.bindings, rebaselineAuthorization: { ...auth, rotationId: "rotation-other-authorized" }, liveLegacyBaseline, verifyRebaselineLivePostWrite: () => ({}), verifyInitialBindingOrigin }), /authorization|hash|rotation|origin/i);
    const config = buildProductionRotationConfig({ sourceSha, rotationId, approval: { ticket: "CHG-REBASELINE-1", approvedBy: "checker", approverRole: "production-independent-checker", reason: "fixture", verificationRef: "ticket-fixture", minimumGraceSeconds: 2592000 }, bindings: result.bindings, rebaselineAuthorization: auth, rebaselineAuthorizationCoordinates: { workflowRunId: "123456", workflowRunAttempt: "1" }, verifyRebaselineLivePostWrite: () => ({ kind: "PRODUCTION_DUAL_SLOT_REBASELINE_LIVE_POST_WRITE", sourceSha, rotationId, authorizationSha256: auth.authorizationSha256, resources, versionIds: auth.writeIdentities, payloadIdentities: auth.writePayloadIdentities, livePostWriteSha256: canonicalSha256({ kind: "PRODUCTION_DUAL_SLOT_REBASELINE_LIVE_POST_WRITE", sourceSha, rotationId, authorizationSha256: auth.authorizationSha256, resources, versionIds: auth.writeIdentities, payloadIdentities: auth.writePayloadIdentities }) }), verifyInitialBindingOrigin });
    assert.equal(config.operation, PRODUCTION_DUAL_SLOT_REBASELINE.kind);
    assert.deepEqual(config.rebaselineRuntime.authorization, auth);
    const configInput = { sourceSha, rotationId, approval: { ticket: "CHG-REBASELINE-1", approvedBy: "checker", approverRole: "production-independent-checker", reason: "fixture", verificationRef: "ticket-fixture", minimumGraceSeconds: 2592000 }, bindings: result.bindings, rebaselineAuthorization: auth, verifyRebaselineLivePostWrite: () => ({ kind: "PRODUCTION_DUAL_SLOT_REBASELINE_LIVE_POST_WRITE", sourceSha, rotationId, authorizationSha256: auth.authorizationSha256, resources, versionIds: auth.writeIdentities, payloadIdentities: auth.writePayloadIdentities, livePostWriteSha256: canonicalSha256({ kind: "PRODUCTION_DUAL_SLOT_REBASELINE_LIVE_POST_WRITE", sourceSha, rotationId, authorizationSha256: auth.authorizationSha256, resources, versionIds: auth.writeIdentities, payloadIdentities: auth.writePayloadIdentities }) }), verifyInitialBindingOrigin };
    assert.throws(() => buildProductionRotationConfig({ ...configInput }), /coordinates/i);
    assert.throws(() => buildProductionRotationConfig({ ...configInput, rebaselineAuthorizationCoordinates: { workflowRunId: "123456", workflowRunAttempt: "1" }, rebaselineAuthorization: undefined }), /authorization/i);
  } finally { rmSync(outputs.directory, { recursive: true, force: true }); }
});

test("production command runner preserves binary authorization-artifact options", () => {
  let captured;
  const run = createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.INJECTED_TEST, exec: (file, args, options) => {
    captured = { file, args, options };
    return Buffer.from("artifact");
  } });
  assert.deepEqual(run(["gh", "api", "repos/example/actions/artifacts/1/zip"], { encoding: null, maxBuffer: 1234 }), Buffer.from("artifact"));
  assert.equal(captured.file, "gh");
  assert.equal(captured.options.encoding, null);
  assert.equal(captured.options.maxBuffer, 1234);
});

test("production topology rejects ambiguous current staging and substituted Secret Manager reads", async () => {
  const ambiguous = cliTopologyClient(); const sendAmbiguous = ambiguous.send;
  ambiguous.send = async (command) => {
    const response = await sendAmbiguous(command);
    return command.constructor.name === "DescribeSecretCommand" ? { ...response, VersionIdsToStages: { ...response.VersionIdsToStages, [sha256("second-current")]: ["AWSCURRENT"] } } : response;
  };
  await assert.rejects(() => readPreparedDualSlotTopology({ client: ambiguous, preparation, writePlan }), /exactly one/i);
  const substituted = cliTopologyClient(); const sendSubstituted = substituted.send;
  substituted.send = async (command) => {
    const response = await sendSubstituted(command);
    return command.constructor.name === "GetSecretValueCommand" ? { ...response, VersionId: sha256("substituted-version") } : response;
  };
  await assert.rejects(() => readPreparedDualSlotTopology({ client: substituted, preparation, writePlan }), /substituted/i);
});

test("production execute CLI authenticates every H-to-N resume state before invoking its executor", async () => {
  for (let completed = 0; completed <= 7; completed += 1) {
    const outputs = temporary(); const preparationFile = path.join(outputs.directory, "preparation.json"); const journalFile = path.join(outputs.directory, "journal.json");
    writeFileSync(preparationFile, JSON.stringify(preparation), { mode: 0o600 }); chmodSync(preparationFile, 0o600);
    writeRebaselineMaterialJournal({ filePath: journalFile, repositoryRoot: process.cwd(), sourceSha, rotationId, baselineIdentitySha256: identity.identitySha256, generatedMaterial: material });
    const captured = []; const client = { ...cliTopologyClient(REBASELINE_SLOT_ORDER.slice(0, completed)), assertCredentialIdentity: async () => {} };
    const result = await runProductionDualSlotRebaselineCli({
      argv: ["--execute", "--source-sha", sourceSha, "--rotation-id", rotationId, "--preparation", preparationFile, "--material-journal", journalFile, "--workflow-run-id", "123456", "--workflow-run-attempt", "1", "--completion-output", outputs.completionFile, "--rotation-bindings-output", outputs.bindingsFile],
      repositoryRoot: process.cwd(), readCheckout: () => ({ toolingSha: sourceSha, porcelainStatus: "" }), createRun: () => () => "{}", createClient: () => client,
      resolveAuthorization: () => ({ authorization: authorization() }), auditReferences: () => audit,
      executePrepared: async (input) => { captured.push(input); return { baselineComplete: true, writes: 0, completion: { baselineBindingSha256: "c".repeat(64) }, completionPath: outputs.completionFile, completionSha256: "d".repeat(64), bindingsPath: outputs.bindingsFile, bindingsSha256: "e".repeat(64) }; }, output: () => {},
    });
    assert.equal(result.baselineComplete, true); assert.equal(captured.length, 1); assert.equal(captured[0].currentPreconditions.liveReferenceAuditSha256, audit.stableAuditSha256);
    rmSync(outputs.directory, { recursive: true, force: true });
  }
});

test("production execute CLI never regenerates missing resume material", async () => {
  const outputs = temporary(); const preparationFile = path.join(outputs.directory, "preparation.json");
  writeFileSync(preparationFile, JSON.stringify(preparation), { mode: 0o600 }); chmodSync(preparationFile, 0o600);
  let topologyRead = false;
  await assert.rejects(() => runProductionDualSlotRebaselineCli({
    argv: ["--execute", "--source-sha", sourceSha, "--rotation-id", rotationId, "--preparation", preparationFile, "--material-journal", path.join(outputs.directory, "missing-journal.json"), "--workflow-run-id", "123456", "--workflow-run-attempt", "1", "--completion-output", outputs.completionFile, "--rotation-bindings-output", outputs.bindingsFile],
    repositoryRoot: process.cwd(), readCheckout: () => ({ toolingSha: sourceSha, porcelainStatus: "" }), createRun: () => () => "{}", createClient: () => ({ assertCredentialIdentity: async () => {} }), resolveAuthorization: () => ({ authorization: authorization() }), readPreparedTopology: async () => { topologyRead = true; throw new Error("must not read topology"); }, output: () => {},
  }), /material journal|ENOENT|does not exist/i);
  assert.equal(topologyRead, false); rmSync(outputs.directory, { recursive: true, force: true });
});

test("production prepare CLI reuses authenticated abandonment evidence after a preparation crash", async () => {
  const outputs = temporary(); const args = ["--prepare", "--source-sha", sourceSha, "--rotation-id", rotationId, "--output-directory", outputs.directory, "--database-dependencies", "0", "--external-consumers", "0"];
  const auditWithLegacy = { ...audit, legacy: legacyBaseline, runningTasks: 2, pendingTasks: 0, activeTaskDefinition: "fixture-backend:1" };
  const common = {
    argv: args, repositoryRoot: process.cwd(), readCheckout: () => ({ toolingSha: sourceSha, porcelainStatus: "" }), createRun: () => () => "{}", createClient: () => ({ assertCredentialIdentity: async () => {} }), historicalTopologySha256,
    gitRun: (gitArgs) => { if (gitArgs[0] === "fetch" || gitArgs[0] === "merge-base") return ""; if (gitArgs[0] === "status") return ""; if (gitArgs[0] === "rev-parse" && gitArgs[1] === "--is-shallow-repository") return "false"; if (gitArgs[0] === "rev-parse" && (gitArgs[1] === "FETCH_HEAD" || gitArgs[1] === "HEAD")) return `${sourceSha}\n`; if (gitArgs[0] === "rev-parse" && gitArgs[1] === "--git-path") return ".git/absent"; if (gitArgs[0] === "symbolic-ref") return "refs/remotes/origin/main"; throw new Error(`unexpected git ${gitArgs.join(" ")}`); },
    readTopology: async () => ({ resources, currentVersionIds, observedSlotIdentities, observedSlotIdentitiesSha256: canonicalSha256(observedSlotIdentities) }), auditReferences: () => auditWithLegacy, output: () => {},
  };
  let crash = true;
  await assert.rejects(() => runProductionDualSlotRebaselineCli({ ...common, afterAbandonmentPersist: async () => { if (crash) throw new Error("injected preparation crash"); } }), /injected preparation crash/);
  const abandonmentPath = path.join(outputs.directory, "abandonment-evidence.json"); const firstEvidence = readFileSync(abandonmentPath);
  assert.equal(existsSync(path.join(outputs.directory, "rebaseline-preparation.json")), false);
  crash = false;
  const resumed = await runProductionDualSlotRebaselineCli({ ...common });
  assert.equal(resumed.writeCount, 7); assert.deepEqual(readFileSync(abandonmentPath), firstEvidence); assert.equal(existsSync(resumed.preparationFile), true);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("production prepare CLI resumes an exact preparation published before its process acknowledgement", async () => {
  const outputs = temporary();
  const auditWithLegacy = { ...audit, legacy: legacyBaseline, runningTasks: 2, pendingTasks: 0, activeTaskDefinition: "fixture-backend:1" };
  const common = {
    argv: ["--prepare", "--source-sha", sourceSha, "--rotation-id", rotationId, "--output-directory", outputs.directory, "--database-dependencies", "0", "--external-consumers", "0"],
    repositoryRoot: process.cwd(), readCheckout: () => ({ toolingSha: sourceSha, porcelainStatus: "" }), createRun: () => () => "{}", createClient: () => ({ assertCredentialIdentity: async () => {} }), historicalTopologySha256,
    gitRun: (gitArgs) => { if (gitArgs[0] === "fetch" || gitArgs[0] === "merge-base") return ""; if (gitArgs[0] === "status") return ""; if (gitArgs[0] === "rev-parse" && gitArgs[1] === "--is-shallow-repository") return "false"; if (gitArgs[0] === "rev-parse" && (gitArgs[1] === "FETCH_HEAD" || gitArgs[1] === "HEAD")) return `${sourceSha}\n`; if (gitArgs[0] === "rev-parse" && gitArgs[1] === "--git-path") return ".git/absent"; if (gitArgs[0] === "symbolic-ref") return "refs/remotes/origin/main"; throw new Error(`unexpected git ${gitArgs.join(" ")}`); },
    readTopology: async () => ({ resources, currentVersionIds, observedSlotIdentities, observedSlotIdentitiesSha256: canonicalSha256(observedSlotIdentities) }), auditReferences: () => auditWithLegacy, output: () => {},
  };
  await assert.rejects(() => runProductionDualSlotRebaselineCli({ ...common, afterPreparationPersist: async () => { throw new Error("injected post-preparation crash"); } }), /injected post-preparation crash/);
  const preparationPath = path.join(outputs.directory, "rebaseline-preparation.json");
  const firstPreparation = readFileSync(preparationPath);
  const resumed = await runProductionDualSlotRebaselineCli(common);
  assert.equal(resumed.preparationSha256.length, 64);
  assert.deepEqual(readFileSync(preparationPath), firstPreparation);
  const divergent = JSON.parse(readFileSync(preparationPath, "utf8"));
  divergent.writePlan[0].clientRequestToken = sha256("divergent-preparation-write");
  const { preparationSha256, ...preparationBody } = divergent;
  divergent.preparationSha256 = canonicalSha256(preparationBody);
  writeFileSync(preparationPath, `${JSON.stringify(divergent)}\n`);
  await assert.rejects(() => runProductionDualSlotRebaselineCli(common), /write plan|preparation/i);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("production prepare CLI rejects a divergent existing abandonment artifact", async () => {
  const outputs = temporary(); const args = ["--prepare", "--source-sha", sourceSha, "--rotation-id", rotationId, "--output-directory", outputs.directory, "--database-dependencies", "0", "--external-consumers", "0"];
  const auditWithLegacy = { ...audit, legacy: legacyBaseline, runningTasks: 2, pendingTasks: 0, activeTaskDefinition: "fixture-backend:1" };
  const common = {
    argv: args, repositoryRoot: process.cwd(), readCheckout: () => ({ toolingSha: sourceSha, porcelainStatus: "" }), createRun: () => () => "{}", createClient: () => ({ assertCredentialIdentity: async () => {} }), historicalTopologySha256,
    gitRun: (gitArgs) => { if (gitArgs[0] === "fetch" || gitArgs[0] === "merge-base") return ""; if (gitArgs[0] === "status") return ""; if (gitArgs[0] === "rev-parse" && gitArgs[1] === "--is-shallow-repository") return "false"; if (gitArgs[0] === "rev-parse" && (gitArgs[1] === "FETCH_HEAD" || gitArgs[1] === "HEAD")) return `${sourceSha}\n`; if (gitArgs[0] === "rev-parse" && gitArgs[1] === "--git-path") return ".git/absent"; if (gitArgs[0] === "symbolic-ref") return "refs/remotes/origin/main"; throw new Error(`unexpected git ${gitArgs.join(" ")}`); },
    readTopology: async () => ({ resources, currentVersionIds, observedSlotIdentities, observedSlotIdentitiesSha256: canonicalSha256(observedSlotIdentities) }), auditReferences: () => auditWithLegacy, output: () => {},
  };
  await runProductionDualSlotRebaselineCli({ ...common });
  const abandonmentPath = path.join(outputs.directory, "abandonment-evidence.json"); const divergent = JSON.parse(readFileSync(abandonmentPath, "utf8")); divergent.currentVersionIds = { ...divergent.currentVersionIds, jwtPending: "divergent-version" }; writeFileSync(abandonmentPath, `${JSON.stringify(divergent, null, 2)}\n`);
  await assert.rejects(() => runProductionDualSlotRebaselineCli({ ...common }), /hash|identity|match|exact/i);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("seven-slot execution resumes at every write boundary and persists exact completion plus bindings", async () => {
  for (let failAt = 1; failAt <= 7; failAt += 1) { const outputs = temporary(); const adapters = executionAdapters({ failAt }); await assert.rejects(() => execute(adapters, outputs), /interruption/); const resumed = await execute(adapters, outputs); assert.equal(resumed.baselineComplete, true); assert.equal(JSON.stringify(resumed.completion).includes(material.jwt), false); assert.equal(readFileSync(outputs.completionFile, "utf8").includes(material.jwt), false); rmSync(outputs.directory, { recursive: true, force: true }); }
});

test("executor waits for a bounded read-only convergence after an acknowledged deterministic write", async () => {
  const outputs = temporary(); const adapters = executionAdapters({ postWriteHistoricalReadLag: 1 });
  const result = await execute(adapters, outputs, { sleep: () => {} });
  assert.equal(result.baselineComplete, true);
  assert.equal(adapters.store.get("jwtPending").filter(({ versionId }) => versionId === writePlan.find(({ slot }) => slot === "jwtPending").clientRequestToken).length, 1);
  assert.equal(adapters.operations.filter(({ operation, slot }) => operation === "write" && slot === "jwtPending").length, 1);
  assert.equal(adapters.operations.filter(({ operation, slot }) => operation === "read" && slot === "jwtPending").length >= 3, true);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("post-write convergence rejects every non-historical non-exact state without another secret write", async () => {
  const jwt = writePlan.find(({ slot }) => slot === "jwtPending");
  const variants = [
    { name: "wrong version", snapshot: () => ({ arn: jwt.secretArn, versions: [{ versionId: sha256("wrong-version"), stages: ["AWSCURRENT"], payloadSha256: jwt.payloadSha256 }], currentVersionId: sha256("wrong-version"), currentStages: ["AWSCURRENT"], currentPayloadSha256: jwt.payloadSha256 }) },
    { name: "wrong payload", snapshot: () => ({ arn: jwt.secretArn, versions: [{ versionId: jwt.clientRequestToken, stages: ["AWSCURRENT"], payloadSha256: sha256("wrong-payload") }], currentVersionId: jwt.clientRequestToken, currentStages: ["AWSCURRENT"], currentPayloadSha256: sha256("wrong-payload") }) },
    { name: "wrong stage", snapshot: () => ({ arn: jwt.secretArn, versions: [{ versionId: jwt.clientRequestToken, stages: ["AWSPREVIOUS"], payloadSha256: jwt.payloadSha256 }], currentVersionId: jwt.clientRequestToken, currentStages: ["AWSPREVIOUS"], currentPayloadSha256: jwt.payloadSha256 }) },
  ];
  for (const { name, snapshot } of variants) {
    const outputs = temporary(); const adapters = executionAdapters(); let wrote = false;
    const readSlot = adapters.readSlot; const writeSlot = adapters.writeSlot;
    adapters.writeSlot = async (...args) => { const result = await writeSlot(...args); wrote = true; return result; };
    adapters.readSlot = async (...args) => wrote ? snapshot() : readSlot(...args);
    await assert.rejects(() => execute(adapters, outputs, { sleep: () => {} }), /deterministic|current version|prepared write|exactly one/);
    assert.equal([...adapters.store.values()].reduce((total, versions) => total + versions.length, 0), 8, name);
    rmSync(outputs.directory, { recursive: true, force: true });
  }
});

test("post-write historical snapshots time out and read errors fail closed without another secret write", async () => {
  const timeoutOutputs = temporary(); const timeoutAdapters = executionAdapters({ postWriteHistoricalReadLag: 6 });
  await assert.rejects(() => execute(timeoutAdapters, timeoutOutputs, { sleep: () => {} }), /did not converge/);
  assert.equal([...timeoutAdapters.store.values()].reduce((total, versions) => total + versions.length, 0), 8);
  rmSync(timeoutOutputs.directory, { recursive: true, force: true });

  const errorOutputs = temporary(); const errorAdapters = executionAdapters(); let wrote = false;
  const readSlot = errorAdapters.readSlot; const writeSlot = errorAdapters.writeSlot;
  errorAdapters.writeSlot = async (...args) => { const result = await writeSlot(...args); wrote = true; return result; };
  errorAdapters.readSlot = async (...args) => { if (wrote) throw new Error("injected post-write read failure"); return readSlot(...args); };
  await assert.rejects(() => execute(errorAdapters, errorOutputs, { sleep: () => {} }), /injected post-write read failure/);
  assert.equal([...errorAdapters.store.values()].reduce((total, versions) => total + versions.length, 0), 8);
  rmSync(errorOutputs.directory, { recursive: true, force: true });
});

test("authenticated one-of-seven resume skips the converged slot and writes the remaining six", async () => {
  const outputs = temporary(); const adapters = executionAdapters(); const jwt = writePlan.find(({ slot }) => slot === "jwtPending");
  adapters.store.set("jwtPending", [{ versionId: currentVersionIds.jwtPending, stages: ["AWSPREVIOUS"], payloadSha256: observedSlotIdentities.jwtPending.payloadSha256 }, { versionId: jwt.clientRequestToken, stages: ["AWSCURRENT"], payloadSha256: jwt.payloadSha256 }]);
  const result = await execute(adapters, outputs, { sleep: () => {} });
  assert.equal(result.writes, 6);
  assert.equal(adapters.operations.filter(({ operation, slot }) => operation === "write" && slot === "jwtPending").length, 0);
  assert.equal([...adapters.store.values()].reduce((total, versions) => total + versions.length, 0), 14);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("every partial write boundary resumes through harmless ECS task replacement but not a changed task-definition set", async () => {
  for (let failAt = 0; failAt <= 7; failAt += 1) {
    const outputs = temporary(); let observation = 0;
    const adapters = executionAdapters({ failAt, liveReferenceAudit: () => ({ ...audit, auditSha256: canonicalSha256({ observation: observation++, taskArn: `replacement-${observation}` }) }) });
    if (failAt > 0) await assert.rejects(() => execute(adapters, outputs), /interruption/);
    const resumed = await execute(adapters, outputs); assert.equal(resumed.baselineComplete, true); assert.equal(resumed.writes, failAt === 0 ? 7 : 7 - failAt);
    rmSync(outputs.directory, { recursive: true, force: true });
  }
  const outputs = temporary(); const unsafe = executionAdapters({ liveReferenceAudit: { ...audit, stableAuditSha256: "0".repeat(64) } });
  await assert.rejects(() => execute(unsafe, outputs), /security topology/); assert.equal([...unsafe.store.values()].every((versions) => versions.length === 1), true);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("executor rejects an unrecognized current secret version before another write", async () => {
  const outputs = temporary(); const adapters = executionAdapters(); const slot = REBASELINE_SLOT_ORDER[0];
  adapters.store.set(slot, [{ versionId: sha256("unexpected-current"), stages: ["AWSCURRENT"], payloadSha256: canonicalSha256({ value: "unrelated" }) }]);
  await assert.rejects(() => execute(adapters, outputs), /neither the authenticated historical state nor the exact prepared write/);
  assert.equal([...adapters.store.values()].every((versions) => versions.length === 1), true);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("completion and bindings persistence crash windows resume with zero duplicate secret versions", async () => {
  for (const hook of ["afterCompletionPersist", "afterBindingsPersist"]) {
    const outputs = temporary(); const adapters = executionAdapters(); let injected = false;
    await assert.rejects(() => execute(adapters, outputs, { [hook]: async () => { if (!injected) { injected = true; throw new Error(`crash after ${hook}`); } } }), /crash/);
    const resumed = await execute(adapters, outputs); assert.equal(resumed.writes, 0); assert.equal(resumed.baselineComplete, true); rmSync(outputs.directory, { recursive: true, force: true });
  }
});

test("immutable JSON publication never leaves a partial final path across crash points", () => {
  const value = { schemaVersion: 1, kind: "crash-safe-fixture", identity: "a".repeat(64) };
  const crashMethods = ["openSync", "writeSync", "fsyncSync", "closeSync", "linkSync"];
  for (const method of crashMethods) {
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-persist-crash-")); chmodSync(directory, 0o700);
    const filePath = path.join(directory, "completion.json"); let crashed = false;
    const fsOps = new Proxy(fs, { get(target, property) { const operation = target[property]; if (property !== method || typeof operation !== "function") return operation; return (...args) => { if (!crashed) { crashed = true; throw new Error(`injected ${method} crash`); } return operation(...args); }; } });
    assert.throws(() => persistExactPrivateJson({ filePath, value, repositoryRoot: process.cwd(), label: "Crash fixture", fsOps }), /crash/);
    assert.equal(fs.existsSync(filePath), false); assert.doesNotThrow(() => persistExactPrivateJson({ filePath, value, repositoryRoot: process.cwd(), label: "Crash fixture" }));
    assert.deepEqual(JSON.parse(readFileSync(filePath, "utf8")), value); rmSync(directory, { recursive: true, force: true });
  }
});

test("immutable JSON publication resumes exact finals, ignores orphan temps, and rejects races or replacements", () => {
  const value = { schemaVersion: 1, kind: "publication-fixture", identity: "b".repeat(64) }; const other = { ...value, identity: "c".repeat(64) };
  const scenarios = [
    (directory, filePath) => { writeFileSync(path.join(directory, ".stage-b-private-orphan.tmp"), "truncated", { mode: 0o600 }); },
    (directory, filePath) => { writeFileSync(path.join(directory, ".stage-b-private-complete.tmp"), `${JSON.stringify(value)}\n`, { mode: 0o600 }); },
  ];
  for (const seedOrphan of scenarios) { const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-persist-orphan-")); chmodSync(directory, 0o700); const filePath = path.join(directory, "bindings.json"); seedOrphan(directory, filePath); assert.doesNotThrow(() => persistExactPrivateJson({ filePath, value, repositoryRoot: process.cwd(), label: "Orphan fixture" })); rmSync(directory, { recursive: true, force: true }); }
  for (const seed of [value, other]) { const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-persist-final-")); chmodSync(directory, 0o700); const filePath = path.join(directory, "bindings.json"); writeFileSync(filePath, `${JSON.stringify(seed, null, 2)}\n`, { mode: 0o600 }); if (seed === value) assert.doesNotThrow(() => persistExactPrivateJson({ filePath, value, repositoryRoot: process.cwd(), label: "Existing fixture" })); else assert.throws(() => persistExactPrivateJson({ filePath, value, repositoryRoot: process.cwd(), label: "Existing fixture" }), /different|identity/i); rmSync(directory, { recursive: true, force: true }); }
  for (const raceValue of [value, other]) { const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-persist-race-")); chmodSync(directory, 0o700); const filePath = path.join(directory, "completion.json"); const fsOps = new Proxy(fs, { get(target, property) { const operation = target[property]; if (property !== "linkSync") return operation; return (temporary, final) => { writeFileSync(final, `${JSON.stringify(raceValue, null, 2)}\n`, { mode: 0o600, flag: "wx" }); return operation.call(target, temporary, final); }; } }); if (raceValue === value) assert.doesNotThrow(() => persistExactPrivateJson({ filePath, value, repositoryRoot: process.cwd(), label: "Race fixture", fsOps })); else assert.throws(() => persistExactPrivateJson({ filePath, value, repositoryRoot: process.cwd(), label: "Race fixture", fsOps }), /different|identity/i); rmSync(directory, { recursive: true, force: true }); }
});

test("publication failure after no-replace link leaves a complete final that retries safely", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-persist-after-link-")); chmodSync(directory, 0o700); const filePath = path.join(directory, "completion.json"); const value = { kind: "after-link", identity: "d".repeat(64) }; let fsyncCalls = 0;
  const fsOps = new Proxy(fs, { get(target, property) { const operation = target[property]; if (property !== "fsyncSync") return operation; return (...args) => { fsyncCalls += 1; if (fsyncCalls === 2) throw new Error("injected post-publication crash"); return operation(...args); }; } });
  assert.throws(() => persistExactPrivateJson({ filePath, value, repositoryRoot: process.cwd(), label: "Post-link fixture", fsOps }), /post-publication/); assert.deepEqual(JSON.parse(readFileSync(filePath, "utf8")), value); assert.doesNotThrow(() => persistExactPrivateJson({ filePath, value, repositoryRoot: process.cwd(), label: "Post-link fixture" })); rmSync(directory, { recursive: true, force: true });
});

test("material journal uses the same crash-safe immutable publication path", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-journal-crash-")); chmodSync(directory, 0o700); const filePath = path.join(directory, "material-journal.json"); let failed = false;
  const fsOps = new Proxy(fs, { get(target, property) { const operation = target[property]; if (property !== "writeSync") return operation; return (...args) => { if (!failed) { failed = true; throw new Error("injected journal write crash"); } return operation(...args); }; } });
  assert.throws(() => writeRebaselineMaterialJournal({ filePath, repositoryRoot: process.cwd(), sourceSha, rotationId, baselineIdentitySha256: identity.identitySha256, generatedMaterial: material, fsOps }), /journal write crash/); assert.equal(fs.existsSync(filePath), false); assert.doesNotThrow(() => writeRebaselineMaterialJournal({ filePath, repositoryRoot: process.cwd(), sourceSha, rotationId, baselineIdentitySha256: identity.identitySha256, generatedMaterial: material })); rmSync(directory, { recursive: true, force: true });
});

test("durable output preflight fails before any secret write when an existing output accompanies a partial baseline", async () => {
  const outputs = temporary(); writeFileSync(outputs.completionFile, "{}", { mode: 0o600 }); const adapters = executionAdapters();
  await assert.rejects(() => execute(adapters, outputs), /output|incomplete/i);
  assert.equal([...adapters.store.entries()].every(([slot, versions]) => versions.length === 1 && versions[0].versionId === currentVersionIds[slot]), true);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("runtime admits only a declared rebaseline producer anchored to independent authorization", async () => {
  const outputs = temporary(); const result = await execute(executionAdapters(), outputs); const auth = authorization();
  assertBaselineCompletion(result.completion, { sourceSha, rotationId, resources, authorizationBinding: auth.authorizationSha256, writePayloadIdentities: auth.writePayloadIdentities }); assertRebaselineRotationBindings(result.bindings, { authorization: auth }); assert.doesNotThrow(() => assertBindings(result.bindings, { rebaselineAuthorization: auth, verifyRebaselineLivePostWrite: () => ({ kind: "PRODUCTION_DUAL_SLOT_REBASELINE_LIVE_POST_WRITE", sourceSha, rotationId, authorizationSha256: auth.authorizationSha256, resources, versionIds: auth.writeIdentities, payloadIdentities: auth.writePayloadIdentities, livePostWriteSha256: canonicalSha256({ kind: "PRODUCTION_DUAL_SLOT_REBASELINE_LIVE_POST_WRITE", sourceSha, rotationId, authorizationSha256: auth.authorizationSha256, resources, versionIds: auth.writeIdentities, payloadIdentities: auth.writePayloadIdentities }) }), verifyInitialBindingOrigin }));
  const stripped = { ...result.bindings }; delete stripped.operation; delete stripped.baselineCompletionSha256; assert.throws(() => assertBindings(stripped, { rebaselineAuthorization: auth, verifyRebaselineLivePostWrite: () => ({}), verifyInitialBindingOrigin }), /schema|producer|rebaseline|origin/i);
  const fabricated = { ...result.completion, authorizationBinding: "f".repeat(64) }; fabricated.baselineBindingSha256 = canonicalSha256(Object.fromEntries(Object.entries(fabricated).filter(([key]) => key !== "baselineBindingSha256"))); const bad = { ...result.bindings, baselineCompletion: fabricated, baselineCompletionSha256: fabricated.baselineBindingSha256 }; assert.throws(() => assertBindings(bad, { rebaselineAuthorization: auth, verifyRebaselineLivePostWrite: () => ({}), verifyInitialBindingOrigin }), /authorization|origin/i);
  assert.doesNotThrow(() => readBoundBaselineCompletion({ filePath: outputs.completionFile, expectedSha256: result.completionSha256, authorization: auth }));
  assert.throws(() => readBoundBaselineCompletion({ filePath: outputs.completionFile, expectedSha256: result.completionSha256, authorization: { ...auth, authorizationSha256: "f".repeat(64) } }), /hash|authorization/i);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("durable rebaseline evidence persists only non-secret exact transition records", async () => {
  const outputs = temporary(); const materialFile = path.join(outputs.directory, "material-journal.json");
  writeRebaselineMaterialJournal({ filePath: materialFile, repositoryRoot: process.cwd(), sourceSha, rotationId, baselineIdentitySha256: identity.identitySha256, generatedMaterial: material });
  const materialBytes = readFileSync(materialFile); const auth = authorization({ materialJournalSha256: JSON.parse(materialBytes).journalSha256, materialJournalFileSha256: sha256(materialBytes) });
  await execute(executionAdapters(), outputs, { authorization: auth });
  const bundle = buildProductionDualSlotRebaselineDurableEvidence({
    publisherSourceSha: sourceSha, authorizationWorkflowRunId: "123456", authorizationWorkflowRunAttempt: "1",
    preparationBytes: Buffer.from(JSON.stringify(preparation)), materialJournalBytes: readFileSync(materialFile), completionBytes: readFileSync(outputs.completionFile), bindingsBytes: readFileSync(outputs.bindingsFile), authorization: auth,
  });
  assert.throws(() => buildProductionDualSlotRebaselineDurableEvidence({
    publisherSourceSha: sourceSha, authorizationWorkflowRunId: "765432", authorizationWorkflowRunAttempt: "1",
    preparationBytes: Buffer.from(JSON.stringify(preparation)), materialJournalBytes: readFileSync(materialFile), completionBytes: readFileSync(outputs.completionFile), bindingsBytes: readFileSync(outputs.bindingsFile), authorization: auth,
  }), /coordinates do not match the authenticated approval/);
  assert.equal(Object.hasOwn(bundle, "generatedMaterial"), false);
  assert.doesNotMatch(JSON.stringify(bundle), /generatedMaterial|BEGIN PRIVATE KEY|"value"\s*:/i);
  assert.doesNotThrow(() => assertProductionDualSlotRebaselineDurableEvidence(bundle, { publisherSourceSha: sourceSha, authorization: auth }));
  const alteredJournal = structuredClone(bundle); alteredJournal.manifest.materialJournalSha256 = "f".repeat(64); const { evidenceSha256: journalEvidenceSha, ...journalBody } = alteredJournal.manifest; alteredJournal.manifest.evidenceSha256 = canonicalSha256(journalBody);
  assert.throws(() => assertProductionDualSlotRebaselineDurableEvidence(alteredJournal, { publisherSourceSha: sourceSha, authorization: auth }), /material journal|authenticated transition/i);
  const alteredJournalFile = structuredClone(bundle); alteredJournalFile.manifest.materialJournalFileSha256 = "f".repeat(64); const { evidenceSha256: journalFileEvidenceSha, ...journalFileBody } = alteredJournalFile.manifest; alteredJournalFile.manifest.evidenceSha256 = canonicalSha256(journalFileBody);
  assert.throws(() => assertProductionDualSlotRebaselineDurableEvidence(alteredJournalFile, { publisherSourceSha: sourceSha, authorization: auth }), /material journal|authenticated transition/i);
  const alternatePreparationBytes = Buffer.from(`${JSON.stringify(preparation, null, 4)}\n`);
  const canonicalized = buildProductionDualSlotRebaselineDurableEvidence({ publisherSourceSha: sourceSha, authorizationWorkflowRunId: "123456", authorizationWorkflowRunAttempt: "1", preparationBytes: alternatePreparationBytes, materialJournalBytes: materialBytes, completionBytes: readFileSync(outputs.completionFile), bindingsBytes: readFileSync(outputs.bindingsFile), authorization: auth });
  assert.equal(canonicalized.manifest.preparationFileSha256, bundle.manifest.preparationFileSha256);
  const substitutedMaterialFile = path.join(outputs.directory, "substituted-material-journal.json");
  writeRebaselineMaterialJournal({ filePath: substitutedMaterialFile, repositoryRoot: process.cwd(), sourceSha, rotationId, baselineIdentitySha256: identity.identitySha256, generatedMaterial: generateRebaselineMaterial() });
  assert.throws(() => buildProductionDualSlotRebaselineDurableEvidence({
    publisherSourceSha: sourceSha, authorizationWorkflowRunId: "123456", authorizationWorkflowRunAttempt: "1",
    preparationBytes: Buffer.from(JSON.stringify(preparation)), materialJournalBytes: readFileSync(substitutedMaterialFile), completionBytes: readFileSync(outputs.completionFile), bindingsBytes: readFileSync(outputs.bindingsFile), authorization: auth,
  }), /material journal does not produce the authenticated prepared writes/);
  const alteredPreparation = structuredClone(bundle); alteredPreparation.preparation.sourceSha = "f".repeat(40);
  assert.throws(() => assertProductionDualSlotRebaselineDurableEvidence(alteredPreparation, { publisherSourceSha: sourceSha, authorization: auth }), /preparation|source/i);
  const alteredCompletion = structuredClone(bundle); alteredCompletion.completion.authorizationBinding = "f".repeat(64);
  assert.throws(() => assertProductionDualSlotRebaselineDurableEvidence(alteredCompletion, { publisherSourceSha: sourceSha, authorization: auth }), /completion|authorization/i);
  const alteredBindings = structuredClone(bundle); alteredBindings.bindings.rotationId = "rotation-other-20260828";
  assert.throws(() => assertProductionDualSlotRebaselineDurableEvidence(alteredBindings, { publisherSourceSha: sourceSha, authorization: auth }), /authorization|binding|rotation/i);
  const alteredManifest = structuredClone(bundle); alteredManifest.manifest.publisherSourceSha = "f".repeat(40); const { evidenceSha256, ...manifestBody } = alteredManifest.manifest; alteredManifest.manifest.evidenceSha256 = canonicalSha256(manifestBody);
  assert.throws(() => assertProductionDualSlotRebaselineDurableEvidence(alteredManifest, { publisherSourceSha: sourceSha, authorization: auth }), /manifest|source/i);
  const alteredCoordinates = structuredClone(bundle); alteredCoordinates.manifest.authorizationWorkflowRunId = "765432"; const { evidenceSha256: coordinateHash, ...coordinateBody } = alteredCoordinates.manifest; alteredCoordinates.manifest.evidenceSha256 = canonicalSha256(coordinateBody);
  assert.throws(() => assertProductionDualSlotRebaselineDurableEvidence(alteredCoordinates, { publisherSourceSha: sourceSha, authorization: auth }), /coordinates do not match the authenticated approval/);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("durable publisher conditionally creates and reads back the exact canonical bytes", async () => {
  const outputs = temporary(); const materialFile = path.join(outputs.directory, "material-journal.json");
  writeRebaselineMaterialJournal({ filePath: materialFile, repositoryRoot: process.cwd(), sourceSha, rotationId, baselineIdentitySha256: identity.identitySha256, generatedMaterial: material });
  const materialBytes = readFileSync(materialFile); const auth = authorization({ materialJournalSha256: JSON.parse(materialBytes).journalSha256, materialJournalFileSha256: sha256(materialBytes) });
  await execute(executionAdapters(), outputs, { authorization: auth });
  const bundle = { ...buildProductionDualSlotRebaselineDurableEvidence({ publisherSourceSha: sourceSha, authorizationWorkflowRunId: "123456", authorizationWorkflowRunAttempt: "1", preparationBytes: Buffer.from(JSON.stringify(preparation)), materialJournalBytes: materialBytes, completionBytes: readFileSync(outputs.completionFile), bindingsBytes: readFileSync(outputs.bindingsFile), authorization: auth }), authorization: auth };
  let body; const run = (args) => {
    if (args[1] === "put-object") { body = readFileSync(args[args.indexOf("--body") + 1]); return "{}"; }
    if (args[1] === "head-object") return JSON.stringify({ ServerSideEncryption: "AES256", ContentLength: body.length });
    if (args[1] === "get-object") { writeFileSync(args.at(-1), body); return "{}"; }
    throw new Error(`unexpected ${args.join(" ")}`);
  };
  const persisted = persistProductionDualSlotRebaselineDurableEvidence({ bundle, publisherSourceSha: sourceSha, run, protectedCheckout: () => { assertStageBCanonicalRepositoryUrl("https://github.com/T-ej2003/genuine-scan-main.git"); return protectedCheckout(); } });
  assert.equal(persisted.status, "CREATED"); assert.match(persisted.key, new RegExp(`^production-dual-slot-rebaseline-evidence/${rotationId}/`));
  assert.deepEqual(Object.keys(JSON.parse(body)).sort(), ["bindings", "completion", "manifest", "preparation"]);
  assert.equal(Object.hasOwn(JSON.parse(body), "authorization"), false);
  assert.throws(() => persistProductionDualSlotRebaselineDurableEvidence({ bundle: { ...bundle, attackerControlled: { not: "durable" } }, publisherSourceSha: sourceSha, run, protectedCheckout: () => protectedCheckout() }), /unsupported top-level/i);
  assert.throws(() => persistProductionDualSlotRebaselineDurableEvidence({ bundle, publisherSourceSha: sourceSha, run: () => { throw new Error("PreconditionFailed"); }, protectedCheckout: () => protectedCheckout() }), /conditional create failed/i);
  for (const [label, checkout] of [
    ["local HEAD mismatch", protectedCheckout("b".repeat(40))],
    ["origin/main mismatch", protectedCheckout(sourceSha, { originMainHead: "b".repeat(40) })],
    ["dirty worktree", protectedCheckout(sourceSha, { porcelainStatus: " M tracked.js" })],
    ["malformed source evidence", {}],
  ]) {
    let putCount = 0;
    assert.throws(() => persistProductionDualSlotRebaselineDurableEvidence({ bundle, publisherSourceSha: sourceSha, run: (args) => { if (args[1] === "put-object") putCount += 1; }, protectedCheckout: () => checkout }), /Stage B|protected|checkout|field/i, label);
    assert.equal(putCount, 0, label);
  }
  assert.throws(() => persistProductionDualSlotRebaselineDurableEvidence({ bundle, publisherSourceSha: sourceSha, run: () => { throw new Error("source CAS failed"); }, protectedCheckout: () => { throw new Error("source authentication failed"); } }), /source authentication failed/);
  for (const remote of [
    "https://github.com/attacker/genuine-scan-main.git",
    "https://github.com/T-ej2003/other-repository.git",
    "https://github.com/T-ej2003/genuine-scan-main-fork.git",
    "https://gitlab.com/T-ej2003/genuine-scan-main.git",
    "malformed-remote",
  ]) {
    let putCount = 0;
    assert.throws(() => persistProductionDualSlotRebaselineDurableEvidence({ bundle, publisherSourceSha: sourceSha, run: (args) => { if (args[1] === "put-object") putCount += 1; }, protectedCheckout: () => { assertStageBCanonicalRepositoryUrl(remote); return protectedCheckout(); } }), /canonical|malformed/);
    assert.equal(putCount, 0, remote);
  }
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("durable rebaseline resolver reads only its immutable S3 coordinate", async () => {
  const outputs = temporary(); const materialFile = path.join(outputs.directory, "material-journal.json");
  writeRebaselineMaterialJournal({ filePath: materialFile, repositoryRoot: process.cwd(), sourceSha, rotationId, baselineIdentitySha256: identity.identitySha256, generatedMaterial: material });
  const materialBytes = readFileSync(materialFile); const auth = authorization({ materialJournalSha256: JSON.parse(materialBytes).journalSha256, materialJournalFileSha256: sha256(materialBytes) });
  await execute(executionAdapters(), outputs, { authorization: auth });
  const bundle = buildProductionDualSlotRebaselineDurableEvidence({ publisherSourceSha: sourceSha, authorizationWorkflowRunId: "123456", authorizationWorkflowRunAttempt: "1", preparationBytes: Buffer.from(JSON.stringify(preparation)), materialJournalBytes: readFileSync(materialFile), completionBytes: readFileSync(outputs.completionFile), bindingsBytes: readFileSync(outputs.bindingsFile), authorization: auth });
  const run = (command, args) => {
    if (command === "aws" && args[0] === "s3api" && args[1] === "get-object") { writeFileSync(args.at(-1), `${JSON.stringify(bundle, null, 2)}\n`); return "{}"; }
    throw new Error(`unexpected ${command} ${args.join(" ")}`);
  };
  const options = { evidenceSha256: bundle.manifest.evidenceSha256, publisherSourceSha: sourceSha, authorization: auth, run };
  assert.equal(resolveProductionDualSlotRebaselineDurableEvidenceArtifact(options).evidence.manifest.evidenceSha256, bundle.manifest.evidenceSha256);
  assert.throws(() => resolveProductionDualSlotRebaselineDurableEvidenceArtifact({ ...options, run: (command, args) => { if (command === "aws" && args[0] === "s3api" && args[1] === "get-object") { writeFileSync(args.at(-1), `${JSON.stringify({ ...bundle, attackerControlled: "not authenticated" }, null, 2)}\n`); return "{}"; } throw new Error(`unexpected ${command} ${args.join(" ")}`); } }), /schema|unsupported field/i);
  assert.throws(() => resolveProductionDualSlotRebaselineDurableEvidenceArtifact({ ...options, evidenceSha256: "f".repeat(64) }), /coordinate|immutable/i);
  assert.throws(() => resolveProductionDualSlotRebaselineDurableEvidenceArtifact({ ...options, publisherSourceSha: "f".repeat(40) }), /source|manifest/i);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("runtime legacy/current secret identifiers are anchored to the authorized baseline identity", async () => {
  const outputs = temporary(); const result = await execute(executionAdapters(), outputs); const auth = authorization();
  for (const [group, field] of [["jwt", "currentSecretId"], ["qr", "privateCurrentSecretId"], ["qr", "publicCurrentSecretId"]]) {
    const tampered = structuredClone(result.bindings); tampered[group][field] = `${tampered[group][field]}-substituted`;
    assert.throws(() => assertRebaselineRotationBindings(tampered, { authorization: auth }), /legacy baseline|authorization|inconsistent/i);
  }
  const swapped = structuredClone(result.bindings); swapped.jwt.currentSecretId = result.bindings.qr.publicCurrentSecretId; swapped.legacy.jwtCurrent = swapped.jwt.currentSecretId;
  assert.throws(() => assertRebaselineRotationBindings(swapped, { authorization: auth }), /legacy baseline|authorization|inconsistent/i);
  rmSync(outputs.directory, { recursive: true, force: true });
});

test("runtime authorization resolver derives the expected digest from GitHub provenance, never the completion", () => {
  const auth = authorization(); const archive = Buffer.from("zip-fixture"); const seen = [];
  const execute = (command, args, options) => {
    seen.push({ command, args, options });
    if (command === "gh" && args[1] === "repos/T-ej2003/genuine-scan-main/actions/runs/123456") return JSON.stringify({ id: 123456, repository: { id: 9, full_name: PRODUCTION_DUAL_SLOT_REBASELINE.repository }, head_repository: { full_name: PRODUCTION_DUAL_SLOT_REBASELINE.repository }, path: ".github/workflows/authorize-production-dual-slot-rebaseline.yml", event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", run_attempt: 1, actor: { login: "operator" } });
    if (command === "gh" && args[1].endsWith("/artifacts")) return JSON.stringify([{ artifacts: [{ id: 91, name: "production-dual-slot-rebaseline-authorization", expired: false, workflow_run: { id: 123456, head_sha: sourceSha, repository_id: 9 }, digest: `sha256:${sha256(archive)}` }] }]);
    if (command === "gh" && args[1].endsWith("/zip")) return archive;
    if (command === "unzip" && args[0] === "-Z1") return "authorization.json\n";
    if (command === "unzip" && args[0] === "-Z") return "-  authorization.json\n";
    if (command === "unzip" && args[0] === "-p") return JSON.stringify(auth);
    throw new Error(`unexpected ${command} ${args.join(" ")}`);
  };
  const run = createProductionGithubCommandRunner({ env: { GH_TOKEN: "fixture-github-token" }, exec: execute });
  const resolved = resolveProductionDualSlotRebaselineAuthorizationArtifact({ workflowRunId: "123456", workflowRunAttempt: "1", sourceSha, rotationId, resources, run });
  assert.equal(resolved.authorization.authorizationSha256, auth.authorizationSha256); const zip = seen.find(({ args }) => args[1].endsWith("/zip")); assert.equal(zip.options.encoding, null); assert.equal(zip.args.includes("--output"), false);
});

test("successor recovery resolver accepts only its exact protected workflow artifact", () => {
  const sourceSha = PARTIAL_REBASELINE_RECOVERY_BASE_SOURCE_SHA;
  const envelope = recoveryEnvelopeFixture();
  const image = makeCanonicalImageAuthorization({ sourceSha, imageReleaseSha: sourceSha });
  const approval = createProductionEnvironmentApprovalEvidence({ environmentConfig: { name: "production", id: 17, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 7, login: "checker" } }] }] }, repository: PRODUCTION_DUAL_SLOT_REBASELINE.repository, environment: "production", sourceSha, workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.dualSlotRebaselineRecoveryWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "987655", workflowRunAttempt: "1", executionActor: "operator", observedAt: image.now, actualApproval: { state: "approved", environmentId: 17, environmentName: "production", userId: 7, userLogin: "checker" } });
  const liveCas = { liveReferenceAuditSha256: sha256("resolver-recovery-audit"), liveLegacyBaselineIdentitySha256: sha256("resolver-recovery-legacy"), observedSlotIdentitiesSha256: sha256("resolver-recovery-slots") };
  const authorization = createPartialRebaselineRecoveryAuthorization({ protectedEnvironmentApprovalEvidence: approval, sourceSha, recoveryEnvelope: envelope, imageAuthorization: image.authorization, imageAuthorizationValidation: { now: image.now, verifyImageEvidence: image.verifyImageEvidence }, ...liveCas, reason: "resume fixture", approverRole: "checker", verificationRef: "fixture", proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === sourceSha && descendantSha === sourceSha });
  const archive = Buffer.from("recovery-zip-fixture");
  const execute = (command, args, options = {}) => {
    if (command === "gh" && args[1].endsWith("/actions/runs/987655")) return JSON.stringify({ id: 987655, repository: { id: 9, full_name: PRODUCTION_DUAL_SLOT_REBASELINE.repository }, head_repository: { full_name: PRODUCTION_DUAL_SLOT_REBASELINE.repository }, path: ".github/workflows/authorize-production-dual-slot-rebaseline-recovery.yml", event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", run_attempt: 1, actor: { login: "operator" } });
    if (command === "gh" && args[1].endsWith("/artifacts")) return JSON.stringify([{ artifacts: [{ id: 92, name: "production-dual-slot-rebaseline-successor-recovery-authorization", expired: false, workflow_run: { id: 987655, head_sha: sourceSha, repository_id: 9 }, digest: `sha256:${sha256(archive)}` }] }]);
    if (command === "gh" && args[1].endsWith("/zip")) return archive;
    if (command === "unzip" && args[0] === "-Z1") return "recovery-authorization.json\n";
    if (command === "unzip" && args[0] === "-p") return JSON.stringify(authorization);
    throw new Error(`unexpected ${command} ${args.join(" ")}`);
  };
  const run = createProductionGithubCommandRunner({ env: { GH_TOKEN: "fixture-github-token" }, exec: execute });
  const options = { workflowRunId: "987655", workflowRunAttempt: "1", sourceSha, recoveryEnvelope: envelope, imageAuthorization: image.authorization, imageAuthorizationValidation: { now: image.now, verifyImageEvidence: image.verifyImageEvidence }, liveCas, proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === sourceSha && descendantSha === sourceSha, run };
  assert.equal(resolvePartialRebaselineRecoveryAuthorizationArtifact(options).authorization.authorizationSha256, authorization.authorizationSha256);
  assert.throws(() => resolvePartialRebaselineRecoveryAuthorizationArtifact({ ...options, workflowRunAttempt: "2" }), /provenance/i);
  assert.throws(() => resolvePartialRebaselineRecoveryAuthorizationArtifact({ ...options, sourceSha: "f".repeat(40) }), /provenance|source/i);
});

test("dispatcher reviewer text cannot replace the actual protected-environment approver", () => {
  const actual = authorization();
  assert.throws(() => createProductionDualSlotRebaselineAuthorization({ protectedEnvironmentApprovalEvidence: actual.protectedEnvironmentApprovalEvidence, sourceSha, historicalRotationId, rotationId, abandonmentEvidenceSha256: abandoned.evidenceSha256, baselineIdentitySha256: identity.identitySha256, resources, writeIdentities: actual.writeIdentities, writePayloadIdentities: actual.writePayloadIdentities, materialJournalSha256: actual.materialJournalSha256, materialJournalFileSha256: actual.materialJournalFileSha256, expectedSecretValueWrites: 7, expectedSecretDeletes: 0, liveReferenceAudit: "PASS", liveReferenceAuditSha256: audit.stableAuditSha256, observedSlotIdentitiesSha256: abandoned.observedSlotIdentitiesSha256, reason: "fixture", approvedBy: "dispatcher-not-actual", approverRole: "production-independent-checker", verificationRef: "ticket" }), /Dispatcher-supplied|authenticated/i);
});

test("full live ECS audit rejects a legacy running revision when service points at a newer revision", () => {
  const old = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:50"; const current = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:51"; const legacy = [legacyBaseline.jwtCurrent, legacyBaseline.qrPrivateCurrent, legacyBaseline.qrPublicCurrent]; const definition = (arn, references = []) => ({ taskDefinition: { taskDefinitionArn: arn, containerDefinitions: [{ name: "backend", secrets: [...legacy, ...references].map((valueFrom, index) => ({ name: ["JWT_SECRET", "QR_SIGN_PRIVATE_KEY", "QR_SIGN_PUBLIC_KEY"][index] || `EXTRA_${index}`, valueFrom })), environment: [{ name: "QR_SIGN_ACTIVE_KEY_VERSION", value: "legacy-v1" }] }] } });
  const run = (args) => { if (args[1] === "describe-services") return JSON.stringify({ services: [{ serviceArn: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr", taskDefinition: current, desiredCount: 2, runningCount: 1, pendingCount: 1, deployments: [{ id: "primary", status: "PRIMARY", taskDefinition: current }, { id: "rollback", status: "ACTIVE", taskDefinition: old }], deploymentController: { type: "ECS" } }] }); if (args[1] === "list-tasks") return JSON.stringify({ taskArns: args.includes("RUNNING") ? ["arn:aws:ecs:eu-west-2:368992683803:task/old"] : [] }); if (args[1] === "describe-tasks") return JSON.stringify({ tasks: [{ taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/old", taskDefinitionArn: old, lastStatus: "RUNNING", desiredStatus: "RUNNING" }] }); if (args[1] === "describe-task-definition") return JSON.stringify(args[args.indexOf("--task-definition") + 1] === old ? definition(old, [resources.jwtPending]) : definition(current)); throw new Error(`unexpected ${args.join(" ")}`); };
  const result = auditLiveProductionDualSlotReferences({ run, resources }); assert.equal(result.status, "FAIL"); assert.equal(result.dualSlotReferences, 1); assert.equal(result.evidence.taskDefinitionArns.includes(old), true);
});

test("ECS audit treats a desired-stopped draining task with a running lastStatus as live", () => {
  const taskArn = "arn:aws:ecs:eu-west-2:368992683803:task/draining/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const currentDefinition = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:51";
  const drainingDefinition = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:50";
  const definition = (arn, references = []) => ({ taskDefinition: { taskDefinitionArn: arn, containerDefinitions: [{ name: "backend", secrets: [legacyBaseline.jwtCurrent, legacyBaseline.qrPrivateCurrent, legacyBaseline.qrPublicCurrent, ...references].map((valueFrom, index) => ({ name: ["JWT_SECRET", "QR_SIGN_PRIVATE_KEY", "QR_SIGN_PUBLIC_KEY", "JWT_PENDING"][index], valueFrom })), environment: [{ name: "QR_SIGN_ACTIVE_KEY_VERSION", value: "legacy-v1" }] }] } });
  const run = (args) => {
    if (args[1] === "describe-services") return JSON.stringify({ services: [{ serviceArn: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr", taskDefinition: currentDefinition, desiredCount: 2, runningCount: 1, pendingCount: 0, deployments: [{ id: "primary", status: "PRIMARY", taskDefinition: currentDefinition }], deploymentController: { type: "ECS" } }] });
    if (args[1] === "list-tasks") return JSON.stringify({ taskArns: args.includes("--desired-status") && args[args.indexOf("--desired-status") + 1] === "STOPPED" ? [taskArn] : [] });
    if (args[1] === "describe-tasks") return JSON.stringify({ tasks: [{ taskArn, taskDefinitionArn: drainingDefinition, desiredStatus: "STOPPED", lastStatus: "RUNNING" }] });
    if (args[1] === "describe-task-definition") return JSON.stringify(args[args.indexOf("--task-definition") + 1] === drainingDefinition ? definition(drainingDefinition, [resources.jwtPending]) : definition(currentDefinition));
    throw new Error(`unexpected ${args.join(" ")}`);
  };
  const result = auditLiveProductionDualSlotReferences({ run, resources });
  assert.equal(result.status, "FAIL");
  assert.equal(result.dualSlotReferences, 1);
});

test("ECS audit uses lastStatus for lifecycle safety and paginates the complete census", () => {
  const currentDefinition = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:51";
  const drainingDefinition = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:50";
  const taskArn = "arn:aws:ecs:eu-west-2:368992683803:task/draining/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const legacy = [legacyBaseline.jwtCurrent, legacyBaseline.qrPrivateCurrent, legacyBaseline.qrPublicCurrent];
  const definition = (arn, references = []) => ({ taskDefinition: { taskDefinitionArn: arn, containerDefinitions: [{ name: "backend", secrets: [...legacy, ...references].map((valueFrom, index) => ({ name: ["JWT_SECRET", "QR_SIGN_PRIVATE_KEY", "QR_SIGN_PUBLIC_KEY", "JWT_PENDING"][index], valueFrom })), environment: [{ name: "QR_SIGN_ACTIVE_KEY_VERSION", value: "legacy-v1" }] }] } });
  const listCalls = [];
  const run = (args) => {
    if (args[1] === "describe-services") return JSON.stringify({ services: [{ serviceArn: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr", taskDefinition: currentDefinition, desiredCount: 2, runningCount: 1, pendingCount: 0, deployments: [{ id: "primary", status: "PRIMARY", taskDefinition: currentDefinition }], deploymentController: { type: "ECS" } }] });
    if (args[1] === "list-tasks") {
      listCalls.push(args);
      return JSON.stringify(args.includes("--starting-token") ? { taskArns: [taskArn] } : { taskArns: [], nextToken: "page-2" });
    }
    if (args[1] === "describe-tasks") return JSON.stringify({ tasks: [{ taskArn, taskDefinitionArn: drainingDefinition, desiredStatus: "STOPPED", lastStatus: "RUNNING" }] });
    if (args[1] === "describe-task-definition") return JSON.stringify(args[args.indexOf("--task-definition") + 1] === drainingDefinition ? definition(drainingDefinition, [resources.jwtPending]) : definition(currentDefinition));
    throw new Error(`unexpected ${args.join(" ")}`);
  };
  const result = auditLiveProductionDualSlotReferences({ run, resources });
  assert.equal(result.status, "FAIL");
  assert.equal(result.dualSlotReferences, 1);
  assert.equal(listCalls.length, 8);
  assert.equal(listCalls.every((args) => args.includes("--page-size") && args.includes("--max-items")), true);
  assert.equal(listCalls.some((args) => args.includes("PENDING")), false);
});

test("ECS audit excludes only terminal stopped tasks and fails on DescribeTasks failures", () => {
  const currentDefinition = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:51";
  const liveTaskArn = "arn:aws:ecs:eu-west-2:368992683803:task/live/cccccccccccccccccccccccccccccccc";
  const stoppedTaskArn = "arn:aws:ecs:eu-west-2:368992683803:task/stopped/cccccccccccccccccccccccccccccccc";
  const definition = { taskDefinition: { taskDefinitionArn: currentDefinition, containerDefinitions: [{ name: "backend", secrets: [legacyBaseline.jwtCurrent, legacyBaseline.qrPrivateCurrent, legacyBaseline.qrPublicCurrent].map((valueFrom, index) => ({ name: ["JWT_SECRET", "QR_SIGN_PRIVATE_KEY", "QR_SIGN_PUBLIC_KEY"][index], valueFrom })), environment: [{ name: "QR_SIGN_ACTIVE_KEY_VERSION", value: "legacy-v1" }] }] } };
  const makeRun = ({ failures = false } = {}) => (args) => {
    if (args[1] === "describe-services") return JSON.stringify({ services: [{ serviceArn: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr", taskDefinition: currentDefinition, desiredCount: 0, runningCount: 0, pendingCount: 0, deployments: [{ id: "primary", status: "PRIMARY", taskDefinition: currentDefinition }], deploymentController: { type: "ECS" } }] });
    if (args[1] === "list-tasks") return JSON.stringify({ taskArns: args[args.indexOf("--desired-status") + 1] === "STOPPED" ? [stoppedTaskArn] : [liveTaskArn] });
    if (args[1] === "describe-tasks") return JSON.stringify(failures ? { tasks: [], failures: [{ arn: stoppedTaskArn, reason: "missing" }] } : { tasks: [{ taskArn: liveTaskArn, taskDefinitionArn: currentDefinition, desiredStatus: "RUNNING", lastStatus: "RUNNING" }, { taskArn: stoppedTaskArn, taskDefinitionArn: currentDefinition, desiredStatus: "STOPPED", lastStatus: "STOPPED" }] });
    if (args[1] === "describe-task-definition") return JSON.stringify(definition);
    throw new Error(`unexpected ${args.join(" ")}`);
  };
  assert.equal(auditLiveProductionDualSlotReferences({ run: makeRun(), resources }).status, "PASS");
  assert.throws(() => auditLiveProductionDualSlotReferences({ run: makeRun({ failures: true }), resources }), /failures|incomplete/i);
});

test("ECS audit treats every non-terminal lastStatus as live regardless of desiredStatus", () => {
  const currentDefinition = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:51";
  const protectedDefinition = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:50";
  const liveTaskArn = "arn:aws:ecs:eu-west-2:368992683803:task/live/cccccccccccccccccccccccccccccccc";
  const taskArn = "arn:aws:ecs:eu-west-2:368992683803:task/matrix/dddddddddddddddddddddddddddddddd";
  const definition = (arn, references = []) => ({ taskDefinition: { taskDefinitionArn: arn, containerDefinitions: [{ name: "backend", secrets: [[legacyBaseline.jwtCurrent, legacyBaseline.qrPrivateCurrent, legacyBaseline.qrPublicCurrent], ...references].flat().map((valueFrom, index) => ({ name: ["JWT_SECRET", "QR_SIGN_PRIVATE_KEY", "QR_SIGN_PUBLIC_KEY", "JWT_PENDING"][index], valueFrom })), environment: [{ name: "QR_SIGN_ACTIVE_KEY_VERSION", value: "legacy-v1" }] }] } });
  const audit = (desiredStatus, lastStatus) => auditLiveProductionDualSlotReferences({ resources, run: (args) => {
    if (args[1] === "describe-services") return JSON.stringify({ services: [{ serviceArn: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr", taskDefinition: currentDefinition, desiredCount: 1, runningCount: 1, pendingCount: 0, deployments: [{ id: "primary", status: "PRIMARY", taskDefinition: currentDefinition }], deploymentController: { type: "ECS" } }] });
    if (args[1] === "list-tasks") return JSON.stringify({ taskArns: [taskArn, liveTaskArn] });
    if (args[1] === "describe-tasks") return JSON.stringify({ tasks: [{ taskArn, taskDefinitionArn: protectedDefinition, desiredStatus, lastStatus }, { taskArn: liveTaskArn, taskDefinitionArn: currentDefinition, desiredStatus: "RUNNING", lastStatus: "RUNNING" }] });
    if (args[1] === "describe-task-definition") return JSON.stringify(args[args.indexOf("--task-definition") + 1] === protectedDefinition ? definition(protectedDefinition, [[resources.jwtPending]]) : definition(currentDefinition));
    throw new Error(`unexpected ${args.join(" ")}`);
  } });
  for (const [desiredStatus, lastStatus] of [["RUNNING", "RUNNING"], ["RUNNING", "PENDING"], ["STOPPED", "RUNNING"], ["STOPPED", "DEACTIVATING"]]) assert.equal(audit(desiredStatus, lastStatus).status, "FAIL");
  assert.equal(audit("STOPPED", "STOPPED").status, "PASS");
});

test("ECS audit rejects mixed live legacy baselines hidden by service.taskDefinition", () => {
  const currentDefinition = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:61";
  const drainingDefinition = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:60";
  const currentTask = "arn:aws:ecs:eu-west-2:368992683803:task/current/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
  const drainingTask = "arn:aws:ecs:eu-west-2:368992683803:task/draining/ffffffffffffffffffffffffffffffff";
  const definition = (arn, baseline) => ({ taskDefinition: { taskDefinitionArn: arn, containerDefinitions: [{ name: "backend", secrets: [{ name: "JWT_SECRET", valueFrom: baseline.jwtCurrent }, { name: "QR_SIGN_PRIVATE_KEY", valueFrom: baseline.qrPrivateCurrent }, { name: "QR_SIGN_PUBLIC_KEY", valueFrom: baseline.qrPublicCurrent }], environment: [{ name: "QR_SIGN_ACTIVE_KEY_VERSION", value: baseline.qrCurrentVersion }] }] } });
  const baselineA = legacyBaseline;
  const baselineB = { jwtCurrent: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:jwt-b", qrPrivateCurrent: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:qr-private-b", qrPublicCurrent: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:qr-public-b", qrCurrentVersion: "legacy-b" };
  const run = (args) => {
    if (args[1] === "describe-services") return JSON.stringify({ services: [{ serviceArn: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr", taskDefinition: currentDefinition, desiredCount: 2, runningCount: 1, pendingCount: 0, deployments: [{ id: "primary", status: "PRIMARY", taskDefinition: currentDefinition }, { id: "rollback", status: "ACTIVE", taskDefinition: drainingDefinition }], deploymentController: { type: "ECS" } }] });
    if (args[1] === "list-tasks") return JSON.stringify({ taskArns: args[args.indexOf("--desired-status") + 1] === "STOPPED" ? [drainingTask] : [currentTask] });
    if (args[1] === "describe-tasks") return JSON.stringify({ tasks: [{ taskArn: currentTask, taskDefinitionArn: currentDefinition, desiredStatus: "RUNNING", lastStatus: "RUNNING" }, { taskArn: drainingTask, taskDefinitionArn: drainingDefinition, desiredStatus: "STOPPED", lastStatus: "RUNNING" }] });
    if (args[1] === "describe-task-definition") return JSON.stringify(args[args.indexOf("--task-definition") + 1] === currentDefinition ? definition(currentDefinition, baselineA) : definition(drainingDefinition, baselineB));
    throw new Error(`unexpected ${args.join(" ")}`);
  };
  const result = auditLiveProductionDualSlotReferences({ run, resources });
  assert.equal(result.status, "FAIL");
  assert.equal(result.legacyRuntimeAuthoritative, false);
  assert.equal(result.liveLegacyBaselineCount, 2);
  assert.deepEqual(result.stableEvidence.deploymentTaskDefinitionCoverage.map(({ taskDefinitionArn, representedByLiveServiceTask }) => ({ taskDefinitionArn, representedByLiveServiceTask })), [{ taskDefinitionArn: currentDefinition, representedByLiveServiceTask: true }, { taskDefinitionArn: drainingDefinition, representedByLiveServiceTask: true }]);
});

test("ECS audit requires one canonical legacy baseline across every live service definition", () => {
  const currentDefinition = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:61";
  const replacementDefinition = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:62";
  const currentTask = "arn:aws:ecs:eu-west-2:368992683803:task/current/11111111111111111111111111111111";
  const replacementTask = "arn:aws:ecs:eu-west-2:368992683803:task/replacement/22222222222222222222222222222222";
  const definition = (arn, baseline) => ({ taskDefinition: { taskDefinitionArn: arn, containerDefinitions: [{ name: "backend", secrets: [{ name: "JWT_SECRET", valueFrom: baseline.jwtCurrent }, { name: "QR_SIGN_PRIVATE_KEY", valueFrom: baseline.qrPrivateCurrent }, { name: "QR_SIGN_PUBLIC_KEY", valueFrom: baseline.qrPublicCurrent }], environment: [{ name: "QR_SIGN_ACTIVE_KEY_VERSION", value: baseline.qrCurrentVersion }] }] } });
  const auditFor = (replacementBaseline) => auditLiveProductionDualSlotReferences({ resources, run: (args) => {
    if (args[1] === "describe-services") return JSON.stringify({ services: [{ serviceArn: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr", taskDefinition: currentDefinition, desiredCount: 2, runningCount: 2, pendingCount: 0, deployments: [{ id: "primary", status: "PRIMARY", taskDefinition: currentDefinition }, { id: "active", status: "ACTIVE", taskDefinition: replacementDefinition }], deploymentController: { type: "ECS" } }] });
    if (args[1] === "list-tasks") return JSON.stringify({ taskArns: [currentTask, replacementTask] });
    if (args[1] === "describe-tasks") return JSON.stringify({ tasks: [{ taskArn: currentTask, taskDefinitionArn: currentDefinition, desiredStatus: "RUNNING", lastStatus: "RUNNING" }, { taskArn: replacementTask, taskDefinitionArn: replacementDefinition, desiredStatus: "STOPPED", lastStatus: "RUNNING" }] });
    if (args[1] === "describe-task-definition") return JSON.stringify(args[args.indexOf("--task-definition") + 1] === currentDefinition ? definition(currentDefinition, legacyBaseline) : definition(replacementDefinition, replacementBaseline));
    throw new Error(`unexpected ${args.join(" ")}`);
  } });
  const same = auditFor(legacyBaseline);
  assert.equal(same.status, "PASS");
  assert.equal(same.liveLegacyBaselineCount, 1);
  assert.deepEqual(same.legacy, legacyBaseline);
  for (const field of ["jwtCurrent", "qrPrivateCurrent", "qrPublicCurrent", "qrCurrentVersion"]) {
    const changed = { ...legacyBaseline, [field]: `${legacyBaseline[field]}-different` };
    const result = auditFor(changed);
    assert.equal(result.status, "FAIL", field);
    assert.equal(result.legacyRuntimeAuthoritative, false, field);
    assert.equal(result.liveLegacyBaselineCount, 2, field);
  }
});

test("ECS audit fails closed when no live service baseline can be authenticated", () => {
  const stoppedTaskArn = "arn:aws:ecs:eu-west-2:368992683803:task/stopped/33333333333333333333333333333333";
  const taskDefinition = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:61";
  const definition = { taskDefinition: { taskDefinitionArn: taskDefinition, containerDefinitions: [{ name: "backend", secrets: [legacyBaseline.jwtCurrent, legacyBaseline.qrPrivateCurrent, legacyBaseline.qrPublicCurrent].map((valueFrom, index) => ({ name: ["JWT_SECRET", "QR_SIGN_PRIVATE_KEY", "QR_SIGN_PUBLIC_KEY"][index], valueFrom })), environment: [{ name: "QR_SIGN_ACTIVE_KEY_VERSION", value: "legacy-v1" }] }] } };
  const result = auditLiveProductionDualSlotReferences({ resources, run: (args) => {
    if (args[1] === "describe-services") return JSON.stringify({ services: [{ serviceArn: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr", taskDefinition, desiredCount: 0, runningCount: 0, pendingCount: 0, deployments: [{ id: "primary", status: "PRIMARY", taskDefinition }], deploymentController: { type: "ECS" } }] });
    if (args[1] === "list-tasks") return JSON.stringify({ taskArns: args[args.indexOf("--desired-status") + 1] === "STOPPED" ? [stoppedTaskArn] : [] });
    if (args[1] === "describe-tasks") return JSON.stringify({ tasks: [{ taskArn: stoppedTaskArn, taskDefinitionArn: taskDefinition, desiredStatus: "STOPPED", lastStatus: "STOPPED" }] });
    if (args[1] === "describe-task-definition") return JSON.stringify(definition);
    throw new Error(`unexpected ${args.join(" ")}`);
  } });
  assert.equal(result.status, "FAIL");
  assert.equal(result.liveLegacyBaselineCount, 0);
  assert.equal(result.legacyRuntimeAuthoritative, false);
});

test("ECS audit distinguishes harmless task replacement from a safe-but-reauthorization-worthy definition change", () => {
  const td50 = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:50"; const td51 = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:51";
  const legacy = [legacyBaseline.jwtCurrent, legacyBaseline.qrPrivateCurrent, legacyBaseline.qrPublicCurrent];
  const definition = (arn) => ({ taskDefinition: { taskDefinitionArn: arn, containerDefinitions: [{ name: "backend", secrets: legacy.map((valueFrom, index) => ({ name: ["JWT_SECRET", "QR_SIGN_PRIVATE_KEY", "QR_SIGN_PUBLIC_KEY"][index], valueFrom })), environment: [{ name: "QR_SIGN_ACTIVE_KEY_VERSION", value: "legacy-v1" }] }] } });
  const run = (taskArn, taskDefinition) => (args) => {
    if (args[1] === "describe-services") return JSON.stringify({ services: [{ serviceArn: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr", taskDefinition, desiredCount: 2, runningCount: 2, pendingCount: 0, deployments: [{ id: "primary", status: "PRIMARY", taskDefinition }], deploymentController: { type: "ECS" } }] });
    if (args[1] === "list-tasks") return JSON.stringify({ taskArns: args.includes("RUNNING") ? [taskArn] : [] });
    if (args[1] === "describe-tasks") return JSON.stringify({ tasks: [{ taskArn, taskDefinitionArn: taskDefinition, lastStatus: "RUNNING", desiredStatus: "RUNNING" }] });
    if (args[1] === "describe-task-definition") return JSON.stringify(definition(args[args.indexOf("--task-definition") + 1]));
    throw new Error(`unexpected ${args.join(" ")}`);
  };
  const first = auditLiveProductionDualSlotReferences({ run: run("arn:aws:ecs:eu-west-2:368992683803:task/old", td50), resources });
  const replacement = auditLiveProductionDualSlotReferences({ run: run("arn:aws:ecs:eu-west-2:368992683803:task/new", td50), resources });
  const changedDefinition = auditLiveProductionDualSlotReferences({ run: run("arn:aws:ecs:eu-west-2:368992683803:task/newer", td51), resources });
  assert.equal(first.status, "PASS"); assert.notEqual(first.auditSha256, replacement.auditSha256); assert.equal(first.stableAuditSha256, replacement.stableAuditSha256);
  assert.equal(changedDefinition.status, "PASS"); assert.notEqual(first.stableAuditSha256, changedDefinition.stableAuditSha256);
});

test("ECS audit fails closed when a listed task cannot be tied to an inspected definition", () => {
  const run = (args) => {
    if (args[1] === "describe-services") return JSON.stringify({ services: [{ serviceArn: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr", taskDefinition: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:50", deployments: [], deploymentController: { type: "ECS" } }] });
    if (args[1] === "list-tasks") return JSON.stringify({ taskArns: args.includes("RUNNING") ? ["arn:aws:ecs:eu-west-2:368992683803:task/uninspectable"] : [] });
    if (args[1] === "describe-tasks") return JSON.stringify({ tasks: [{ taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/uninspectable" }] });
    throw new Error(`unexpected ${args.join(" ")}`);
  };
  assert.throws(() => auditLiveProductionDualSlotReferences({ run, resources }), /inventory is incomplete/i);
});

test("protected checkout rejects tracked, staged, untracked, and substituted source state", () => {
  const fixture = (status = "", head = sourceSha, remote = sourceSha) => (args) => { if (args[0] === "fetch" || args[0] === "merge-base") return ""; if (args[0] === "rev-parse" && args[1] === "FETCH_HEAD") return remote; if (args[0] === "rev-parse" && args[1] === "HEAD") return head; if (args[0] === "rev-parse" && args[1] === "--is-shallow-repository") return "false"; if (args[0] === "rev-parse" && args[1] === "--git-path") return ".git/NOPE"; if (args[0] === "symbolic-ref") return "refs/remotes/origin/main"; if (args[0] === "status") return status; throw new Error(`unexpected git ${args.join(" ")}`); };
  assert.doesNotThrow(() => readAuthenticatedRebaselineCheckout({ sourceSha, gitRun: fixture(), repositoryRoot: process.cwd() })); for (const status of [" M scripts/a.mjs", "M  scripts/a.mjs", "?? node_modules/evil.mjs"]) assert.throws(() => readAuthenticatedRebaselineCheckout({ sourceSha, gitRun: fixture(status), repositoryRoot: process.cwd() }), /modification|untracked/); assert.throws(() => readAuthenticatedRebaselineCheckout({ sourceSha, gitRun: fixture("", "b".repeat(40)), repositoryRoot: process.cwd() }), /requested|match/);
});

test("the rebaseline boundary has no unrelated mutation escape hatch", () => { const contract = readFileSync(new URL("../aws/production-dual-slot-rebaseline-contract.mjs", import.meta.url), "utf8"); const executor = readFileSync(new URL("../aws/rebaseline-production-dual-slot.mjs", import.meta.url), "utf8"); assert.equal(/new\s+(DeleteSecret|UpdateSecret|RegisterTaskDefinition|PutResourcePolicy)Command|\["ecs",\s*"(update-service|register-task-definition)"\]/i.test(contract), false); assert.equal(/new\s+(DeleteSecret|UpdateSecret|RegisterTaskDefinition|PutResourcePolicy)Command|\["ecs",\s*"(update-service|register-task-definition)"\]/i.test(executor), false); assert.equal(executor.includes("PutSecretValueCommand"), true); });

test("production entrypoints pin the private historical topology digest", () => {
  const executor = readFileSync(new URL("../aws/rebaseline-production-dual-slot.mjs", import.meta.url), "utf8");
  const runtime = readFileSync(new URL("../aws/prepare-production-cutover-runtime.mjs", import.meta.url), "utf8");
  assert.match(executor, /historical topology is not the protected-source abandoned identity/);
  assert.match(runtime, /historicalTopologySha256 !== REBASELINE_ABANDONED_HISTORICAL_TOPOLOGY_SHA256/);
  assert.equal(/arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr\/prod\/rotation/.test(readFileSync(new URL("../aws/production-dual-slot-rebaseline-contract.mjs", import.meta.url), "utf8")), false);
});
