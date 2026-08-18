#!/usr/bin/env node
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  TEMPORARY_KMS_CAPABILITY,
  assertRootDropOwnershipEvidence,
  assertSteadyStateReleasePolicy,
  assertTemporaryCapabilityEvidence,
  assertTemporaryCapabilityTransition,
  assertTemporaryReleasePolicy,
  assertStageARootDropCreationPlan,
  assertManagedPolicyDocumentSize,
  buildRootDropOwnershipEvidence,
  buildTemporaryCapabilityEvidence,
  buildTemporaryReleasePolicy,
  isTemporaryTagResourceStatement,
} from "./production-stage-a-temporary-kms-capability.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { ensureStageBPrivateFile, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { assertStageAStateIdentityBinding, buildStageAStateIdentity } from "./generate-production-green-stage-a-prerequisites.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sourcePolicyPath = path.join(root, TEMPORARY_KMS_CAPABILITY.sourcePolicyPath);
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const VERSION = /^v[1-9][0-9]*$/;
export const AWS_MANAGED_POLICY_VERSION_LIMIT = 5;
export const AWS_POLICY_VERSION_CREATE_HEADROOM = AWS_MANAGED_POLICY_VERSION_LIMIT - 1;
export const TEMPORARY_KMS_POLICY_VERSION_CLASSES = Object.freeze([
  "CURRENT_DEFAULT_STEADY_STATE",
  "CURRENT_ACTIVE_TEMPORARY",
  "RECOGNIZED_STALE_STEADY_STATE",
  "RECOGNIZED_STALE_TEMPORARY",
  "UNKNOWN",
  "AMBIGUOUS",
]);
// AWS permits five managed-policy versions; one authenticated non-default slot must be free before each create.
const canonical = (value) => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const fail = (message) => { throw new Error(`Temporary Stage-A KMS capability: ${message}`); };

const policyDocumentFingerprint = (document) => sha256(canonical(document));
const validCreateDate = (value) => typeof value === "string" && Number.isFinite(Date.parse(value));

export function classifyTemporaryKmsPolicyVersion(version, { steadyStatePolicy, sourceSha, transitionId } = {}) {
  if (!version || typeof version !== "object" || !VERSION.test(version.VersionId || "") || typeof version.IsDefaultVersion !== "boolean" || !version.document) return "UNKNOWN";
  const temporary = version.document.Statement?.some(isTemporaryTagResourceStatement) === true;
  const expectedTemporary = temporary && SHA40.test(sourceSha || "") && /^[A-Za-z0-9._-]{8,128}$/.test(transitionId || "")
    ? (() => { try { assertTemporaryReleasePolicy(version.document, { steadyStatePolicy, sourceSha, transitionId }); return true; } catch { return false; } })()
    : false;
  if (version.IsDefaultVersion) {
    if (temporary) return expectedTemporary ? "CURRENT_ACTIVE_TEMPORARY" : "AMBIGUOUS";
    return canonical(version.document) === canonical(steadyStatePolicy) ? "CURRENT_DEFAULT_STEADY_STATE" : "UNKNOWN";
  }
  if (temporary) return expectedTemporary ? "RECOGNIZED_STALE_TEMPORARY" : "UNKNOWN";
  if (canonical(version.document) === canonical(steadyStatePolicy)) return "RECOGNIZED_STALE_STEADY_STATE";
  return "UNKNOWN";
}

export function selectTemporaryKmsPolicyCapacityCandidate(versions, classifications = new Map()) {
  const eligible = versions.filter((version) => classifications.get(version.VersionId) === "RECOGNIZED_STALE_STEADY_STATE");
  if (!eligible.length) fail("no authenticated stale policy version is available for capacity cleanup");
  if (eligible.some((version) => !validCreateDate(version.CreateDate))) fail("safe policy-version cleanup requires authoritative CreateDate metadata");
  eligible.sort((left, right) => Date.parse(left.CreateDate) - Date.parse(right.CreateDate) || left.VersionId.localeCompare(right.VersionId));
  const candidate = eligible[0];
  if (candidate.IsDefaultVersion) fail("capacity cleanup selected the default policy version");
  return candidate;
}

const versionTopologyFingerprint = ({ policy, versions }) => canonical({
  defaultVersionId: policy.DefaultVersionId,
  versions: versions.map(({ VersionId, IsDefaultVersion, CreateDate, document }) => ({ VersionId, IsDefaultVersion, CreateDate: CreateDate || null, documentSha256: policyDocumentFingerprint(document) })).sort((left, right) => left.VersionId.localeCompare(right.VersionId)),
});

const assertSameVersion = (before, after, versionId) => {
  const left = before.versions.find((version) => version.VersionId === versionId);
  const right = after.versions.find((version) => version.VersionId === versionId);
  if (!left || !right || canonical({ VersionId: left.VersionId, CreateDate: left.CreateDate || null, documentSha256: policyDocumentFingerprint(left.document) }) !== canonical({ VersionId: right.VersionId, CreateDate: right.CreateDate || null, documentSha256: policyDocumentFingerprint(right.document) })) fail(`policy version ${versionId} changed during the capacity transition`);
};

function attachMutationAccounting(error, mutationAccounting, details = {}) {
  Object.assign(error, { mutationAccounting: { ...mutationAccounting }, capacityRecovery: details });
  return error;
}

function assertIdentity({ sourceSha, transitionId } = {}) {
  if (!SHA40.test(sourceSha || "") || !/^[A-Za-z0-9._-]{8,128}$/.test(transitionId || "")) fail("source SHA and transition ID are required");
}

function readJson(filePath) { return JSON.parse(readFileSync(filePath, "utf8")); }

function writeEvidence(filePath, value, repositoryRoot = root) {
  return writeStageBPrivateFileAtomic({ filePath, bytes: Buffer.from(`${JSON.stringify(value, null, 2)}\n`), repositoryRoot, overwrite: true, label: "Temporary Stage-A KMS capability evidence" });
}

export function createTemporaryKmsCapabilityRunner({ run, sourcePolicy = readJson(sourcePolicyPath), now = () => new Date().toISOString(), writeEvidence: writeEvidenceFn = writeEvidence, requireStageAStateBinding = false } = {}) {
  if (typeof run !== "function") throw new Error("An explicit AWS command runner is required.");
  const readVersions = ({ allowTemporaryVersionId, sourceSha, transitionId } = {}) => {
    const policy = JSON.parse(run(["iam", "get-policy", "--policy-arn", TEMPORARY_KMS_CAPABILITY.policyArn]));
    const rawVersions = JSON.parse(run(["iam", "list-policy-versions", "--policy-arn", TEMPORARY_KMS_CAPABILITY.policyArn])).Versions || [];
    if (!Array.isArray(rawVersions) || rawVersions.length === 0 || rawVersions.length > AWS_MANAGED_POLICY_VERSION_LIMIT) fail("managed-policy version topology is outside AWS limits");
    if (rawVersions.some(({ VersionId }) => !VERSION.test(VersionId || "")) || new Set(rawVersions.map(({ VersionId }) => VersionId)).size !== rawVersions.length) fail("managed-policy version topology contains an invalid or duplicate version identity");
    const documents = rawVersions.map((version) => ({
      ...version,
      IsDefaultVersion: typeof version.IsDefaultVersion === "boolean" ? version.IsDefaultVersion : version.VersionId === policy.Policy?.DefaultVersionId,
      document: normalizeIamPolicyDocument(JSON.parse(run(["iam", "get-policy-version", "--policy-arn", TEMPORARY_KMS_CAPABILITY.policyArn, "--version-id", version.VersionId])).PolicyVersion?.Document, "IAM policy version document"),
    }));
    if (documents.filter(({ IsDefaultVersion }) => IsDefaultVersion).length !== 1 || documents.filter(({ IsDefaultVersion }) => IsDefaultVersion)[0]?.VersionId !== policy.Policy?.DefaultVersionId) fail("managed-policy default-version topology is ambiguous");
    const classifications = new Map(documents.map((version) => [version.VersionId, classifyTemporaryKmsPolicyVersion(version, { steadyStatePolicy: sourcePolicy, sourceSha, transitionId })]));
    if ([...classifications.values()].some((classification) => classification === "UNKNOWN" || classification === "AMBIGUOUS")) fail("managed-policy version topology contains an unknown or ambiguous version");
    const active = documents.find(({ VersionId }) => VersionId === policy.Policy?.DefaultVersionId);
    if (!active || !VERSION.test(active.VersionId)) fail("default managed-policy version is unreadable");
    const temporary = documents.filter(({ document }) => document.Statement?.some(isTemporaryTagResourceStatement));
    if (temporary.some(({ VersionId }) => VersionId !== active.VersionId && VersionId !== allowTemporaryVersionId)) fail("non-default temporary policy version creates an unknown topology");
    return { policy: policy.Policy, versions: documents, active, classifications };
  };
  const recordMutation = (accounting, action, outcome) => {
    accounting.mutationOutcomes.push({ action, outcome });
    if (outcome === "OUTCOME_UNKNOWN") accounting.unknownMutations += 1;
    if (["CONFIRMED_SUCCESS", "CONFIRMED_SUCCESS_READBACK"].includes(outcome)) accounting.iamWrites += 1;
  };
  const writePolicyVersion = (document, { accounting, expectedState, readState, allowTemporaryVersionId } = {}) => {
    assertManagedPolicyDocumentSize(document);
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temporary-kms-policy-"));
    const temporaryPath = path.join(directory, "policy.json");
    const bytes = Buffer.from(JSON.stringify(document));
    writeFileSync(temporaryPath, bytes, { mode: 0o600, flag: "wx" });
    try {
      if (expectedState && readState) {
        const beforeCreate = readState({ allowTemporaryVersionId });
        if (versionTopologyFingerprint(beforeCreate) !== versionTopologyFingerprint(expectedState)) fail("managed-policy topology changed before policy-version creation");
      }
      accounting.iamWriteAttempts += 1;
      try {
        const result = JSON.parse(run(["iam", "create-policy-version", "--policy-arn", TEMPORARY_KMS_CAPABILITY.policyArn, "--policy-document", `file://${temporaryPath}`, "--set-as-default"]));
        const version = result.PolicyVersion;
        if (!version || !VERSION.test(version.VersionId || "")) fail("CreatePolicyVersion returned an invalid version identity");
        accounting.policyVersionCreations += 1;
        accounting.policyDefaultChanges += 1;
        recordMutation(accounting, "CreatePolicyVersion", "CONFIRMED_SUCCESS");
        return version;
      } catch (error) {
        if (!error.mutationOutcome) {
          try {
            const recovered = readState?.({ allowTemporaryVersionId });
            const active = recovered?.active;
            if (active && VERSION.test(active.VersionId || "") && recovered.policy?.DefaultVersionId === active.VersionId && canonical(active.document) === canonical(document)) {
              recordMutation(accounting, "CreatePolicyVersion", "CONFIRMED_SUCCESS_READBACK");
              accounting.policyVersionCreations += 1;
              accounting.policyDefaultChanges += 1;
              return active;
            }
            error.mutationOutcome = "OUTCOME_UNKNOWN";
          } catch { error.mutationOutcome = "OUTCOME_UNKNOWN"; }
        }
        if (error.mutationOutcome === "OUTCOME_UNKNOWN") recordMutation(accounting, "CreatePolicyVersion", "OUTCOME_UNKNOWN");
        throw attachMutationAccounting(error, accounting);
      }
    } finally {
      unlinkSync(temporaryPath);
      rmdirSync(directory);
    }
  };
  const deletePolicyVersion = (versionId, accounting, readState, allowTemporaryVersionId) => {
    if (!VERSION.test(versionId || "")) fail("policy-version deletion identity is malformed");
    accounting.iamWriteAttempts += 1;
    try {
      run(["iam", "delete-policy-version", "--policy-arn", TEMPORARY_KMS_CAPABILITY.policyArn, "--version-id", versionId]);
      accounting.policyVersionDeletions += 1;
      recordMutation(accounting, "DeletePolicyVersion", "CONFIRMED_SUCCESS");
    } catch (error) {
      try {
        const recovered = readState?.({ allowTemporaryVersionId });
        if (recovered && !recovered.versions.some(({ VersionId }) => VersionId === versionId)) {
          accounting.policyVersionDeletions += 1;
          recordMutation(accounting, "DeletePolicyVersion", "CONFIRMED_SUCCESS_READBACK");
          return;
        }
        error.mutationOutcome = "ATTEMPTED_REJECTED";
      } catch { error.mutationOutcome = "OUTCOME_UNKNOWN"; }
      recordMutation(accounting, "DeletePolicyVersion", error.mutationOutcome === "OUTCOME_UNKNOWN" ? "OUTCOME_UNKNOWN" : "ATTEMPTED_REJECTED");
      throw attachMutationAccounting(error, accounting, { deletedVersionIds: [] });
    }
  };
  const ensurePolicyVersionCapacity = ({ current, readState, allowTemporaryVersionId, accounting } = {}) => {
    if (current.versions.length <= AWS_POLICY_VERSION_CREATE_HEADROOM) return current;
    if (current.versions.length !== AWS_MANAGED_POLICY_VERSION_LIMIT) fail("managed-policy version capacity is outside the authenticated AWS limit");
    const candidate = selectTemporaryKmsPolicyCapacityCandidate(current.versions, current.classifications);
    if (!validCreateDate(candidate.CreateDate)) fail("safe policy-version cleanup requires authoritative CreateDate metadata");
    const beforeCleanup = readState({ allowTemporaryVersionId });
    if (versionTopologyFingerprint(beforeCleanup) !== versionTopologyFingerprint(current)) fail("managed-policy topology changed before capacity cleanup");
    const freshCandidate = selectTemporaryKmsPolicyCapacityCandidate(beforeCleanup.versions, beforeCleanup.classifications);
    if (freshCandidate.VersionId !== candidate.VersionId || freshCandidate.IsDefaultVersion) fail("managed-policy cleanup candidate changed before deletion");
    try {
      deletePolicyVersion(freshCandidate.VersionId, accounting, readState);
    } catch (error) {
      throw attachMutationAccounting(error, accounting, { deletedVersionIds: [] });
    }
    try {
      const afterCleanup = readState({ allowTemporaryVersionId });
      if (afterCleanup.versions.length !== beforeCleanup.versions.length - 1 || afterCleanup.versions.some(({ VersionId }) => VersionId === freshCandidate.VersionId) || afterCleanup.policy.DefaultVersionId !== beforeCleanup.policy.DefaultVersionId) {
        throw new Error("managed-policy topology changed after capacity cleanup");
      }
      for (const version of beforeCleanup.versions) if (version.VersionId !== freshCandidate.VersionId) assertSameVersion(beforeCleanup, afterCleanup, version.VersionId);
      if (afterCleanup.versions.length >= AWS_MANAGED_POLICY_VERSION_LIMIT) throw new Error("managed-policy capacity was not freed");
      return { ...afterCleanup, capacityDeletedVersionId: freshCandidate.VersionId };
    } catch (error) {
      throw attachMutationAccounting(error, accounting, { deletedVersionIds: [freshCandidate.VersionId] });
    }
  };
  const assertSource = (active) => {
    assertSteadyStateReleasePolicy(sourcePolicy);
    if (active.document.Statement?.some(isTemporaryTagResourceStatement)) return;
    if (canonical(active.document) !== canonical(sourcePolicy)) fail("live steady-state policy differs from protected source");
  };
  const runPhase = ({ phase, sourceSha, transitionId, stateFile, planSha256, planJsonFile, terraformStateFile, stageAStateFile, stageAStateIdentity, applyFailed = false, partialOperationCensus = false } = {}) => {
    assertIdentity({ sourceSha, transitionId });
    const accounting = { iamWriteAttempts: 0, iamWrites: 0, policyVersionDeletions: 0, policyVersionCreations: 0, policyDefaultChanges: 0, unknownMutations: 0, mutationOutcomes: [] };
    const persistEvidence = (filePath, value) => writeEvidenceFn(filePath, value);
    if (phase === "authorize" && requireStageAStateBinding) {
      if (!stageAStateFile || !stageAStateIdentity || !existsSync(stageAStateFile)) fail("authenticated Stage A state identity is required before temporary capability authorization");
      const stateBytes = readFileSync(stageAStateFile);
      const currentIdentity = buildStageAStateIdentity(JSON.parse(stateBytes), { stateBytes });
      assertStageAStateIdentityBinding(currentIdentity, stageAStateIdentity);
    }
    const previousFile = existsSync(stateFile) ? ensureStageBPrivateFile({ filePath: stateFile, repositoryRoot: root, label: "Temporary Stage-A KMS capability evidence" }).path : null;
    let previous = previousFile ? readJson(previousFile) : null;
    let state = previous?.state || "ABSENT";
    const readState = ({ allowTemporaryVersionId } = {}) => readVersions({ allowTemporaryVersionId, sourceSha, transitionId });
    const current = readState({ allowTemporaryVersionId: previous?.temporaryVersionId });
    const activeTemporary = current.active.document.Statement?.some(isTemporaryTagResourceStatement);
    if (!previous && phase === "abort" && activeTemporary) {
      if (!applyFailed || !partialOperationCensus || !SHA256.test(planSha256 || "") || !planJsonFile) fail("authenticated recovery inputs are required for an unrecorded temporary capability");
      const planFile = ensureStageBPrivateFile({ filePath: planJsonFile, repositoryRoot: root, label: "Classified Stage-A plan JSON" });
      assertStageARootDropCreationPlan(readJson(planFile.path));
      assertTemporaryReleasePolicy(current.active.document, { steadyStatePolicy: sourcePolicy, sourceSha, transitionId });
      previous = buildTemporaryCapabilityEvidence({ state: "AUTHORIZED_FOR_ROOT_DROP_CREATION", sourceSha, transitionId, planSha256, defaultVersionId: current.active.VersionId, temporaryVersionId: current.active.VersionId, observedAt: now() });
      persistEvidence(stateFile, previous);
      state = previous.state;
    }
    if (phase === "abort") {
      if (!applyFailed || !partialOperationCensus || !SHA256.test(planSha256 || "") || !planJsonFile || !existsSync(planJsonFile) || !["AUTHORIZED_FOR_ROOT_DROP_CREATION", "STAGE_A_APPLY"].includes(state)) fail("apply failure, authenticated partial-operation census, and exact Stage-A plan bindings are required");
      const planFile = ensureStageBPrivateFile({ filePath: planJsonFile, repositoryRoot: root, label: "Classified Stage-A plan JSON" });
      assertStageARootDropCreationPlan(readJson(planFile.path));
      if (previous && (previous.transitionId !== transitionId || previous.planSha256 !== planSha256)) fail("abort recovery belongs to a different transition or plan");
      const persistedTemporary = current.versions.find(({ VersionId }) => VersionId === previous?.temporaryVersionId);
      const completedAbort = previous && !activeTemporary && !persistedTemporary && current.active.VersionId !== previous.temporaryVersionId && !current.versions.some(({ document }) => document.Statement?.some(isTemporaryTagResourceStatement));
      if (completedAbort) {
        assertTemporaryCapabilityEvidence(previous, { sourceSha, state });
        assertSource(current.active);
        const evidence = buildTemporaryCapabilityEvidence({ ...previous, state: "REVOKED", temporaryVersionId: null, defaultVersionId: current.active.VersionId, ownership: null, observedAt: now() });
        assertTemporaryCapabilityEvidence(evidence, { sourceSha, state: "REVOKED" });
        assertTemporaryCapabilityTransition(state, evidence.state, { sourceSha });
        persistEvidence(stateFile, evidence);
        return { evidence, writes: 0, recovery: "AUTHENTICATED_ABORT_ALREADY_REVOKED", mutationAccounting: accounting };
      }
    }
    if (previous && ["AUTHORIZED_FOR_ROOT_DROP_CREATION", "STAGE_A_APPLY", "ROOT_DROP_OWNERSHIP_VERIFIED"].includes(state)) {
      const persistedTemporary = current.versions.find(({ VersionId }) => VersionId === previous.temporaryVersionId);
      const alreadySteadyAfterWrite = ["abort", "revoke"].includes(phase) && !activeTemporary && persistedTemporary?.document.Statement?.some(isTemporaryTagResourceStatement);
      const authenticatedAlreadyRevoked = state === "ROOT_DROP_OWNERSHIP_VERIFIED" && phase === "revoke" && !activeTemporary && !persistedTemporary && current.active.VersionId !== previous.temporaryVersionId;
      if (authenticatedAlreadyRevoked) {
        assertTemporaryCapabilityEvidence(previous, { sourceSha, state });
        if (previous.transitionId !== transitionId || !SHA256.test(previous.planSha256 || "")) fail("already-revoked recovery identity is incomplete");
        assertSource(current.active);
        const evidence = buildTemporaryCapabilityEvidence({ ...previous, state: "REVOKED", temporaryVersionId: null, defaultVersionId: current.active.VersionId, observedAt: now() });
        assertTemporaryCapabilityEvidence(evidence, { sourceSha, state: "REVOKED" });
        assertTemporaryCapabilityTransition(state, evidence.state, { sourceSha });
        persistEvidence(stateFile, evidence);
        return { evidence, writes: 0, recovery: "AUTHENTICATED_ALREADY_REVOKED", mutationAccounting: accounting };
      }
      if (!alreadySteadyAfterWrite && (!activeTemporary || current.active.VersionId !== previous.temporaryVersionId)) fail("authenticated temporary capability is not the live default version");
      assertTemporaryReleasePolicy((alreadySteadyAfterWrite ? persistedTemporary : current.active).document, { steadyStatePolicy: sourcePolicy, sourceSha, transitionId: previous.transitionId });
    }
    if (phase === "authorize") {
      if (state === "AUTHORIZED_FOR_ROOT_DROP_CREATION" && activeTemporary) {
        assertTemporaryCapabilityEvidence(previous, { sourceSha, state });
        if (requireStageAStateBinding) assertStageAStateIdentityBinding(previous.stageAStateIdentity, stageAStateIdentity);
        if (previous.transitionId !== transitionId || previous.temporaryVersionId !== current.active.VersionId || previous.planSha256 !== planSha256) fail("existing authorization belongs to a different transition or plan");
        if (!planJsonFile) fail("exact classified Stage-A plan JSON is required for replay");
        const planFile = ensureStageBPrivateFile({ filePath: planJsonFile, repositoryRoot: root, label: "Classified Stage-A plan JSON" });
        assertStageARootDropCreationPlan(readJson(planFile.path));
        return { evidence: previous, writes: 0, mutationAccounting: accounting };
      }
      if (state !== "ABSENT" || activeTemporary) fail("authorization state or live policy topology is not ALL_OLD");
      assertSource(current.active);
      if (!SHA256.test(planSha256 || "") || !planJsonFile) fail("exact classified Stage-A plan binding is required before authorization");
      const planFile = ensureStageBPrivateFile({ filePath: planJsonFile, repositoryRoot: root, label: "Classified Stage-A plan JSON" });
      assertStageARootDropCreationPlan(readJson(planFile.path));
      const temporaryDocument = buildTemporaryReleasePolicy(sourcePolicy, { sourceSha, transitionId });
      const capacityState = ensurePolicyVersionCapacity({ current, readState, allowTemporaryVersionId: previous?.temporaryVersionId, accounting });
      let version;
      let readback;
      try {
        version = writePolicyVersion(temporaryDocument, { accounting, expectedState: capacityState, readState });
        readback = readState({ allowTemporaryVersionId: version.VersionId });
        if (readback.versions.length !== capacityState.versions.length + 1) fail("temporary policy creation changed unexpected policy-version topology");
        for (const existing of capacityState.versions) assertSameVersion(capacityState, readback, existing.VersionId);
        const created = readback.versions.find(({ VersionId }) => VersionId === version.VersionId);
        if (!created || canonical(created.document) !== canonical(temporaryDocument) || readback.policy.DefaultVersionId !== version.VersionId) fail("temporary policy creation readback is not exact");
        if (!readback.active.document.Statement?.some(isTemporaryTagResourceStatement) || readback.active.VersionId !== version.VersionId) fail("temporary policy readback is not exact");
      } catch (error) {
        throw attachMutationAccounting(error, accounting, { deletedVersionIds: capacityState.capacityDeletedVersionId ? [capacityState.capacityDeletedVersionId] : [], createdVersionIds: version?.VersionId ? [version.VersionId] : [] });
      }
      const evidence = buildTemporaryCapabilityEvidence({ state: "AUTHORIZED_FOR_ROOT_DROP_CREATION", sourceSha, transitionId, planSha256, stageAStateIdentity, defaultVersionId: readback.active.VersionId, temporaryVersionId: readback.active.VersionId, observedAt: now() });
      assertTemporaryReleasePolicy(readback.active.document, { steadyStatePolicy: sourcePolicy, sourceSha, transitionId });
      persistEvidence(stateFile, evidence);
      return { evidence, writes: accounting.iamWrites, mutationAccounting: accounting };
    }
    if (!previous) fail("a prior capability evidence file is required");
    if (phase === "mark-stage-a-apply") {
      assertTemporaryCapabilityEvidence(previous, { sourceSha, state: "AUTHORIZED_FOR_ROOT_DROP_CREATION" });
      if (!SHA256.test(planSha256 || "")) fail("Stage-A plan SHA is required");
      const evidence = buildTemporaryCapabilityEvidence({ ...previous, state: "STAGE_A_APPLY", planSha256, observedAt: now() });
      assertTemporaryCapabilityTransition(previous.state, evidence.state, { sourceSha });
      persistEvidence(stateFile, evidence);
      return { evidence, writes: 0 };
    }
    if (phase === "mark-root-drop-owned") {
      assertTemporaryCapabilityEvidence(previous, { sourceSha, state: "STAGE_A_APPLY" });
      if (!terraformStateFile || !existsSync(terraformStateFile)) fail("fresh canonical Stage-A state is required");
      const ownership = buildRootDropOwnershipEvidence({ terraformState: readJson(terraformStateFile), sourceSha, transitionId, planSha256: previous.planSha256, observedAt: now() });
      assertRootDropOwnershipEvidence(ownership, { sourceSha, planSha256: previous.planSha256 });
      const evidence = buildTemporaryCapabilityEvidence({ ...previous, state: "ROOT_DROP_OWNERSHIP_VERIFIED", ownership, observedAt: now() });
      assertTemporaryCapabilityTransition(previous.state, evidence.state, { sourceSha });
      persistEvidence(stateFile, evidence);
      return { evidence, writes: 0 };
    }
    if (phase === "abort") {
      // Inputs and completed-abort recovery were validated before lifecycle replay.
    } else if (phase === "revoke") {
      if (state === "REVOKED") {
        assertTemporaryCapabilityEvidence(previous, { sourceSha, state });
        assertSource(current.active);
        if (current.versions.some(({ document }) => document.Statement?.some(isTemporaryTagResourceStatement))) fail("temporary capability version remains after revocation");
        return { evidence: previous, writes: 0, mutationAccounting: accounting };
      }
      if (state !== "ROOT_DROP_OWNERSHIP_VERIFIED") fail("root-drop Terraform ownership must be verified before revocation");
    } else if (phase === "verify-absent") {
      if (state === "ABSENCE_VERIFIED") {
        assertTemporaryCapabilityEvidence(previous, { sourceSha, state });
        assertSource(current.active);
        if (current.versions.some(({ document }) => document.Statement?.some(isTemporaryTagResourceStatement))) fail("temporary capability version remains after absence verification");
        return { evidence: previous, writes: 0 };
      }
      if (state !== "REVOKED") fail("revocation evidence is required before absence verification");
      assertSource(current.active);
      if (current.versions.some(({ document }) => document.Statement?.some(isTemporaryTagResourceStatement))) fail("temporary capability version remains present");
      const evidence = buildTemporaryCapabilityEvidence({ ...previous, state: "ABSENCE_VERIFIED", temporaryVersionId: null, defaultVersionId: current.active.VersionId, observedAt: now() });
      assertTemporaryCapabilityEvidence(evidence, { sourceSha, state: "ABSENCE_VERIFIED" });
      assertTemporaryCapabilityTransition(previous.state, evidence.state, { sourceSha, evidence });
      persistEvidence(stateFile, evidence);
      return { evidence, writes: 0 };
    } else fail(`unsupported phase ${phase}`);
    if (!["AUTHORIZED_FOR_ROOT_DROP_CREATION", "STAGE_A_APPLY", "ROOT_DROP_OWNERSHIP_VERIFIED"].includes(state)) fail("capability state is not revocable");
    const temporaryVersion = current.versions.find(({ VersionId }) => VersionId === previous.temporaryVersionId);
    if (!temporaryVersion || !temporaryVersion.document.Statement?.some(isTemporaryTagResourceStatement)) fail("authenticated temporary policy does not exist");
    if (!activeTemporary && !["abort", "revoke"].includes(phase)) fail("authenticated temporary policy is not the live default version");
    const capacityState = activeTemporary
      ? ensurePolicyVersionCapacity({ current, readState, allowTemporaryVersionId: previous.temporaryVersionId, accounting })
      : current;
    let steadyVersion = current.active;
    let afterDefault;
    try {
      if (activeTemporary) steadyVersion = writePolicyVersion(sourcePolicy, { accounting, expectedState: capacityState, readState, allowTemporaryVersionId: previous.temporaryVersionId });
      afterDefault = readState({ allowTemporaryVersionId: previous.temporaryVersionId });
    } catch (error) {
      throw attachMutationAccounting(error, accounting, { deletedVersionIds: capacityState.capacityDeletedVersionId ? [capacityState.capacityDeletedVersionId] : [], createdVersionIds: steadyVersion !== current.active ? [steadyVersion.VersionId] : [] });
    }
    const deletedForCapacity = capacityState.capacityDeletedVersionId ? [capacityState.capacityDeletedVersionId] : [];
    const createdForSteadyState = activeTemporary ? [steadyVersion.VersionId] : [];
    try {
      assertSource(afterDefault.active);
      if (afterDefault.active.VersionId !== steadyVersion.VersionId) fail("steady-state policy was not made default");
      if (activeTemporary) {
        if (afterDefault.versions.length !== capacityState.versions.length + 1) fail("steady-state policy creation changed unexpected policy-version topology");
        for (const existing of capacityState.versions) assertSameVersion(capacityState, afterDefault, existing.VersionId);
        const created = afterDefault.versions.find(({ VersionId }) => VersionId === steadyVersion.VersionId);
        if (!created || canonical(created.document) !== canonical(sourcePolicy)) fail("steady-state policy creation readback is not exact");
      }
    } catch (error) {
      throw attachMutationAccounting(error, accounting, { deletedVersionIds: deletedForCapacity, createdVersionIds: createdForSteadyState });
    }
    if (previous.temporaryVersionId !== afterDefault.active.VersionId) {
      try {
        deletePolicyVersion(previous.temporaryVersionId, accounting, readState, previous.temporaryVersionId);
      } catch (error) {
        throw attachMutationAccounting(error, accounting, { deletedVersionIds: deletedForCapacity, createdVersionIds: createdForSteadyState });
      }
    }
    let finalRead;
    try {
      finalRead = readState();
    } catch (error) {
      throw attachMutationAccounting(error, accounting, { deletedVersionIds: [...deletedForCapacity, previous.temporaryVersionId], createdVersionIds: createdForSteadyState });
    }
    try {
      if (finalRead.versions.some(({ document }) => document.Statement?.some(isTemporaryTagResourceStatement))) fail("temporary policy version remains after revocation");
      const evidence = buildTemporaryCapabilityEvidence({ ...previous, state: "REVOKED", temporaryVersionId: null, defaultVersionId: finalRead.active.VersionId, ownership: state === "ROOT_DROP_OWNERSHIP_VERIFIED" ? previous.ownership : null, observedAt: now() });
      assertTemporaryCapabilityEvidence(evidence, { sourceSha, state: "REVOKED" });
      assertTemporaryCapabilityTransition(previous.state, evidence.state, { sourceSha });
      persistEvidence(stateFile, evidence);
      return { evidence, writes: accounting.iamWrites, mutationAccounting: accounting };
    } catch (error) {
      throw attachMutationAccounting(error, accounting, { deletedVersionIds: [...deletedForCapacity, previous.temporaryVersionId], createdVersionIds: createdForSteadyState });
    }
  };
  return { runPhase };
}

function option(argv, name, required = true) {
  const index = argv.indexOf(name);
  const value = index >= 0 ? argv[index + 1] : undefined;
  if (required && (!value || value.startsWith("--"))) fail(`${name} is required`);
  return value;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const argv = process.argv.slice(2);
  const profile = option(argv, "--admin-profile");
  const releaseProfile = option(argv, "--release-profile", false);
  const region = option(argv, "--region", false) || TEMPORARY_KMS_CAPABILITY.region;
  if (region !== TEMPORARY_KMS_CAPABILITY.region) fail("region is outside the protected production boundary");
  const phase = option(argv, "--phase");
  const sourceSha = option(argv, "--source-sha");
  const transitionId = option(argv, "--transition-id");
  const stateFile = option(argv, "--state-file");
  const run = (args) => execFileSync("aws", [...args, "--region", region, "--profile", profile, "--output", "json", "--no-cli-pager"], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (releaseProfile && releaseProfile === profile) fail("administrator and release profiles must be distinct");
  const stageAStateFile = option(argv, "--stage-a-state", false);
  if (phase === "authorize" && !stageAStateFile) fail("--stage-a-state is required before temporary capability authorization");
  const stageAStateIdentityFile = option(argv, "--stage-a-state-identity", false);
  if (phase === "authorize" && !stageAStateIdentityFile) fail("--stage-a-state-identity is required before temporary capability authorization");
  const stageAStateIdentity = stageAStateIdentityFile ? readJson(stageAStateIdentityFile) : null;
  const result = createTemporaryKmsCapabilityRunner({ run, requireStageAStateBinding: Boolean(stageAStateFile) }).runPhase({ phase, sourceSha, transitionId, stateFile, planSha256: option(argv, "--plan-sha256", false), planJsonFile: option(argv, "--plan-json", false), terraformStateFile: option(argv, "--terraform-state", false), stageAStateFile, stageAStateIdentity, applyFailed: argv.includes("--apply-failed"), partialOperationCensus: argv.includes("--partial-operation-census-verified") });
  process.stdout.write(`${JSON.stringify({ state: result.evidence.state, evidenceSha256: result.evidence.evidenceSha256, writes: result.writes, mutationAccounting: result.mutationAccounting || null })}\n`);
}
