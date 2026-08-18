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
  buildRootDropOwnershipEvidence,
  buildTemporaryCapabilityEvidence,
  buildTemporaryReleasePolicy,
  isTemporaryTagResourceStatement,
} from "./production-stage-a-temporary-kms-capability.mjs";
import { ensureStageBPrivateFile, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sourcePolicyPath = path.join(root, TEMPORARY_KMS_CAPABILITY.sourcePolicyPath);
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const VERSION = /^v[1-9][0-9]*$/;
const canonical = (value) => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const text = (value) => decodeURIComponent(value || "");
const parseDocument = (value) => JSON.parse(text(value));
const fail = (message) => { throw new Error(`Temporary Stage-A KMS capability: ${message}`); };

function assertIdentity({ sourceSha, transitionId } = {}) {
  if (!SHA40.test(sourceSha || "") || !/^[A-Za-z0-9._-]{8,128}$/.test(transitionId || "")) fail("source SHA and transition ID are required");
}

function readJson(filePath) { return JSON.parse(readFileSync(filePath, "utf8")); }

function writeEvidence(filePath, value, repositoryRoot = root) {
  return writeStageBPrivateFileAtomic({ filePath, bytes: Buffer.from(`${JSON.stringify(value, null, 2)}\n`), repositoryRoot, overwrite: true, label: "Temporary Stage-A KMS capability evidence" });
}

export function createTemporaryKmsCapabilityRunner({ run, sourcePolicy = readJson(sourcePolicyPath), now = () => new Date().toISOString() } = {}) {
  if (typeof run !== "function") throw new Error("An explicit AWS command runner is required.");
  const readVersions = ({ allowTemporaryVersionId } = {}) => {
    const policy = JSON.parse(run(["iam", "get-policy", "--policy-arn", TEMPORARY_KMS_CAPABILITY.policyArn]));
    const versions = JSON.parse(run(["iam", "list-policy-versions", "--policy-arn", TEMPORARY_KMS_CAPABILITY.policyArn])).Versions || [];
    const documents = versions.map((version) => ({ ...version, document: parseDocument(JSON.parse(run(["iam", "get-policy-version", "--policy-arn", TEMPORARY_KMS_CAPABILITY.policyArn, "--version-id", version.VersionId])).PolicyVersion?.Document) }));
    const active = documents.find(({ VersionId }) => VersionId === policy.Policy?.DefaultVersionId);
    if (!active || !VERSION.test(active.VersionId)) fail("default managed-policy version is unreadable");
    const temporary = documents.filter(({ document }) => document.Statement?.some(isTemporaryTagResourceStatement));
    if (temporary.some(({ VersionId }) => VersionId !== active.VersionId && VersionId !== allowTemporaryVersionId)) fail("non-default temporary policy version creates an unknown topology");
    return { policy: policy.Policy, versions: documents, active };
  };
  const writePolicyVersion = (document) => {
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temporary-kms-policy-"));
    const temporaryPath = path.join(directory, "policy.json");
    const bytes = Buffer.from(JSON.stringify(document));
    writeFileSync(temporaryPath, bytes, { mode: 0o600, flag: "wx" });
    try {
      return JSON.parse(run(["iam", "create-policy-version", "--policy-arn", TEMPORARY_KMS_CAPABILITY.policyArn, "--policy-document", `file://${temporaryPath}`, "--set-as-default"])).PolicyVersion;
    } finally {
      unlinkSync(temporaryPath);
      rmdirSync(directory);
    }
  };
  const assertSource = (active) => {
    assertSteadyStateReleasePolicy(sourcePolicy);
    if (active.document.Statement?.some(isTemporaryTagResourceStatement)) return;
    if (canonical(active.document) !== canonical(sourcePolicy)) fail("live steady-state policy differs from protected source");
  };
  const runPhase = ({ phase, sourceSha, transitionId, stateFile, planSha256, planJsonFile, terraformStateFile, applyFailed = false, partialOperationCensus = false } = {}) => {
    assertIdentity({ sourceSha, transitionId });
    const previousFile = existsSync(stateFile) ? ensureStageBPrivateFile({ filePath: stateFile, repositoryRoot: root, label: "Temporary Stage-A KMS capability evidence" }).path : null;
    let previous = previousFile ? readJson(previousFile) : null;
    let state = previous?.state || "ABSENT";
    const current = readVersions({ allowTemporaryVersionId: previous?.temporaryVersionId });
    const activeTemporary = current.active.document.Statement?.some(isTemporaryTagResourceStatement);
    if (!previous && phase === "abort" && activeTemporary) {
      if (!applyFailed || !partialOperationCensus || !SHA256.test(planSha256 || "") || !planJsonFile) fail("authenticated recovery inputs are required for an unrecorded temporary capability");
      const planFile = ensureStageBPrivateFile({ filePath: planJsonFile, repositoryRoot: root, label: "Classified Stage-A plan JSON" });
      assertStageARootDropCreationPlan(readJson(planFile.path));
      assertTemporaryReleasePolicy(current.active.document, { steadyStatePolicy: sourcePolicy, sourceSha, transitionId });
      previous = buildTemporaryCapabilityEvidence({ state: "AUTHORIZED_FOR_ROOT_DROP_CREATION", sourceSha, transitionId, planSha256, defaultVersionId: current.active.VersionId, temporaryVersionId: current.active.VersionId, observedAt: now() });
      writeEvidence(stateFile, previous);
      state = previous.state;
    }
    if (previous && ["AUTHORIZED_FOR_ROOT_DROP_CREATION", "STAGE_A_APPLY", "ROOT_DROP_OWNERSHIP_VERIFIED"].includes(state)) {
      if (!activeTemporary || current.active.VersionId !== previous.temporaryVersionId) fail("authenticated temporary capability is not the live default version");
      assertTemporaryReleasePolicy(current.active.document, { steadyStatePolicy: sourcePolicy, sourceSha, transitionId: previous.transitionId });
    }
    if (phase === "authorize") {
      if (state === "AUTHORIZED_FOR_ROOT_DROP_CREATION" && activeTemporary) {
        assertTemporaryCapabilityEvidence(previous, { sourceSha, state });
        if (previous.transitionId !== transitionId || previous.temporaryVersionId !== current.active.VersionId || previous.planSha256 !== planSha256) fail("existing authorization belongs to a different transition or plan");
        if (!planJsonFile) fail("exact classified Stage-A plan JSON is required for replay");
        const planFile = ensureStageBPrivateFile({ filePath: planJsonFile, repositoryRoot: root, label: "Classified Stage-A plan JSON" });
        assertStageARootDropCreationPlan(readJson(planFile.path));
        return { evidence: previous, writes: 0 };
      }
      if (state !== "ABSENT" || activeTemporary) fail("authorization state or live policy topology is not ALL_OLD");
      assertSource(current.active);
      if (!SHA256.test(planSha256 || "") || !planJsonFile) fail("exact classified Stage-A plan binding is required before authorization");
      const planFile = ensureStageBPrivateFile({ filePath: planJsonFile, repositoryRoot: root, label: "Classified Stage-A plan JSON" });
      assertStageARootDropCreationPlan(readJson(planFile.path));
      const version = writePolicyVersion(buildTemporaryReleasePolicy(sourcePolicy, { sourceSha, transitionId }));
      const readback = readVersions();
      if (!readback.active.document.Statement?.some(isTemporaryTagResourceStatement) || readback.active.VersionId !== version.VersionId) fail("temporary policy readback is not exact");
      const evidence = buildTemporaryCapabilityEvidence({ state: "AUTHORIZED_FOR_ROOT_DROP_CREATION", sourceSha, transitionId, planSha256, defaultVersionId: readback.active.VersionId, temporaryVersionId: readback.active.VersionId, observedAt: now() });
      assertTemporaryReleasePolicy(readback.active.document, { steadyStatePolicy: sourcePolicy, sourceSha, transitionId });
      writeEvidence(stateFile, evidence);
      return { evidence, writes: 1 };
    }
    if (!previous) fail("a prior capability evidence file is required");
    if (phase === "mark-stage-a-apply") {
      assertTemporaryCapabilityEvidence(previous, { sourceSha, state: "AUTHORIZED_FOR_ROOT_DROP_CREATION" });
      if (!SHA256.test(planSha256 || "")) fail("Stage-A plan SHA is required");
      const evidence = buildTemporaryCapabilityEvidence({ ...previous, state: "STAGE_A_APPLY", planSha256, observedAt: now() });
      assertTemporaryCapabilityTransition(previous.state, evidence.state, { sourceSha });
      writeEvidence(stateFile, evidence);
      return { evidence, writes: 0 };
    }
    if (phase === "mark-root-drop-owned") {
      assertTemporaryCapabilityEvidence(previous, { sourceSha, state: "STAGE_A_APPLY" });
      if (!terraformStateFile || !existsSync(terraformStateFile)) fail("fresh canonical Stage-A state is required");
      const ownership = buildRootDropOwnershipEvidence({ terraformState: readJson(terraformStateFile), sourceSha, transitionId, planSha256: previous.planSha256, observedAt: now() });
      assertRootDropOwnershipEvidence(ownership, { sourceSha, planSha256: previous.planSha256 });
      const evidence = buildTemporaryCapabilityEvidence({ ...previous, state: "ROOT_DROP_OWNERSHIP_VERIFIED", ownership, observedAt: now() });
      assertTemporaryCapabilityTransition(previous.state, evidence.state, { sourceSha });
      writeEvidence(stateFile, evidence);
      return { evidence, writes: 0 };
    }
    if (phase === "abort") {
      if (!applyFailed || !partialOperationCensus || !["AUTHORIZED_FOR_ROOT_DROP_CREATION", "STAGE_A_APPLY"].includes(state)) fail("apply failure and authenticated partial-operation census are required");
    } else if (phase === "revoke") {
      if (state === "REVOKED") {
        assertTemporaryCapabilityEvidence(previous, { sourceSha, state });
        assertSource(current.active);
        if (current.versions.some(({ document }) => document.Statement?.some(isTemporaryTagResourceStatement))) fail("temporary capability version remains after revocation");
        return { evidence: previous, writes: 0 };
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
      writeEvidence(stateFile, evidence);
      return { evidence, writes: 0 };
    } else fail(`unsupported phase ${phase}`);
    if (!["AUTHORIZED_FOR_ROOT_DROP_CREATION", "STAGE_A_APPLY", "ROOT_DROP_OWNERSHIP_VERIFIED"].includes(state)) fail("capability state is not revocable");
    if (!activeTemporary || current.active.VersionId !== previous.temporaryVersionId) fail("active temporary policy does not match authenticated evidence");
    const steadyVersion = current.active.document.Statement?.some(isTemporaryTagResourceStatement) ? writePolicyVersion(sourcePolicy) : current.active;
    const afterDefault = readVersions({ allowTemporaryVersionId: previous.temporaryVersionId });
    assertSource(afterDefault.active);
    if (afterDefault.active.VersionId !== steadyVersion.VersionId) fail("steady-state policy was not made default");
    if (previous.temporaryVersionId !== afterDefault.active.VersionId) {
      run(["iam", "delete-policy-version", "--policy-arn", TEMPORARY_KMS_CAPABILITY.policyArn, "--version-id", previous.temporaryVersionId]);
    }
    const finalRead = readVersions();
    if (finalRead.versions.some(({ document }) => document.Statement?.some(isTemporaryTagResourceStatement))) fail("temporary policy version remains after revocation");
    const evidence = buildTemporaryCapabilityEvidence({ ...previous, state: "REVOKED", temporaryVersionId: null, defaultVersionId: finalRead.active.VersionId, ownership: state === "ROOT_DROP_OWNERSHIP_VERIFIED" ? previous.ownership : null, observedAt: now() });
    assertTemporaryCapabilityEvidence(evidence, { sourceSha, state: "REVOKED" });
    assertTemporaryCapabilityTransition(previous.state, evidence.state, { sourceSha });
    writeEvidence(stateFile, evidence);
    return { evidence, writes: 2 };
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
  const result = createTemporaryKmsCapabilityRunner({ run }).runPhase({ phase, sourceSha, transitionId, stateFile, planSha256: option(argv, "--plan-sha256", false), planJsonFile: option(argv, "--plan-json", false), terraformStateFile: option(argv, "--terraform-state", false), applyFailed: argv.includes("--apply-failed"), partialOperationCensus: argv.includes("--partial-operation-census-verified") });
  process.stdout.write(`${JSON.stringify({ state: result.evidence.state, evidenceSha256: result.evidence.evidenceSha256, writes: result.writes })}\n`);
}
