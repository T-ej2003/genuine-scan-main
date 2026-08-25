#!/usr/bin/env node
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createFailedRecoveryEvidenceReference, FAILED_RECOVERY_EVIDENCE_REFERENCE } from "./production-backend-failed-recovery-evidence-reference.mjs";
import { readStageBPrivateFileBytes, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const RELEASE_NOTES = "KMS-authenticated MSCQR backend failed-recovery history.";
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? null : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

function parseJson(value, label) {
  if (typeof value !== "string" && !Buffer.isBuffer(value)) throw new Error(`${label} response is missing.`);
  const text = value.toString();
  if (!text.trim()) throw new Error(`${label} response is empty.`);
  try { return JSON.parse(text); }
  catch { throw new Error(`${label} response is malformed.`); }
}

const exactPositiveId = (value) => /^[1-9][0-9]*$/.test(String(value || ""));

function assertReleaseIdentity(release, expected) {
  if (!release || !exactPositiveId(release.id) || release.tag_name !== expected.tag || release.target_commitish !== expected.sourceSha
    || release.name !== expected.tag || release.body !== RELEASE_NOTES || typeof release.draft !== "boolean" || typeof release.immutable !== "boolean"
    || !Array.isArray(release.assets)) throw new Error("Existing failed-recovery evidence release conflicts with the protected transaction identity.");
  const expectedAssets = release.assets.filter(({ name }) => name === expected.name);
  if (expectedAssets.length > 1 || release.assets.length !== expectedAssets.length) throw new Error("Existing failed-recovery evidence release contains duplicate or conflicting assets.");
  return expectedAssets[0] || null;
}

function assertAssetMetadata(asset, expected) {
  if (!asset || !exactPositiveId(asset.id) || asset.name !== expected.name || asset.state !== "uploaded"
    || asset.size !== expected.evidenceBytes.length || asset.digest !== `sha256:${expected.evidenceByteSha256}`) {
    throw new Error("Existing failed-recovery evidence asset conflicts with the protected evidence bytes.");
  }
}

function normalizeReleaseView(value) {
  const asset = (item) => {
    const match = /\/releases\/assets\/([1-9][0-9]*)$/.exec(item?.apiUrl || "");
    if (!match) throw new Error("Failed-recovery release asset API identity is malformed.");
    return { id: Number(match[1]), name: item.name, state: item.state, size: item.size, digest: item.digest };
  };
  return { id: value?.databaseId, tag_name: value?.tagName, target_commitish: value?.targetCommitish, name: value?.name, body: value?.body, draft: value?.isDraft, immutable: value?.isImmutable, assets: Array.isArray(value?.assets) ? value.assets.map(asset) : value?.assets };
}

function readRelease(run, expected) {
  try {
    const value = parseJson(run("gh", ["release", "view", expected.tag, "--repo", FAILED_RECOVERY_EVIDENCE_REFERENCE.repository, "--json", "databaseId,tagName,targetCommitish,name,body,isDraft,isImmutable,assets"]), "Failed-recovery release");
    return normalizeReleaseView(value);
  } catch (error) { if (error?.releaseNotFound === true) return null; throw error; }
}

const readAsset = (run, assetId) => parseJson(run("gh", ["api", `repos/${FAILED_RECOVERY_EVIDENCE_REFERENCE.repository}/releases/assets/${assetId}`]), "Failed-recovery release asset");
const readPublishedRelease = (run, releaseId) => parseJson(run("gh", ["api", `repos/${FAILED_RECOVERY_EVIDENCE_REFERENCE.repository}/releases/${releaseId}`]), "Published failed-recovery release");

function downloadAsset(run, assetId) {
  const bytes = run("gh", ["api", `repos/${FAILED_RECOVERY_EVIDENCE_REFERENCE.repository}/releases/assets/${assetId}`, "-H", "Accept: application/octet-stream"], { encoding: null });
  if (!Buffer.isBuffer(bytes)) throw new Error("Failed-recovery release asset download did not return bytes.");
  return bytes;
}

function inspectRemote(run, expected) {
  let release = readRelease(run, expected);
  if (!release) return Object.freeze({ state: "ABSENT", release: null, asset: null, evidenceBytes: null });
  let listedAsset = assertReleaseIdentity(release, expected);
  if (release.immutable && release.draft) throw new Error("Failed-recovery evidence release has an impossible immutable draft state.");
  if (!release.draft && !release.immutable) throw new Error("Existing published failed-recovery evidence release is not immutable and cannot be reconciled safely.");
  if (release.immutable) {
    const published = readPublishedRelease(run, release.id);
    const publishedAsset = assertReleaseIdentity(published, expected);
    if (String(published.id) !== String(release.id) || String(publishedAsset?.id || "") !== String(listedAsset?.id || "")) throw new Error("Published failed-recovery evidence release identity differs from its tag readback.");
    release = published; listedAsset = publishedAsset;
  }
  if (!listedAsset) {
    if (release.immutable || !release.draft) throw new Error("Published failed-recovery evidence release is missing its exact asset.");
    return Object.freeze({ state: "MUTABLE_DRAFT_EMPTY", release, asset: null, evidenceBytes: null });
  }
  assertAssetMetadata(listedAsset, expected);
  const asset = readAsset(run, listedAsset.id);
  assertAssetMetadata(asset, expected);
  if (String(asset.id) !== String(listedAsset.id)) throw new Error("Failed-recovery evidence asset readback identity changed.");
  const evidenceBytes = downloadAsset(run, asset.id);
  if (evidenceBytes.length !== expected.evidenceBytes.length || hash(evidenceBytes) !== expected.evidenceByteSha256 || !evidenceBytes.equals(expected.evidenceBytes)) {
    throw new Error("Existing failed-recovery evidence asset bytes conflict with the protected evidence.");
  }
  return Object.freeze({ state: release.immutable ? "IMMUTABLE_PUBLISHED" : "MUTABLE_DRAFT_READY", release, asset, evidenceBytes });
}

function assertSameRemoteIdentity(before, after, label) {
  const identity = (value) => JSON.stringify({ state: value.state, releaseId: value.release ? String(value.release.id) : null, assetId: value.asset ? String(value.asset.id) : null });
  if (identity(before) !== identity(after)) throw new Error(`Failed-recovery evidence release changed concurrently before ${label}.`);
}

function persistReference(outputFile, bytes) {
  const output = path.resolve(outputFile);
  if (fs.existsSync(output)) {
    const existing = readStageBPrivateFileBytes({ filePath: output, repositoryRoot: root, label: "Immutable failed recovery evidence reference" });
    if (!existing.bytes.equals(bytes)) throw new Error("Existing local failed-recovery evidence reference conflicts with final remote evidence.");
    return output;
  }
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, overwrite: false, files: [{ filePath: output, bytes, label: "Immutable failed recovery evidence reference" }] });
  return output;
}

export function publishProductionBackendFailedRecoveryEvidence({ sourceSha, evidenceFile, evidenceFileSha256, outputFile, run, protectedMain = readFreshProtectedMainIdentity, writeReference = persistReference } = {}) {
  protectedMain({ cwd: root, expectedSourceSha: sourceSha });
  if (typeof run !== "function" || typeof writeReference !== "function") throw new Error("Failed-recovery evidence publication adapters are incomplete.");
  const evidence = readStageBPrivateFileBytes({ filePath: path.resolve(evidenceFile), repositoryRoot: root, label: "Authenticated failed recovery evidence" });
  if (evidence.sha256 !== evidenceFileSha256) throw new Error("Authenticated failed recovery evidence bytes changed before publication.");
  const envelope = parseJson(evidence.bytes, "Authenticated failed recovery evidence");
  if (!/^[a-f0-9]{64}$/.test(envelope?.envelopeSha256 || "")) throw new Error("Authenticated failed recovery evidence envelope identity is invalid.");
  const expected = Object.freeze({ sourceSha, evidenceBytes: evidence.bytes, evidenceByteSha256: evidence.sha256, tag: FAILED_RECOVERY_EVIDENCE_REFERENCE.releaseTag(envelope.envelopeSha256), name: FAILED_RECOVERY_EVIDENCE_REFERENCE.assetName(envelope.envelopeSha256) });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-failed-recovery-release-"));
  try {
    const assetFile = path.join(directory, expected.name); fs.writeFileSync(assetFile, evidence.bytes, { mode: 0o600, flag: "wx" });
    let mutationCount = 0;
    for (let transition = 0; transition < 4; transition += 1) {
      const remote = inspectRemote(run, expected);
      if (remote.state === "IMMUTABLE_PUBLISHED") {
        const reference = createFailedRecoveryEvidenceReference({ sourceSha, evidenceBytes: remote.evidenceBytes, release: remote.release, asset: remote.asset });
        const output = writeReference(outputFile, Buffer.from(`${JSON.stringify(reference, null, 2)}\n`));
        return Object.freeze({ outputFile: output, referenceSha256: reference.referenceSha256, releaseId: reference.releaseId, assetId: reference.assetId, mutationCount, resumed: mutationCount === 0 });
      }
      if (remote.state === "ABSENT") {
        assertSameRemoteIdentity(remote, inspectRemote(run, expected), "creation");
        run("gh", ["release", "create", expected.tag, "--repo", FAILED_RECOVERY_EVIDENCE_REFERENCE.repository, "--target", sourceSha, "--title", expected.tag, "--notes", RELEASE_NOTES, "--draft"]);
      } else if (remote.state === "MUTABLE_DRAFT_EMPTY") {
        assertSameRemoteIdentity(remote, inspectRemote(run, expected), "asset upload");
        run("gh", ["release", "upload", expected.tag, assetFile, "--repo", FAILED_RECOVERY_EVIDENCE_REFERENCE.repository]);
      } else if (remote.state === "MUTABLE_DRAFT_READY") {
        assertSameRemoteIdentity(remote, inspectRemote(run, expected), "publication");
        run("gh", ["release", "edit", expected.tag, "--repo", FAILED_RECOVERY_EVIDENCE_REFERENCE.repository, "--draft=false"]);
      } else throw new Error("Failed-recovery evidence release state is not governed.");
      mutationCount += 1;
      inspectRemote(run, expected);
    }
    throw new Error("Failed-recovery evidence publication did not reach one exact immutable release.");
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

function defaultRun(command, args, options = {}) {
  try { return execFileSync(command, args, { cwd: root, encoding: options.encoding === null ? null : "utf8", stdio: ["ignore", "pipe", "pipe"] }); }
  catch (error) {
    const stderr = String(error?.stderr || "").trim();
    const match = /\(HTTP ([1-5][0-9]{2})\)$/.exec(stderr);
    if (match) error.httpStatus = Number(match[1]);
    if (stderr === "release not found") error.releaseNotFound = true;
    throw error;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = publishProductionBackendFailedRecoveryEvidence({ sourceSha: required(process.argv, "--source-sha"), evidenceFile: required(process.argv, "--evidence"), evidenceFileSha256: required(process.argv, "--evidence-sha256"), outputFile: required(process.argv, "--output"), run: defaultRun });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
