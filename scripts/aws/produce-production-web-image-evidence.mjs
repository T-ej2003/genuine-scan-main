#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { WEB_RELEASE, assertWebPublicationArtifactBundle, buildWebPublicationIdentity, buildWebImageEvidence, signWebImageEvidence, assertWebImageEvidence } from "./production-web-release-contract.mjs";
import { buildGovernedWebImageAuthorization } from "./production-web-image-authorization.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { verifyProductionReleaseImageAuthorization } from "./verify-production-release-image-authorization.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { createRootAttestationKmsSigner } from "./production-root-attestation-signer.mjs";
import { createRootAttestationKmsVerifier, ROOT_ATTESTATION_SIGNER_ARN } from "./production-root-attestation-key.mjs";
import { readBoundStageBPrivateJson, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";

const REPOSITORY = "T-ej2003/genuine-scan-main";
const SHA = /^[a-f0-9]{40}$/;
const HASH = /^[a-f0-9]{64}$/;
const WORKFLOW_RUN = /^[1-9][0-9]*$/;
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const json = (bytes, label) => { try { return JSON.parse(Buffer.from(bytes).toString("utf8")); } catch { throw new Error(`${label} is malformed.`); } };

function assertFreshProtectedSource(sourceSha, { cwd = process.cwd(), git = execFileSync } = {}) {
  if (!SHA.test(sourceSha || "")) throw new Error("Protected source SHA is malformed.");
  const read = (args) => git("git", args, { cwd, encoding: "utf8" }).trim();
  const protectedMainSha = read(["rev-parse", "origin/main"]);
  try { git("git", ["merge-base", "--is-ancestor", sourceSha, protectedMainSha], { cwd, encoding: "utf8", stdio: ["ignore", "ignore", "ignore"] }); } catch { throw new Error("Web evidence source is not reachable from protected main."); }
  if (read(["rev-parse", "HEAD"]) !== sourceSha || !SHA.test(protectedMainSha) || read(["status", "--porcelain"]) !== "") throw new Error("Web evidence requires a clean checkout of a commit reachable from protected main.");
  return true;
}

function requireOption(argv, name) {
  const matches = argv.reduce((found, value, index) => value === name ? [...found, argv[index + 1]] : found, []);
  if (matches.length !== 1 || !matches[0] || matches[0].startsWith("--")) throw new Error(`${name} is required exactly once.`);
  return matches[0];
}

function assertCli(argv) {
  const allowed = new Set(["--source-sha", "--stage-b-authorization", "--stage-b-authorization-sha256", "--web-workflow-run-id", "--output-dir"]);
  if (argv.length !== 10) throw new Error("Web evidence producer accepts exactly five options.");
  for (let index = 0; index < argv.length; index += 2) if (!allowed.has(argv[index])) throw new Error("Web evidence producer received an unsupported option.");
}

function defaultGithub(args, options = {}) { return execFileSync("gh", args, { encoding: options.binary ? "buffer" : "utf8", stdio: ["ignore", "pipe", "pipe"] }); }

function extractArtifactBundle(archiveBytes, { exec = execFileSync } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-web-publication-")); const archive = path.join(directory, "artifact.zip");
  try {
    fs.writeFileSync(archive, archiveBytes, { mode: 0o600, flag: "wx" });
    const names = String(exec("unzip", ["-Z1", archive], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })).trim().split(/\n/).filter(Boolean).sort();
    const expected = ["web-image.jsonl", "web.provenance.json", "web.spdx.json"];
    if (JSON.stringify(names) !== JSON.stringify(expected)) throw new Error("Web publication artifact has an unexpected member set.");
    const read = (name) => Buffer.from(exec("unzip", ["-p", archive, name], { encoding: "buffer", stdio: ["ignore", "pipe", "pipe"] }));
    return Object.freeze({ artifactBytes: read("web-image.jsonl"), provenanceBytes: read("web.provenance.json"), sbomBytes: read("web.spdx.json") });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

export function readGovernedWebPublication({ sourceSha, workflowRunId, workflowDefinitionSha, github = defaultGithub, extract = extractArtifactBundle } = {}) {
  if (!SHA.test(sourceSha || "") || !WORKFLOW_RUN.test(String(workflowRunId || ""))) throw new Error("Web publication source or workflow run is invalid.");
  const run = json(github(["api", `repos/${REPOSITORY}/actions/runs/${workflowRunId}`]), "Web publication workflow run");
  const artifacts = json(github(["api", `repos/${REPOSITORY}/actions/runs/${workflowRunId}/artifacts`]), "Web publication artifacts").artifacts;
  const matches = Array.isArray(artifacts) ? artifacts.filter((artifact) => artifact?.name === WEB_RELEASE.artifactName) : [];
  const expectedWorkflowDefinitionSha = workflowDefinitionSha || run?.head_sha;
  if (run?.id !== Number(workflowRunId) || run.path !== WEB_RELEASE.workflowFile || run.name !== WEB_RELEASE.workflowName || run.event !== "workflow_dispatch" || run.head_sha !== expectedWorkflowDefinitionSha || !SHA.test(run.head_sha || "") || run.head_branch !== "main" || run.conclusion !== "success" || run.actor?.login !== WEB_RELEASE.reviewer || matches.length !== 1 || matches[0].expired !== false || !/^\d+$/.test(String(matches[0].id || "")) || !/^sha256:[a-f0-9]{64}$/.test(matches[0].digest || "")) throw new Error("Web publication workflow identity is not canonical.");
  const artifact = matches[0]; const archiveBytes = Buffer.from(github(["api", `repos/${REPOSITORY}/actions/artifacts/${artifact.id}/zip`], { binary: true }));
  if (`sha256:${sha256(archiveBytes)}` !== artifact.digest) throw new Error("Web publication artifact archive digest is invalid.");
  const bundle = extract(archiveBytes);
  assertWebPublicationArtifactBundle({ ...bundle, sourceSha, workflowRunId, workflowDefinitionSha: run.head_sha });
  return Object.freeze({ observed: Object.freeze({ workflowRunId: String(run.id), workflowDatabaseId: String(run.workflow_id), workflowFile: run.path, workflowName: run.name, event: run.event, workflowDefinitionSha: run.head_sha, headBranch: run.head_branch, conclusion: run.conclusion, artifactId: String(artifact.id), artifactName: artifact.name, artifactExpired: false, reviewer: WEB_RELEASE.reviewer }), artifact, archiveBytes, ...bundle });
}

function assertRootCaller(run) {
  const caller = json(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]), "Web evidence signer identity");
  if (caller?.Arn !== ROOT_ATTESTATION_SIGNER_ARN || caller.Account !== WEB_RELEASE.account) throw new Error("Web evidence requires the canonical root-attestation signer identity.");
}

function readRepositoryEvidence(run) {
  const response = json(run(["ecr", "describe-repositories", "--registry-id", WEB_RELEASE.account, "--repository-names", WEB_RELEASE.repository, "--output", "json", "--no-cli-pager"]), "Web image repository");
  if (!Array.isArray(response.repositories) || response.repositories.length !== 1) throw new Error("Web image repository readback is invalid.");
  return response.repositories[0];
}

function readImageEvidence(run, sourceSha) {
  const response = json(run(["ecr", "describe-images", "--repository-name", WEB_RELEASE.repository, "--image-ids", `imageTag=${sourceSha}`, "--output", "json", "--no-cli-pager"]), "Web image readback");
  if (!Array.isArray(response.imageDetails) || response.imageDetails.length !== 1) throw new Error("Web image readback is invalid.");
  return response.imageDetails[0];
}

export function produceGovernedWebEvidence({ sourceSha, stageBAuthorization, publication, now = new Date().toISOString(), run, verifyStageBImageEvidence, verifyStageBAuthorization = verifyProductionReleaseImageAuthorization, verifyArtifacts, sign, verifyWebEvidence } = {}) {
  if (!SHA.test(sourceSha || "") || typeof run !== "function" || !publication) throw new Error("Governed web evidence inputs are invalid.");
  assertRootCaller(run);
  if (typeof verifyStageBAuthorization !== "function") throw new Error("Stage-B authorization verifier is required.");
  verifyStageBAuthorization({ authorization: stageBAuthorization, sourceSha, verifyImageEvidence: verifyStageBImageEvidence || ((options) => verifyImageEvidenceSignature({ ...options, run })), now });
  const impact = stageBAuthorization?.imageReuseEvidence;
  if (impact?.webPublicationRequired !== true || impact.toolingSha !== sourceSha) throw new Error("Governed web evidence requires authenticated web-required Stage-B impact.");
  const record = assertWebPublicationArtifactBundle({ artifactBytes: publication.artifactBytes, sbomBytes: publication.sbomBytes, provenanceBytes: publication.provenanceBytes, sourceSha, workflowRunId: publication.observed?.workflowRunId, workflowDefinitionSha: publication.observed?.workflowDefinitionSha });
  const identity = buildWebPublicationIdentity({ sourceSha, observed: publication.observed, artifactBytes: publication.artifactBytes, observedAt: now });
  const repositoryEvidence = readRepositoryEvidence(run); const imageReadback = readImageEvidence(run, sourceSha);
  if (imageReadback.imageDigest !== record.image_digest || typeof verifyArtifacts !== "function" || verifyArtifacts(record.image_ref) !== true) throw new Error("Web image supply-chain verification is invalid.");
  const evidence = buildWebImageEvidence({ publicationIdentity: identity, repositoryEvidence, imageReadback: { digest: imageReadback.imageDigest, imagePushedAt: imageReadback.imagePushedAt }, imageImpactSha256: canonicalSha256(impact), createdAt: now, expiresAt: new Date(Date.parse(now) + 24 * 60 * 60 * 1000).toISOString() });
  const signer = sign || createRootAttestationKmsSigner({ run }); const verify = verifyWebEvidence || createRootAttestationKmsVerifier({ run });
  const signature = signWebImageEvidence(evidence, { signedAt: now, sign: signer });
  assertWebImageEvidence(evidence, { signature, verify, now });
  const authorization = buildGovernedWebImageAuthorization({ sourceSha, evidence, signature, stageBAuthorization, now, verify });
  return Object.freeze({ identity, evidence, signature, authorization });
}

export function runCli(argv = process.argv.slice(2), deps = {}) {
  assertCli(argv);
  const sourceSha = requireOption(argv, "--source-sha"); const stageBPath = requireOption(argv, "--stage-b-authorization"); const stageBHash = requireOption(argv, "--stage-b-authorization-sha256"); const workflowRunId = requireOption(argv, "--web-workflow-run-id"); const outputDir = requireOption(argv, "--output-dir");
  if (!SHA.test(sourceSha) || !HASH.test(stageBHash) || !WORKFLOW_RUN.test(workflowRunId)) throw new Error("Web evidence producer binding is malformed.");
  assertFreshProtectedSource(sourceSha, deps);
  const stageBAuthorization = readBoundStageBPrivateJson({ filePath: stageBPath, expectedSha256: stageBHash, label: "Stage-B authorization" });
  const run = deps.run || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "default", region: WEB_RELEASE.region });
  const publication = (deps.readPublication || readGovernedWebPublication)({ sourceSha, workflowRunId, ...(deps.github ? { github: deps.github } : {}) });
  const verifyArtifacts = deps.verifyArtifacts || ((imageRef) => {
    execFileSync("scripts/aws/verify-release-artifacts.sh", [imageRef], {
      stdio: "ignore",
      env: { ...process.env, COSIGN_CERT_IDENTITY_REGEXP: `^https://github.com/${REPOSITORY}/${WEB_RELEASE.workflowFile}@.*$`, COSIGN_CERT_OIDC_ISSUER: "https://token.actions.githubusercontent.com", PROVENANCE_ATTESTATION_TYPE: "https://mscqr.com/attestations/production-web-provenance/v1" },
    });
    return true;
  });
  const result = produceGovernedWebEvidence({ sourceSha, stageBAuthorization, publication, run, now: deps.now || new Date().toISOString(), verifyStageBImageEvidence: deps.verifyStageBImageEvidence, verifyArtifacts });
  const files = ["web-image-evidence.json", "web-image-evidence-signature.json", "web-image-authorization.json"].map((name) => path.resolve(outputDir, name));
  writeStageBPrivateFilesAtomic({ repositoryRoot: process.cwd(), files: [
    { filePath: files[0], bytes: Buffer.from(`${JSON.stringify(result.evidence, null, 2)}\n`), label: "Web image evidence" },
    { filePath: files[1], bytes: Buffer.from(`${JSON.stringify(result.signature, null, 2)}\n`), label: "Web image evidence signature" },
    { filePath: files[2], bytes: Buffer.from(`${JSON.stringify(result.authorization, null, 2)}\n`), label: "Web image authorization" },
  ] });
  return Object.freeze({ outputDir: path.resolve(outputDir), evidenceSha256: result.evidence.evidenceSha256, authorizationSha256: result.authorization.authorizationSha256, sourceSha });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  try { process.stdout.write(`${JSON.stringify(runCli())}\n`); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
