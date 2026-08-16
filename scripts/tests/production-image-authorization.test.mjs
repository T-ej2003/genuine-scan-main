import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertImageAuthorization } from "../aws/production-cutover-control-plane.mjs";
import {
  createImageAuthorization,
  assertCanonicalImageReuseEvidence,
  imageAuthorizationSha256,
  runCli,
} from "../aws/production-image-authorization.mjs";
import {
  assertImageImpactReport,
  deriveStageBImageImpactReport,
  imageImpactReportFor,
  STAGE_B_IMAGE_REUSE_RULES_VERSION,
} from "../aws/validate-stage-b-image-reuse.mjs";
import {
  assertImageEvidence,
  generateImageEvidence,
  imageEvidenceSha256,
  signImageEvidence,
  verifyImageEvidenceSignature,
} from "../aws/production-green-stage-b-image-evidence.mjs";
import { buildStageBImagePublicationIdentity } from "../aws/stage-b-image-publication-identity.mjs";
import { readFreshProtectedMainIdentity } from "../aws/stage-b-deployment-identity.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";

const sourceSha = "96a4be6f0edcd626285c6a1bd8062a4008175d25";
const toolingSha = sourceSha;
const imageReleaseSha = "594bab55f23ff8b2438c12b85b149ba0aebeed1e";
const workflowRunId = "31582010244";
const observedAt = "2026-08-12T10:00:00.000Z";
const digests = {
  backend: "sha256:5c03df843e46dd0853762108c7ae780a4d06b7e11cac585d9d2b2cd3d196f6ad",
  worker: "sha256:949a4f25d9cc5d67358722c7af75e91bd9a944e75496c76fa36b4677fd152cfe",
  "rls-executor": "sha256:6a06c2435f7330c0b5efacce91e526aa0cca9f3f1df02efaec2c8f993b6fde37",
  "rls-canary": "sha256:f26b3c87ef6b7d1545936e50a41a049e5d02b3f11ef81bd41946ca1c967b05ab",
};

const records = [
  ["backend", "mscqr-backend", imageReleaseSha],
  ["worker", "mscqr-worker", imageReleaseSha],
  ["rls-executor", "mscqr-backend", `${imageReleaseSha}-rls-executor`],
  ["rls-canary", "mscqr-backend", `${imageReleaseSha}-rls-canary`],
].map(([service, repository, tag]) => ({
  service,
  repository,
  image_uri: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}:${tag}`,
  image_tag: tag,
  image_digest: digests[service],
  image_ref: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}@${digests[service]}`,
}));
const artifactBytes = Buffer.from(`${records.map((record) => JSON.stringify(record)).join("\n")}\n`);
const artifactSha256 = crypto.createHash("sha256").update(artifactBytes).digest("hex");
const publicationIdentity = buildStageBImagePublicationIdentity({
  expectedToolingSha: sourceSha,
  expectedReleaseSha: imageReleaseSha,
  artifactBytes,
  observed: {
    workflowRunId,
    workflowDatabaseId: "401",
    workflowFile: ".github/workflows/production-green-stage-b-images.yml",
    workflowName: "Production Green Stage B Images",
    event: "workflow_dispatch",
    workflowDefinitionSha: sourceSha,
    imageReleaseSha,
    headBranch: "main",
    conclusion: "success",
    artifactId: "501",
    artifactName: "production-green-stage-b-images",
    artifactExpired: false,
    artifactArchiveFilename: null,
  },
  observedAt,
});
const repositories = ["mscqr-backend", "mscqr-worker"].map((repository) => ({
  repositoryName: repository,
  repositoryArn: `arn:aws:ecr:eu-west-2:${STAGE_B.account}:repository/${repository}`,
  registryId: STAGE_B.account,
  repositoryUri: `${STAGE_B.account}.dkr.ecr.eu-west-2.amazonaws.com/${repository}`,
  imageTagMutability: "IMMUTABLE",
  encryptionConfiguration: { encryptionType: "AES256" },
  createdAt: observedAt,
  observedAt,
}));
const describe = (repository, tag) => {
  const record = records.find((candidate) => candidate.repository === repository && candidate.image_tag === tag);
  return { digest: record.image_digest, imagePushedAt: observedAt };
};
const imageEvidence = generateImageEvidence({
  artifactBytes, toolingSha,
  imageReleaseSha,
  workflowRunId,
  artifactSha256,
  publicationIdentity,
  verifierCallerArn: `arn:aws:iam::${STAGE_B.account}:root`,
  observedAt,
  describe,
  repositories,
});
const imageEvidenceSignature = signImageEvidence(imageEvidence, { now: observedAt, sign: () => "AQ==" });
const verifyImageEvidence = ({ report, signatureArtifact, now }) => verifyImageEvidenceSignature({ report, signatureArtifact, now, verify: () => true });
const imageReuseEvidence = deriveStageBImageImpactReport({ imageReleaseSha, toolingSha: sourceSha });

function produce(overrides = {}) {
  return createImageAuthorization({
    sourceSha,
    freshProtectedMain: { fetchSucceeded: true, headSha: sourceSha, freshRemoteMainSha: sourceSha },
    imageEvidence: overrides.imageEvidence || imageEvidence,
    imageEvidenceSignature: overrides.imageEvidenceSignature || imageEvidenceSignature,
    imageReuseEvidence: overrides.imageReuseEvidence || imageReuseEvidence,
    now: overrides.now || observedAt,
    verifyImageEvidence: overrides.verifyImageEvidence || verifyImageEvidence,
  });
}

const freshSourceSha = "94da9651eb9427603be87abe89f89111412755c9";
const freshImageReleaseSha = freshSourceSha;
const freshImpactReleaseSha = "29bf92a14d5e832575009bd76b16886feff62cbd";
const freshWorkflowRunId = "31961264995";
const freshRecords = records.map((record) => {
  const tag = record.service === "rls-executor" ? `${freshImageReleaseSha}-rls-executor` : record.service === "rls-canary" ? `${freshImageReleaseSha}-rls-canary` : freshImageReleaseSha;
  return { ...record, image_tag: tag, image_uri: `${record.image_uri.slice(0, record.image_uri.lastIndexOf(":"))}:${tag}`, image_ref: `${record.image_ref.slice(0, record.image_ref.lastIndexOf("@"))}@${record.image_digest}` };
});
const freshArtifactBytes = Buffer.from(`${freshRecords.map((record) => JSON.stringify(record)).join("\n")}\n`);
const freshArtifactSha256 = crypto.createHash("sha256").update(freshArtifactBytes).digest("hex");
const freshPublicationIdentity = buildStageBImagePublicationIdentity({
  expectedToolingSha: freshSourceSha,
  expectedReleaseSha: freshImageReleaseSha,
  artifactBytes: freshArtifactBytes,
  observed: {
    workflowRunId: freshWorkflowRunId,
    workflowDatabaseId: "322853224",
    workflowFile: ".github/workflows/production-green-stage-b-images.yml",
    workflowName: "Production Green Stage B Images",
    event: "workflow_dispatch",
    workflowDefinitionSha: freshSourceSha,
    imageReleaseSha: freshImageReleaseSha,
    headBranch: "main",
    conclusion: "success",
    artifactId: "9267442109",
    artifactName: "production-green-stage-b-images",
    artifactExpired: false,
    artifactArchiveFilename: null,
  },
  observedAt,
});
const freshImageEvidence = generateImageEvidence({
  artifactBytes: freshArtifactBytes,
  toolingSha: freshSourceSha,
  imageReleaseSha: freshImageReleaseSha,
  workflowRunId: freshWorkflowRunId,
  artifactSha256: freshArtifactSha256,
  publicationIdentity: freshPublicationIdentity,
  verifierCallerArn: `arn:aws:iam::${STAGE_B.account}:root`,
  observedAt,
  describe: (repository, tag) => ({ digest: freshRecords.find((record) => record.repository === repository && record.image_tag === tag).image_digest, imagePushedAt: observedAt }),
  repositories,
});
const freshImageEvidenceSignature = signImageEvidence(freshImageEvidence, { now: observedAt, sign: () => "AQ==" });
const freshVerifyImageEvidence = ({ report, signatureArtifact, now }) => verifyImageEvidenceSignature({ report, signatureArtifact, now, verify: () => true });
const freshImageImpactEvidence = deriveStageBImageImpactReport({ imageReleaseSha: freshImpactReleaseSha, toolingSha: freshSourceSha });
const previousReleaseRecords = freshRecords.map((record) => {
  const tag = record.service === "rls-executor" ? `${freshImpactReleaseSha}-rls-executor` : record.service === "rls-canary" ? `${freshImpactReleaseSha}-rls-canary` : freshImpactReleaseSha;
  return { ...record, image_tag: tag, image_uri: `${record.image_uri.slice(0, record.image_uri.lastIndexOf(":"))}:${tag}` };
});
const previousReleaseArtifactBytes = Buffer.from(`${previousReleaseRecords.map((record) => JSON.stringify(record)).join("\n")}\n`);
const previousReleaseArtifactSha256 = crypto.createHash("sha256").update(previousReleaseArtifactBytes).digest("hex");
const previousReleasePublicationIdentity = buildStageBImagePublicationIdentity({
  expectedToolingSha: freshImpactReleaseSha,
  expectedReleaseSha: freshImpactReleaseSha,
  artifactBytes: previousReleaseArtifactBytes,
  observed: {
    workflowRunId: "31961264994", workflowDatabaseId: "322853223", workflowFile: ".github/workflows/production-green-stage-b-images.yml",
    workflowName: "Production Green Stage B Images", event: "workflow_dispatch", workflowDefinitionSha: freshImpactReleaseSha,
    imageReleaseSha: freshImpactReleaseSha, headBranch: "main", conclusion: "success", artifactId: "9267442108",
    artifactName: "production-green-stage-b-images", artifactExpired: false, artifactArchiveFilename: null,
  },
  observedAt,
});
const previousReleaseImageEvidence = generateImageEvidence({
  artifactBytes: previousReleaseArtifactBytes,
  toolingSha: freshImpactReleaseSha,
  imageReleaseSha: freshImpactReleaseSha,
  workflowRunId: "31961264994",
  artifactSha256: previousReleaseArtifactSha256,
  publicationIdentity: previousReleasePublicationIdentity,
  verifierCallerArn: `arn:aws:iam::${STAGE_B.account}:root`,
  observedAt,
  describe: (repository, tag) => ({ digest: previousReleaseRecords.find((record) => record.repository === repository && record.image_tag === tag).image_digest, imagePushedAt: observedAt }),
  repositories,
});
const previousReleaseImageEvidenceSignature = signImageEvidence(previousReleaseImageEvidence, { now: observedAt, sign: () => "AQ==" });
const previousReleaseVerifyImageEvidence = ({ report, signatureArtifact, now }) => verifyImageEvidenceSignature({ report, signatureArtifact, now, verify: () => true });
const freshAuthorizationInputs = {
  sourceSha: freshSourceSha,
  freshProtectedMain: { fetchSucceeded: true, headSha: freshSourceSha, freshRemoteMainSha: freshSourceSha },
  imageEvidence: freshImageEvidence,
  imageEvidenceSignature: freshImageEvidenceSignature,
  imageReuseEvidence: freshImageImpactEvidence,
  now: observedAt,
  verifyImageEvidence: freshVerifyImageEvidence,
};
const freshAuthorization = createImageAuthorization(freshAuthorizationInputs);

test("canonical 594-to-96 reuse evidence produces downstream-accepted authorization", () => {
  const authorization = produce();
  assert.equal(authorization.sourceSha, sourceSha);
  assert.equal(authorization.imageReleaseSha, imageReleaseSha);
  assert.equal(authorization.workflowRunId, workflowRunId);
  assert.equal(authorization.backendDigest, digests.backend);
  assert.equal(authorization.images.length, 4);
  assert.equal(authorization.evidenceSha256, imageAuthorizationSha256(authorization));
  assert.doesNotThrow(() => assertImageAuthorization(authorization, sourceSha, { now: observedAt, verifyImageEvidence }));
});

test("two-SHA reuse requires the exact source-to-destination authorization", () => {
  assert.notEqual(sourceSha, imageReleaseSha);
  assert.doesNotThrow(() => produce());
  assert.throws(() => createImageAuthorization({ sourceSha, freshProtectedMain: { fetchSucceeded: true, headSha: sourceSha, freshRemoteMainSha: sourceSha }, imageEvidence, imageEvidenceSignature, imageReuseEvidence: undefined, now: observedAt, verifyImageEvidence }), /image-reuse evidence|required|incomplete/);
  assert.throws(() => produce({ imageReuseEvidence: { ...imageReuseEvidence, toolingSha: "b".repeat(40) } }), /different|comparison|bound|independently derived/);
});

test("fresh protected-main publication is a separate authorization path", () => {
  assert.equal(freshImageImpactEvidence.newImagesRequired, true);
  assert.equal(freshImageImpactEvidence.imageReuseCompatible, false);
  assert.equal(freshAuthorization.authorizationPath, "FRESH_IMAGE_PUBLICATION");
  assert.equal(freshAuthorization.imageReuseCompatible, false);
  assert.equal(freshAuthorization.imageBuildInputsChanged, true);
  assert.equal(freshAuthorization.imageReleaseSha, freshSourceSha);
  assert.equal(freshAuthorization.workflowRunId, freshWorkflowRunId);
  assert.doesNotThrow(() => assertImageAuthorization(freshAuthorization, freshSourceSha, { now: observedAt, verifyImageEvidence: freshVerifyImageEvidence }));
});

test("fresh publication rejects stale or cross-boundary evidence", () => {
  assert.throws(() => createImageAuthorization({
    sourceSha: freshSourceSha,
    freshProtectedMain: { fetchSucceeded: true, headSha: freshSourceSha, freshRemoteMainSha: freshSourceSha },
    imageEvidence,
    imageEvidenceSignature,
    imageReuseEvidence: freshImageImpactEvidence,
    now: observedAt,
    verifyImageEvidence,
  }), /protected-main|workflow|publication|bound/);
  assert.throws(() => assertImageAuthorization({ ...freshAuthorization, authorizationPath: "IMAGE_REUSE", evidenceSha256: "0".repeat(64), authorizationSha256: "0".repeat(64) }, freshSourceSha, { now: observedAt, verifyImageEvidence: freshVerifyImageEvidence }), /hash|path/);
  assert.throws(() => createImageAuthorization({
    sourceSha: freshSourceSha,
    freshProtectedMain: { fetchSucceeded: true, headSha: freshSourceSha, freshRemoteMainSha: freshSourceSha },
    imageEvidence: { ...freshImageEvidence, publicationIdentity: { ...freshImageEvidence.publicationIdentity, workflowDefinitionSha: "b".repeat(40) } },
    imageEvidenceSignature: freshImageEvidenceSignature,
    imageReuseEvidence: freshImageImpactEvidence,
    now: observedAt,
    verifyImageEvidence: freshVerifyImageEvidence,
  }), /protected-main|publication|workflow|identity/);
});

test("fresh publication rejects a fully valid previous-release build", () => {
  assert.throws(() => createImageAuthorization({
    sourceSha: freshSourceSha,
    freshProtectedMain: { fetchSucceeded: true, headSha: freshSourceSha, freshRemoteMainSha: freshSourceSha },
    imageEvidence: previousReleaseImageEvidence,
    imageEvidenceSignature: previousReleaseImageEvidenceSignature,
    imageReuseEvidence: freshImageImpactEvidence,
    now: observedAt,
    verifyImageEvidence: previousReleaseVerifyImageEvidence,
  }), /protected-main|workflow|publication|release/);
});

test("fresh publication fails closed for every required source and supply-chain binding", () => {
  const rejected = [
    ["protected SHA", () => assertImageAuthorization(freshAuthorization, "b".repeat(40), { now: observedAt, verifyImageEvidence: freshVerifyImageEvidence })],
    ["release SHA", () => assertImageAuthorization({ ...freshAuthorization, imageReleaseSha: "b".repeat(40) }, freshSourceSha, { now: observedAt, verifyImageEvidence: freshVerifyImageEvidence })],
    ["tooling SHA", () => createImageAuthorization({ ...freshAuthorizationInputs, imageReuseEvidence: { ...freshImageImpactEvidence, toolingSha: "b".repeat(40) } })],
    ["required image", () => assertImageAuthorization({ ...freshAuthorization, images: freshAuthorization.images.slice(0, 3) }, freshSourceSha, { now: observedAt, verifyImageEvidence: freshVerifyImageEvidence })],
    ["digest", () => assertImageAuthorization({ ...freshAuthorization, images: freshAuthorization.images.map((image) => image.service === "backend" ? { ...image, digest: `sha256:${"f".repeat(64)}` } : image) }, freshSourceSha, { now: observedAt, verifyImageEvidence: freshVerifyImageEvidence })],
    ["Cosign/OIDC/tlog/predicate verification", () => createImageAuthorization({ ...freshAuthorizationInputs, verifyImageEvidence: () => { throw new Error("verified supply-chain evidence rejected"); } })],
  ];
  for (const [label, attempt] of rejected) assert.throws(attempt, /source|hash|image|digest|verification|verified|bound|impact|workflow|publication/, label);
});

test("producer rejects rebinding, image-affecting reuse, and changed image evidence", () => {
  assert.throws(() => createImageAuthorization({ ...produce(), sourceSha, freshProtectedMain: { fetchSucceeded: true, headSha: "b".repeat(40), freshRemoteMainSha: sourceSha } }), /source SHA/);
  const imageAffecting = imageImpactReportFor({ imageReleaseSha, toolingSha: sourceSha, toolingInputTreeSha256: imageReuseEvidence.toolingInputTreeSha256, changedFiles: ["backend/src/app.ts"] });
  assert.throws(() => produce({ imageReuseEvidence: imageAffecting }), /stale|unsafe|compatible|independently derived|match/);
  assert.throws(() => produce({ imageEvidence: { ...imageEvidence, workflowRunId: "31582010245" } }), /different report|publication|workflow|signature identity/);
  assert.throws(() => produce({ imageReuseEvidence: { ...imageReuseEvidence, imageReleaseSha: sourceSha } }), /different|comparison|bound|publication|match/);
  const tamperedImage = { ...imageEvidence, images: imageEvidence.images.map((image) => image.service === "backend" ? { ...image, digest: `sha256:${"f".repeat(64)}` } : image) };
  assert.throws(() => produce({ imageEvidence: tamperedImage }), /different report|canonical artifact|digest/);
  assert.throws(() => produce({ imageEvidenceSignature: { ...imageEvidenceSignature, reportSha256: "0".repeat(64) } }), /different report/);
});

test("producer rejects invalid signature, attestation/provenance evidence, and incomplete four-image evidence", () => {
  for (const label of ["signature", "attestation", "provenance"]) {
    assert.throws(() => produce({ verifyImageEvidence: () => { throw new Error(`${label} verification failed`); } }), /verification failed/);
  }
  for (const images of [imageEvidence.images.slice(0, 3), [...imageEvidence.images, imageEvidence.images[0]]]) {
    assert.throws(() => produce({ imageEvidence: { ...imageEvidence, images } }), /four|duplicate|different report|canonical|authoritative/);
  }
  assert.throws(() => assertImageAuthorization({ ...produce(), imageEvidence: undefined }, sourceSha), /incomplete/);
});

test("downstream rejects stale, tampered, and partial authorization envelopes", () => {
  const authorization = produce();
  assert.throws(() => assertImageAuthorization({ ...authorization, sourceSha: "b".repeat(40), imageReleaseSha: "b".repeat(40) }, sourceSha), /invalid|source/);
  assert.throws(() => assertImageAuthorization({ ...authorization, sourceSha: "b".repeat(40) }, sourceSha), /invalid|source/);
  assert.throws(() => assertImageAuthorization({ ...authorization, imageEvidence: { ...authorization.imageEvidence, images: [] } }, sourceSha, { now: observedAt, verifyImageEvidence }), /hash/);
  assert.throws(() => assertImageAuthorization({ ...authorization, imageReuseEvidence: { ...authorization.imageReuseEvidence, imageReuseCompatible: false } }, sourceSha, { now: observedAt, verifyImageEvidence }), /hash/);
  const partial = { ...authorization };
  delete partial.imageEvidence;
  delete partial.imageEvidenceSignature;
  delete partial.imageReuseEvidence;
  assert.throws(() => assertImageAuthorization(partial, sourceSha), /incomplete/);
});

test("canonical image evidence and reuse validators are the only producer gates", () => {
  assert.equal(imageEvidenceSha256(imageEvidence), produce().imageEvidenceSha256);
  assert.doesNotThrow(() => assertImageEvidence(imageEvidence, { signatureArtifact: imageEvidenceSignature, toolingSha, imageReleaseSha, workflowRunId, artifactSha256, now: observedAt, verifySignature: verifyImageEvidence }));
  assert.doesNotThrow(() => assertImageImpactReport({ report: imageReuseEvidence, imageReleaseSha, toolingSha: sourceSha, toolingInputTreeSha256: imageReuseEvidence.toolingInputTreeSha256, changedFiles: imageReuseEvidence.classifiedChangedFiles }));
  assert.equal(imageReuseEvidence.classificationRulesVersion, STAGE_B_IMAGE_REUSE_RULES_VERSION);
});

test("producer rejects caller-supplied impact claims and stale reuse reports", () => {
  const affectedRelease = sourceSha;
  const affectedSource = "9215f8b7902fa19d734b53da171228b51aa4b026";
  const derived = deriveStageBImageImpactReport({ imageReleaseSha: affectedRelease, toolingSha: affectedSource });
  assert.equal(derived.imageReuseCompatible, false);
  const malicious = { ...derived, classifiedChangedFiles: [], imageAffectingFiles: [], toolingInputTreeSha256: "1".repeat(64), imageReuseCompatible: true, newImagesRequired: false, reason: "forged" };
  assert.throws(() => assertCanonicalImageReuseEvidence({ imageReleaseSha: affectedRelease }, malicious, affectedSource), /independently derived/);
  const stale = imageImpactReportFor({ imageReleaseSha: affectedRelease, toolingSha: affectedSource, changedFiles: [], toolingInputTreeSha256: "2".repeat(64) });
  assert.throws(() => assertCanonicalImageReuseEvidence({ imageReleaseSha: affectedRelease }, stale, affectedSource), /independently derived/);
});

test("legacy asserted authorization is rejected without canonical v2 evidence", () => {
  assert.throws(() => assertImageAuthorization({
    valid: true,
    sourceSha,
    evidenceSha256: "a".repeat(64),
    signatureVerified: true,
    attestationVerified: true,
    provenanceVerified: true,
    imageReuseCompatible: true,
    imageBuildInputsChanged: false,
    imageReleaseSha,
    workflowRunId,
    images: Object.keys(digests).map((service) => ({ service, digest: digests[service] })),
  }, sourceSha), /Canonical image authorization/);
});

test("CLI emits one private source-bound authorization artifact", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-image-authorization-"));
  const write = (name, value) => {
    const filePath = path.join(directory, name);
    fs.writeFileSync(filePath, `${JSON.stringify(value)}\n`, { mode: 0o600 });
    fs.chmodSync(filePath, 0o600);
    return filePath;
  };
  try {
    const output = path.join(directory, "image-authorization.json");
    runCli([
      "--source-sha", sourceSha,
      "--image-evidence", write("image-evidence.json", imageEvidence),
      "--image-signature", write("image-evidence.signature.json", imageEvidenceSignature),
      "--image-reuse-evidence", write("image-reuse.json", imageReuseEvidence),
      "--output", output,
    ], { git: (args) => {
      if (args[0] === "fetch") return "";
      if (args[0] === "rev-parse" && args[1] === "FETCH_HEAD") return sourceSha;
      if (args[0] === "rev-parse" && args[1] === "HEAD") return sourceSha;
      throw new Error(`unexpected git call: ${args.join(" ")}`);
    }, now: observedAt, verifyImageEvidence });
    assert.equal(fs.statSync(output).mode & 0o777, 0o600);
    const emitted = JSON.parse(fs.readFileSync(output, "utf8"));
    assert.doesNotThrow(() => assertImageAuthorization(emitted, sourceSha, { now: observedAt, verifyImageEvidence }));
    assert.equal(emitted.evidenceSha256, imageAuthorizationSha256(emitted));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("fresh protected-main identity rejects stale refs, fetch failures, and SHA rebinding without writing authorization", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-fresh-main-"));
  const output = path.join(directory, "image-authorization.json");
  const args = ["--source-sha", sourceSha, "--image-evidence", path.join(directory, "image.json"), "--image-signature", path.join(directory, "signature.json"), "--image-reuse-evidence", path.join(directory, "reuse.json"), "--output", output];
  const run = ({ head = sourceSha, fresh = sourceSha, fetchFailure = false } = {}) => {
    const calls = [];
    const git = (gitArgs) => {
      calls.push([...gitArgs]);
      if (gitArgs[0] === "fetch") {
        if (fetchFailure) throw new Error("network unavailable");
        return "";
      }
      if (gitArgs[0] === "rev-parse" && gitArgs[1] === "FETCH_HEAD") return fresh;
      if (gitArgs[0] === "rev-parse" && gitArgs[1] === "HEAD") return head;
      if (gitArgs[0] === "rev-parse" && gitArgs[1] === "refs/remotes/origin/main") return sourceSha;
      throw new Error(`unexpected git call: ${gitArgs.join(" ")}`);
    };
    return { git, calls };
  };
  try {
    for (const [name, fixture, message] of [
      ["STALE_REMOTE_TRACKING_REF", { head: sourceSha, fresh: "b".repeat(40) }, /freshly fetched protected main/],
      ["FETCH_FAILURE", { fetchFailure: true }, /Fresh protected-main fetch failed/],
      ["HEAD_BEHIND_REMOTE", { head: sourceSha, fresh: "b".repeat(40) }, /freshly fetched protected main/],
      ["SOURCE_SHA_REBINDING", { head: "b".repeat(40), fresh: "b".repeat(40) }, /freshly fetched protected main/],
    ]) {
      const { git, calls } = run(fixture);
      assert.throws(() => runCli(args, { git }), message, name);
      assert.equal(fs.existsSync(output), false, `${name} wrote authorization`);
      assert.equal(calls.some(([command, ref]) => command === "rev-parse" && ref === "refs/remotes/origin/main"), false, `${name} consulted stale tracking ref`);
    }
    const valid = readFreshProtectedMainIdentity({ run: run().git });
    assert.deepEqual(valid, { fetchSucceeded: true, freshRemoteMainSha: sourceSha, headSha: sourceSha });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
