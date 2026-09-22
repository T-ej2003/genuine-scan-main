import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createProductionGithubCommandRunner } from "./production-credential-source-contract.mjs";
import { writeStageBPrivateFileExclusive, writeStageBPrivateFileAtomicExclusive } from "./stage-b-artifact-contract.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";

const repository = "T-ej2003/genuine-scan-main";
const contracts = Object.freeze({
  provisioning: { workflow: ".github/workflows/provision-production-app-only-deployer.yml", artifact: "production-app-only-permissions", file: "app-only-permissions.json" },
  bootstrapAuthorization: { workflow: ".github/workflows/authorize-production-app-only-bootstrap.yml", artifact: "production-app-only-bootstrap-authorization", file: "app-only-bootstrap-authorization.json" },
  publication: { workflow: ".github/workflows/production-green-stage-b-images.yml", artifact: "production-green-stage-b-images", file: "stage-b-images.jsonl" },
  imageAuthorization: { workflow: ".github/workflows/produce-production-green-stage-b-state-reconciliation-image-authorization.yml", artifact: "production-green-stage-b-state-reconciliation-image-authorization", file: "image-authorization.json" },
  requirements: { workflow: ".github/workflows/produce-production-app-only-requirements.yml", artifact: "production-app-only-requirements", file: "app-only-requirements.json" },
  verifierPreparation: { workflow: ".github/workflows/prepare-production-app-only-verifier.yml", artifact: "production-app-only-verifier-preparation", file: "app-only-verifier-preparation.json" },
  compatibility: { workflow: ".github/workflows/verify-production-app-only-compatibility.yml", artifact: "production-app-only-compatibility", file: "app-only-compatibility.json" },
  preparation: { workflow: ".github/workflows/prepare-production-app-only-deployment.yml", artifact: "production-app-only-preparation", file: "app-only-preparation.json" },
});
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

export function parseAppOnlyArtifactReference(text) {
  assert.ok(typeof text === "string" && Buffer.byteLength(text) <= 2048, "Only compact artifact references are accepted");
  const value = JSON.parse(text);
  assert.deepEqual(Object.keys(value).sort(), ["sourceSha", "runId", "runAttempt", "artifactId", "artifactDigest", "fileSha256"].sort());
  assert.match(value.sourceSha || "", /^[a-f0-9]{40}$/);
  for (const field of ["runId", "runAttempt", "artifactId"]) assert.match(String(value[field]), /^[1-9][0-9]*$/);
  assert.match(value.artifactDigest || "", /^sha256:[a-f0-9]{64}$/); assert.match(value.fileSha256 || "", /^[a-f0-9]{64}$/);
  return value;
}

// Private, append-only snapshots. Existing atomic publication fsyncs file and
// directory; mutation adapters await this writer before calling AWS. Workflow
// always-upload remains necessary for runner-loss durability.
export function createAppOnlyEvidenceWriter({ repositoryRoot, sourceSha, preparationSha256, directory: requestedDirectory }) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/); assert.match(preparationSha256 || "", /^[a-f0-9]{64}$/);
  const requested = requestedDirectory || process.env.MSCQR_APP_ONLY_JOURNAL_DIR;
  const directory = requested ? path.resolve(requested) : fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-app-only-evidence-"));
  if (requested) {
    assert.ok(path.isAbsolute(requested) && !directory.startsWith(path.resolve(repositoryRoot) + path.sep), "Journal directory must be external to the checkout");
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  }
  fs.chmodSync(directory, 0o700);
  let sequence = 0, previousSha256 = null;
  const writeEvidence = (event) => {
    assert.ok(event && typeof event === "object" && !Array.isArray(event));
    assert.match(event.status || "", /^[A-Z][A-Z_]{1,79}$/);
    if (event.sourceSha !== undefined) assert.equal(event.sourceSha, sourceSha);
    if (event.preparationSha256 !== undefined) assert.equal(event.preparationSha256, preparationSha256);
    assert.ok(sequence < 100, "Unbounded deployment evidence");
    const body = { schemaVersion: 1, kind: "APP_ONLY_EXECUTION_JOURNAL", sourceSha, preparationSha256,
      sequence: sequence + 1, previousSha256, event };
    const evidenceSha256 = canonicalSha256(body);
    const bytes = Buffer.from(`${JSON.stringify({ ...body, evidenceSha256 })}\n`);
    assert.ok(bytes.length <= 1048576, "Oversized deployment evidence");
    const result = writeStageBPrivateFileAtomicExclusive({ filePath: path.join(directory, `${String(body.sequence).padStart(3, "0")}.json`), bytes, repositoryRoot });
    sequence++; previousSha256 = evidenceSha256;
    return result;
  };
  return { directory, writeEvidence };
}

// zipfile is the platform ZIP parser, not filesystem extraction. Exactly one
// regular member is returned through stdout; no archive path is ever created.
const readMember = `import io,sys,zipfile,stat
data=sys.stdin.buffer.read(8388609)
assert 0<len(data)<=8388608
assert data[-22:-18]==b'PK\\x05\\x06'
with zipfile.ZipFile(io.BytesIO(data)) as z:
 assert not z.comment
 members=z.infolist()
 assert len(members)==1
 m=members[0]
 assert m.filename==sys.argv[1] and m.orig_filename==m.filename and m.header_offset==0
 assert not m.is_dir() and not m.flag_bits&1
 assert stat.S_IFMT(m.external_attr>>16) in (0,stat.S_IFREG)
 assert 0<m.file_size<=1048576 and m.compress_type in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED)
 value=z.read(m)
 assert len(value)==m.file_size
 sys.stdout.buffer.write(value)
`;

export function readAppOnlyArtifactArchive(bytes, kind) {
  const contract = contracts[kind]; assert.ok(contract, "Unknown app-only artifact kind");
  assert.ok(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 8 * 1024 * 1024);
  return execFileSync("/usr/bin/python3", ["-c", readMember, contract.file], {
    input: bytes, timeout: 10000, maxBuffer: 1024 * 1024, stdio: ["pipe", "pipe", "pipe"],
  });
}

export function assertAppOnlyArtifactProvenance({ kind, reference, run, artifact }) {
  const contract = contracts[kind]; assert.ok(contract);
  assert.deepEqual(Object.keys(reference).sort(), ["sourceSha", "runId", "runAttempt", "artifactId", "artifactDigest", "fileSha256"].sort());
  assert.match(reference.sourceSha || "", /^[a-f0-9]{40}$/);
  for (const key of ["runId", "runAttempt", "artifactId"]) assert.match(String(reference[key]), /^[1-9][0-9]*$/);
  assert.match(reference.artifactDigest || "", /^sha256:[a-f0-9]{64}$/);
  assert.match(reference.fileSha256 || "", /^[a-f0-9]{64}$/);
  assert.equal(String(run.id), String(reference.runId));
  assert.equal(String(run.run_attempt), String(reference.runAttempt));
  assert.equal(run.repository?.full_name, repository); assert.equal(run.head_repository?.full_name, repository);
  assert.ok(Number.isSafeInteger(run.repository.id) && run.repository.id > 0);
  assert.equal(run.head_repository.id, run.repository.id);
  assert.equal(run.head_sha, reference.sourceSha); assert.equal(run.head_branch, "main");
  assert.equal(run.path, contract.workflow); assert.equal(run.event, "workflow_dispatch");
  assert.equal(run.status, "completed"); assert.equal(run.conclusion, "success");
  assert.equal(String(artifact.id), String(reference.artifactId)); assert.equal(artifact.name, contract.artifact);
  assert.equal(artifact.expired, false); assert.equal(artifact.digest, reference.artifactDigest);
  assert.equal(String(artifact.workflow_run?.id), String(reference.runId));
  assert.equal(artifact.workflow_run?.head_sha, reference.sourceSha);
  assert.equal(artifact.workflow_run?.head_repository_id, run.head_repository.id);
  assert.equal(artifact.workflow_run?.repository_id, run.repository.id);
  assert.ok(Number.isSafeInteger(artifact.size_in_bytes) && artifact.size_in_bytes > 0 && artifact.size_in_bytes <= 8 * 1024 * 1024);
  return true;
}

export function downloadAppOnlyArtifact({ kind, reference, repositoryRoot, githubRun = createProductionGithubCommandRunner() }) {
  // Validate compact inputs before constructing any API endpoint.
  assert.ok(contracts[kind]);
  for (const key of ["runId", "artifactId"]) assert.match(String(reference[key]), /^[1-9][0-9]*$/);
  const endpoint = `repos/${repository}/actions/runs/${reference.runId}`;
  const get = (url, flags = []) => JSON.parse(githubRun("gh", ["api", url, ...flags], { maxBuffer: 8 * 1024 * 1024 }));
  const run = get(endpoint);
  const readArtifact = () => {
    const pages = get(`${endpoint}/artifacts`, ["--paginate", "--slurp"]);
    assert.ok(Array.isArray(pages) && pages.length > 0 && pages.length <= 10);
    const artifacts = pages.flatMap((page) => page.artifacts);
    assert.equal(new Set(artifacts.map((artifact) => artifact.id)).size, artifacts.length);
    const matches = artifacts.filter((artifact) => artifact.name === contracts[kind].artifact);
    assert.equal(matches.length, 1, "Ambiguous or absent app-only artifact");
    return matches[0];
  };
  const artifact = readArtifact();
  assertAppOnlyArtifactProvenance({ kind, reference, run, artifact });
  const archive = Buffer.from(githubRun("gh", ["api", `repos/${repository}/actions/artifacts/${reference.artifactId}/zip`], { encoding: null, maxBuffer: 8 * 1024 * 1024 }));
  assert.equal(`sha256:${sha256(archive)}`, reference.artifactDigest);
  const bytes = readAppOnlyArtifactArchive(archive, kind);
  assert.equal(sha256(bytes), reference.fileSha256);
  assertAppOnlyArtifactProvenance({ kind, reference, run: get(endpoint), artifact: readArtifact() });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-app-only-consumer-"));
  fs.chmodSync(directory, 0o700);
  const file = writeStageBPrivateFileExclusive({ filePath: path.join(directory, contracts[kind].file), bytes, repositoryRoot });
  return { ...file, bytes, reference: structuredClone(reference), run, artifact };
}
