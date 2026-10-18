import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { readAppOnlyArtifactArchive, assertAppOnlyArtifactProvenance, downloadAppOnlyArtifact,
  parseAppOnlyVerifierDiagnosticReference,
  downloadAppOnlyVerifierJournals, createAppOnlyEvidenceWriter } from "../aws/production-app-only-artifacts.mjs";

const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const file = "app-only-requirements.json", source = "a".repeat(40);
const archive = (members) => execFileSync("python3", ["-c", `import io,json,sys,zipfile,warnings
warnings.simplefilter('ignore')
b=io.BytesIO()
with zipfile.ZipFile(b,'w',compression=zipfile.ZIP_DEFLATED) as z:
 for m in json.load(sys.stdin):
  i=zipfile.ZipInfo(m['name']);i.create_system=3;i.external_attr=m.get('mode',33152)<<16
  z.writestr(i,m.get('value','{}'),compress_type=zipfile.ZIP_DEFLATED)
sys.stdout.buffer.write(b.getvalue())`], { input: JSON.stringify(members), timeout: 10000, maxBuffer: 2 * 1024 * 1024 });
const fixture = (bytes) => {
  const reference = { sourceSha: source, runId: "123", runAttempt: "1", artifactId: "456", artifactDigest: `sha256:${hash(bytes)}`, fileSha256: hash(Buffer.from("{}")) };
  const run = { id: 123, run_attempt: 1, repository: { id: 9, full_name: "T-ej2003/genuine-scan-main" },
    head_repository: { id: 9, full_name: "T-ej2003/genuine-scan-main" }, head_sha: source, head_branch: "main",
    path: ".github/workflows/produce-production-app-only-requirements.yml", event: "workflow_dispatch", status: "completed", conclusion: "success" };
  const artifact = { id: 456, name: "production-app-only-requirements", expired: false, digest: reference.artifactDigest,
    size_in_bytes: bytes.length, workflow_run: { id: 123, head_sha: source, head_repository_id: 9, repository_id: 9 } };
  return { kind: "requirements", reference, run, artifact };
};
test("artifact provenance rejects every run, source and artifact substitution", () => {
  const original = fixture(archive([{ name: file }]));
  assert.equal(assertAppOnlyArtifactProvenance(original), true);
  for (const [part, fields] of Object.entries({ run: ["id", "run_attempt", "head_sha", "head_branch", "path", "event", "status", "conclusion", "repository", "head_repository"],
    artifact: ["id", "name", "expired", "digest", "size_in_bytes", "workflow_run"] })) {
    for (const field of fields) {
      const changed = structuredClone(original); changed[part][field] = "substituted";
      assert.throws(() => assertAppOnlyArtifactProvenance(changed), `${part}.${field}`);
    }
  }
});
test("ZIP closure rejects traversal, absolute, unicode, links, directories, duplicates, extras and oversized members", () => {
  assert.equal(readAppOnlyArtifactArchive(archive([{ name: file }]), "requirements").toString(), "{}");
  for (const members of [[], [{ name: "../" + file }], [{ name: "/" + file }], [{ name: "app-only-requiremеnts.json" }],
    [{ name: file, mode: 0o120777 }], [{ name: file, mode: 0o040700 }], [{ name: file }, { name: "extra" }],
    [{ name: file }, { name: file }], [{ name: file, value: "" }], [{ name: file, value: "x".repeat(1048577) }]]) {
    assert.throws(() => readAppOnlyArtifactArchive(archive(members), "requirements"));
  }
  assert.throws(() => readAppOnlyArtifactArchive(Buffer.from("malformed"), "requirements"));
});

test("canonical security inventory supports the bounded private 8 MiB contract", () => {
  const canonical = "x".repeat(1048577);
  assert.equal(readAppOnlyArtifactArchive(archive([{ name: "security-rebaseline-canonical.json", value: canonical }]), "securityRebaselineCanonical").length, canonical.length);
});
test("canonical security inventory provenance requires private repository access", () => {
  const input = fixture(archive([{ name: file }])); input.kind = "securityRebaselineCanonical"; input.reference.fileSha256 = hash(Buffer.from("{}"));
  input.run.path = ".github/workflows/produce-production-app-only-requirements.yml"; input.artifact.name = "production-security-rebaseline-canonical";
  assert.throws(() => assertAppOnlyArtifactProvenance(input)); input.run.repository.private = true; input.run.head_repository.private = true;
  assert.equal(assertAppOnlyArtifactProvenance(input), true);
});
test("preparation artifacts have exact filenames and private source-bound workflow provenance", () => {
  const cases = [
    ["securityRebaselineRequirements", "production-security-rebaseline-requirements", "app-only-requirements.json"],
    ["securityRebaselineCanonical", "production-security-rebaseline-canonical", "security-rebaseline-canonical.json"],
    ["securityRebaselinePreparation", "production-security-rebaseline-preparation", "preparation-manifest.json"],
    ["securityRebaselineImagePublication", "production-security-rebaseline-image-publication", "production-green-backend-image.jsonl"],
  ];
  for (const [kind, name, member] of cases) {
    const bytes = archive([{ name: member }]);
    assert.equal(readAppOnlyArtifactArchive(bytes, kind).toString(), "{}");
    const input = fixture(bytes);
    input.kind = kind; input.run.path = ".github/workflows/prepare-production-security-rebaseline.yml";
    input.run.repository.private = true; input.run.head_repository.private = true;
    input.artifact.name = name; input.artifact.digest = `sha256:${hash(bytes)}`;
    input.reference.artifactDigest = input.artifact.digest;
    assert.equal(assertAppOnlyArtifactProvenance(input), true, kind);
    input.run.repository.private = false;
    assert.throws(() => assertAppOnlyArtifactProvenance(input), `${kind} must remain private`);
  }
});
test("download authenticates and consumes the same immutable bytes in private storage", () => {
  const bytes = archive([{ name: file }]), input = fixture(bytes), calls = [];
  const githubRun = (command, args) => {
    calls.push(args[1]); assert.equal(command, "gh");
    if (args[1].endsWith("/zip")) return bytes;
    if (args[1].endsWith("/artifacts?per_page=100")) return JSON.stringify([{ total_count: 1, artifacts: [input.artifact] }]);
    return JSON.stringify(input.run);
  };
  const result = downloadAppOnlyArtifact({ ...input, githubRun, repositoryRoot: process.cwd() });
  try {
    assert.equal(result.bytes.toString(), "{}");
    assert.equal(fs.statSync(result.path).mode & 0o777, 0o600);
    assert.equal(fs.statSync(path.dirname(result.path)).mode & 0o777, 0o700);
    assert.equal(calls.filter((url) => url.endsWith("/runs/123")).length, 2);
    assert.ok(calls.includes("repos/T-ej2003/genuine-scan-main/actions/artifacts/456/zip"));
  } finally { fs.unlinkSync(result.path); fs.rmdirSync(path.dirname(result.path)); }
  assert.throws(() => downloadAppOnlyArtifact({ ...input, githubRun, reference: { ...input.reference, fileSha256: "f".repeat(64) } }));
  assert.throws(() => downloadAppOnlyArtifact({ ...input, githubRun: (command, args) => args[1].endsWith("/zip") ? Buffer.from("substitute") : githubRun(command, args) }));
});

test("failed protected verifier journals require exact run, ZIP and both chain tips", () => {
  const members = ["registration", "permission"].flatMap((kind) => [1, 2, 3].map((sequence) => ({
    name: `mscqr-app-only-evidence-${kind}/00${sequence}.json`,
    value: JSON.stringify({ event: { kind: kind === "registration" ? "APP_ONLY_VERIFIER_REGISTRATION" : "APP_ONLY_PERMISSION_RESULT" },
      evidenceSha256: (kind === "registration" ? "a" : "b").repeat(64) }),
  })));
  const bytes = archive(members), reference = { sourceSha: source, runId: "123", artifactId: "456",
    artifactDigest: `sha256:${hash(bytes)}`, registrationJournalSha256: "a".repeat(64), permissionJournalSha256: "b".repeat(64) };
  const run = { id: 123, run_attempt: 1, repository: { id: 9, full_name: "T-ej2003/genuine-scan-main" },
    head_repository: { id: 9 }, head_sha: source, head_branch: "main",
    path: ".github/workflows/verify-production-app-only-compatibility.yml", event: "workflow_dispatch",
    status: "completed", conclusion: "failure" };
  const artifact = { id: 456, name: "production-app-only-verifier-journals", expired: false, digest: reference.artifactDigest,
    size_in_bytes: bytes.length, workflow_run: { id: 123, head_sha: source, head_repository_id: 9, repository_id: 9 } };
  const githubRun = (_, args) => args[1].endsWith("/zip") ? bytes
    : args[1].endsWith("/artifacts?per_page=100") ? JSON.stringify([{ total_count: 1, artifacts: [artifact] }]) : JSON.stringify(run);
  const result = downloadAppOnlyVerifierJournals({ reference, githubRun });
  assert.equal(result.registration.length, 3); assert.equal(result.permission.length, 3);
  for (const mutate of [
    () => ({ reference: { ...reference, sourceSha: "c".repeat(40) }, githubRun }),
    () => ({ reference: { ...reference, registrationJournalSha256: "c".repeat(64) }, githubRun }),
    () => ({ reference, githubRun: (_, args) => args[1].endsWith("/zip") ? Buffer.from("substitute") : githubRun(_, args) }),
    () => ({ reference, githubRun: (_, args) => args[1].endsWith("/zip") ? bytes
      : args[1].endsWith("/artifacts?per_page=100") ? JSON.stringify([{ total_count: 1, artifacts: [artifact] }])
        : JSON.stringify({ ...run, conclusion: "success" }) }),
    () => ({ reference, githubRun: (_, args) => args[1].endsWith("/zip") ? bytes
      : args[1].endsWith("/artifacts?per_page=100") ? JSON.stringify([{ total_count: 1,
        artifacts: [{ ...artifact, workflow_run: { ...artifact.workflow_run, head_repository_id: 10 } }] }]) : JSON.stringify(run) }),
  ]) assert.throws(() => downloadAppOnlyVerifierJournals(mutate()));
  const extra = archive([...members, { name: "extra.json" }]);
  assert.throws(() => downloadAppOnlyVerifierJournals({ reference: { ...reference, artifactDigest: `sha256:${hash(extra)}` },
    githubRun: (_, args) => args[1].endsWith("/zip") ? extra
      : args[1].endsWith("/artifacts?per_page=100") ? JSON.stringify([{ total_count: 1,
        artifacts: [{ ...artifact, digest: `sha256:${hash(extra)}` }] }]) : JSON.stringify(run) }));
});

test("failed verifier diagnostic requires the third exact execution journal and task identity", () => {
  const kinds = { registration: "APP_ONLY_VERIFIER_REGISTRATION", permission: "APP_ONLY_PERMISSION_RESULT",
    execution: "APP_ONLY_VERIFIER_EXECUTION" };
  const taskArn = `arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/${"a".repeat(32)}`;
  const members = Object.entries(kinds).flatMap(([folder, kind]) => [1, 2, 3].map((sequence) => ({
    name: `mscqr-app-only-evidence-${folder}/00${sequence}.json`, value: JSON.stringify({
      event: { kind, ...(folder === "execution" && sequence > 1 ? { taskArn } : {}) },
      evidenceSha256: ({ registration: "a", permission: "b", execution: "c" })[folder].repeat(64) }),
  })));
  const bytes = archive(members);
  const reference = { sourceSha: source, runId: "123", artifactId: "456", artifactDigest: `sha256:${hash(bytes)}`,
    registrationJournalSha256: "a".repeat(64), permissionJournalSha256: "b".repeat(64),
    executionJournalSha256: "c".repeat(64), taskArn };
  const run = { id: 123, run_attempt: 1, repository: { id: 9, full_name: "T-ej2003/genuine-scan-main" },
    head_repository: { id: 9 }, head_sha: source, head_branch: "main",
    path: ".github/workflows/verify-production-app-only-compatibility.yml", event: "workflow_dispatch",
    status: "completed", conclusion: "failure" };
  const artifact = { id: 456, name: "production-app-only-verifier-journals", expired: false, digest: reference.artifactDigest,
    size_in_bytes: bytes.length, workflow_run: { id: 123, head_sha: source, head_repository_id: 9, repository_id: 9 } };
  const githubRun = (_, args) => args[1].endsWith("/zip") ? bytes
    : args[1].endsWith("/artifacts?per_page=100") ? JSON.stringify([{ total_count: 1, artifacts: [artifact] }]) : JSON.stringify(run);
  assert.deepEqual(parseAppOnlyVerifierDiagnosticReference(JSON.stringify(reference)), reference);
  assert.equal(downloadAppOnlyVerifierJournals({ reference, includeExecution: true, githubRun }).execution.length, 3);
  for (const change of [
    { ...reference, executionJournalSha256: "d".repeat(64) },
    { ...reference, taskArn: taskArn.replace(/a{32}$/, "f".repeat(32)) },
    { ...reference, sourceSha: "f".repeat(40) },
  ]) assert.throws(() => downloadAppOnlyVerifierJournals({ reference: change, includeExecution: true, githubRun }));
  assert.throws(() => parseAppOnlyVerifierDiagnosticReference(JSON.stringify({ ...reference, extra: true })));
  assert.throws(() => downloadAppOnlyVerifierJournals({ reference, githubRun }), "Diagnostic ZIP cannot pass legacy six-entry contract");
});

test("artifact expiry, replacement and run rerun during download fail before materialization", () => {
  for (const attack of ["expired", "replacement", "rerun", "duplicate", "deleted"]) {
    const bytes = archive([{ name: file }]), input = fixture(bytes);
    let downloaded = false;
    const githubRun = (_command, args) => {
      if (args[1].endsWith("/zip")) { downloaded = true; return bytes; }
      if (args[1].endsWith("/artifacts?per_page=100")) {
        const artifact = structuredClone(input.artifact);
        if (downloaded && attack === "expired") artifact.expired = true;
        if (downloaded && attack === "replacement") artifact.id++;
        const artifacts = downloaded && attack === "deleted" ? [] : [artifact];
        if (downloaded && attack === "duplicate") artifacts.push({ ...artifact, id: 789 });
        return JSON.stringify([{ total_count: artifacts.length, artifacts }]);
      }
      return JSON.stringify({ ...input.run, run_attempt: downloaded && attack === "rerun" ? 2 : 1 });
    };
    assert.throws(() => downloadAppOnlyArtifact({ ...input, githubRun }), attack);
  }
});

test("durable journal is private, source-bound, hash-chained and never overwrites a substituted destination", () => {
  const preparationSha256 = "b".repeat(64);
  const writer = createAppOnlyEvidenceWriter({ repositoryRoot: process.cwd(), sourceSha: source, preparationSha256 });
  try {
    writer.writeEvidence({ status: "PRE_MUTATION" });
    writer.writeEvidence({ status: "REGISTRATION_INTENT" });
    const files = fs.readdirSync(writer.directory).sort();
    assert.deepEqual(files, ["001.json", "002.json"]);
    assert.equal(fs.statSync(writer.directory).mode & 0o777, 0o700);
    const read = (file) => JSON.parse(fs.readFileSync(path.join(writer.directory, file), "utf8"));
    assert.equal(read(files[1]).previousSha256, read(files[0]).evidenceSha256);
    for (const file of files) assert.equal(fs.statSync(path.join(writer.directory, file)).mode & 0o777, 0o600);
    assert.throws(() => writer.writeEvidence({ status: "PRE_MUTATION", preparationSha256: "c".repeat(64) }));
    assert.throws(() => writer.writeEvidence({ status: "PRE_MUTATION", sourceSha: "c".repeat(40) }));
    fs.symlinkSync(path.join(writer.directory, files[0]), path.join(writer.directory, "003.json"));
    assert.throws(() => writer.writeEvidence({ status: "ACTIVATION_INTENT" }));
    assert.equal(read(files[0]).event.status, "PRE_MUTATION");
  } finally {
    for (const file of fs.readdirSync(writer.directory)) fs.unlinkSync(path.join(writer.directory, file));
    fs.rmdirSync(writer.directory);
  }
});
