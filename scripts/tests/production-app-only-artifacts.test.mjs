import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { readAppOnlyArtifactArchive, assertAppOnlyArtifactProvenance, downloadAppOnlyArtifact, createAppOnlyEvidenceWriter } from "../aws/production-app-only-artifacts.mjs";

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
test("download authenticates and consumes the same immutable bytes in private storage", () => {
  const bytes = archive([{ name: file }]), input = fixture(bytes), calls = [];
  const githubRun = (command, args) => {
    calls.push(args[1]); assert.equal(command, "gh");
    if (args[1].endsWith("/zip")) return bytes;
    if (args[1].endsWith("/artifacts")) return JSON.stringify([{ artifacts: [input.artifact] }]);
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

test("artifact expiry, replacement and run rerun during download fail before materialization", () => {
  for (const attack of ["expired", "replacement", "rerun", "duplicate", "deleted"]) {
    const bytes = archive([{ name: file }]), input = fixture(bytes);
    let downloaded = false;
    const githubRun = (_command, args) => {
      if (args[1].endsWith("/zip")) { downloaded = true; return bytes; }
      if (args[1].endsWith("/artifacts")) {
        const artifact = structuredClone(input.artifact);
        if (downloaded && attack === "expired") artifact.expired = true;
        if (downloaded && attack === "replacement") artifact.id++;
        const artifacts = downloaded && attack === "deleted" ? [] : [artifact];
        if (downloaded && attack === "duplicate") artifacts.push({ ...artifact, id: 789 });
        return JSON.stringify([{ artifacts }]);
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
