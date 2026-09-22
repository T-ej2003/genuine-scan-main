import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { authenticateAppOnlyImages, authenticateAppOnlySessionRiskSource, APP_ONLY_SESSION_RISK_CONTRACT } from "../aws/production-app-only-images.mjs";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";

const sourceSha = "fbc47fd83699403b8708f87d757e552d5bc02dd8", imageReleaseSha = "bcec05a421bff28eb2216f399d0a9e7cd2389d5e";
test("candidate source must contain the reviewed session-risk fallback, not the old zero-threshold implementation", () => {
  assert.deepEqual(authenticateAppOnlySessionRiskSource(process.cwd(), imageReleaseSha), APP_ONLY_SESSION_RISK_CONTRACT);
  assert.throws(() => authenticateAppOnlySessionRiskSource(process.cwd(), "7e93853e6c48ad3020915f551ef89155825ae403"));
  assert.throws(() => authenticateAppOnlySessionRiskSource(process.cwd(), "main:attacker"));
});
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const zip = (filename, bytes) => execFileSync("python3", ["-c", "import io,sys,zipfile\nb=io.BytesIO()\nwith zipfile.ZipFile(b,'w') as z:z.writestr(sys.argv[1],sys.stdin.buffer.read())\nsys.stdout.buffer.write(b.getvalue())", filename], { input: bytes });
function fixture() {
  const { authorization, now } = makeCanonicalImageAuthorization({ sourceSha: imageReleaseSha, imageReleaseSha });
  const publicationBytes = Buffer.from(authorization.imageEvidence.images.map(({ service, repository, tag, digest }) => JSON.stringify({ service, repository,
    image_uri: `${APP_ONLY.account}.dkr.ecr.${APP_ONLY.region}.amazonaws.com/${repository}:${tag}`, image_tag: tag,
    image_digest: digest, image_ref: `${APP_ONLY.account}.dkr.ecr.${APP_ONLY.region}.amazonaws.com/${repository}@${digest}` })).join("\n") + "\n");
  // Preserve canonical producer record order, which is independent of sorted evidence.
  const order = ["backend", "worker", "rls-executor", "rls-canary"];
  const records = publicationBytes.toString().trim().split("\n").map(JSON.parse).sort((a, b) => order.indexOf(a.service) - order.indexOf(b.service));
  const bytes = Buffer.from(records.map(JSON.stringify).join("\n") + "\n");
  assert.equal(hash(bytes), authorization.imageEvidence.canonicalArtifactSha256);
  const make = (runId, artifactId, artifactName, workflow, filename, contents, name) => {
    const archive = zip(filename, contents);
    const reference = { sourceSha: imageReleaseSha, runId, runAttempt: "1", artifactId, artifactDigest: `sha256:${hash(archive)}`, fileSha256: hash(contents) };
    const repo = { full_name: "T-ej2003/genuine-scan-main", id: 9 };
    const run = { id: Number(runId), run_attempt: 1, workflow_id: 401, repository: repo, head_repository: repo,
      head_sha: imageReleaseSha, head_branch: "main", path: workflow, name, event: "workflow_dispatch", status: "completed", conclusion: "success" };
    const artifact = { id: Number(artifactId), name: artifactName, digest: reference.artifactDigest, expired: false, size_in_bytes: archive.length,
      workflow_run: { id: Number(runId), head_sha: imageReleaseSha, repository_id: 9, head_repository_id: 9 } };
    return { reference, archive, run, artifact };
  };
  const publication = make(authorization.workflowRunId, "501", "production-green-stage-b-images", ".github/workflows/production-green-stage-b-images.yml", "stage-b-images.jsonl", bytes, "Production Green Stage B Images");
  const auth = make("777", "888", "production-green-stage-b-state-reconciliation-image-authorization", ".github/workflows/produce-production-green-stage-b-state-reconciliation-image-authorization.yml", "image-authorization.json", Buffer.from(JSON.stringify(authorization)), "Image authorization");
  const githubRun = (command, args) => {
    assert.equal(command, "gh");
    const item = args[1].includes(`/runs/${publication.reference.runId}`) || args[1].includes("/artifacts/501/") ? publication : auth;
    return args[1].endsWith("/zip") ? item.archive : JSON.stringify(args[1].endsWith("/artifacts?per_page=100") ? [{ total_count: 1, artifacts: [item.artifact] }] : item.run);
  };
  const calls = [];
  const run = (args) => {
    calls.push(args);
    if (args[0] === "sts") return JSON.stringify({ Account: APP_ONLY.account });
    assert.equal(args[0], "ecr");
    if (args[1] === "describe-repositories") return JSON.stringify({ repositories: authorization.imageEvidence.repositories.filter((r) => r.repositoryName === args[args.indexOf("--repository-names") + 1]) });
    assert.equal(args[1], "describe-images");
    const tag = args[args.indexOf("--image-ids") + 1].slice("imageTag=".length);
    const repository = args[args.indexOf("--repository-name") + 1];
    return JSON.stringify({ imageDetails: authorization.imageEvidence.images.filter((i) => i.tag === tag && i.repository === repository).map((i) => ({ imageDigest: i.digest, imagePushedAt: now })) });
  };
  return { sourceSha, candidateDigest: authorization.backendDigest, publicationReference: publication.reference,
    authorizationReference: auth.reference, repositoryRoot: process.cwd(), githubRun, run, now, verifySignature: () => true, calls };
}
test("app images retain signed source identity and independently prove current-source reuse", () => {
  const input = fixture(), evidence = authenticateAppOnlyImages(input);
  assert.equal(evidence.signedEvidenceSourceSha, imageReleaseSha);
  assert.equal(evidence.sourceSha, sourceSha); assert.equal(evidence.imageImpact.imageReuseCompatible, true);
  assert.equal(evidence.images.length, 4);
  assert.ok(input.calls.every(([service]) => ["sts", "ecr"].includes(service)));
});
test("image authentication rejects wrong signature, candidate, publication and expired signed evidence", () => {
  const input = fixture();
  assert.throws(() => authenticateAppOnlyImages({ ...input, verifySignature: () => false }), /signature/i);
  assert.throws(() => authenticateAppOnlyImages({ ...input, candidateDigest: `sha256:${"f".repeat(64)}` }));
  assert.throws(() => authenticateAppOnlyImages({ ...input, publicationReference: { ...input.publicationReference, fileSha256: "f".repeat(64) } }));
  assert.throws(() => authenticateAppOnlyImages({ ...input, now: new Date(Date.parse(input.now) + 25 * 3600000).toISOString() }), /stale/);
  assert.throws(() => authenticateAppOnlyImages({ ...input, run: (args) => args[1] === "describe-images" ? JSON.stringify({ imageDetails: [{ imageDigest: `sha256:${"f".repeat(64)}`, imagePushedAt: input.now }] }) : input.run(args) }));
});
