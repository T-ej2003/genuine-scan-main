import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  assertStageBDeploymentIdentity,
  assertStageBProtectedCheckoutMatchesDeploymentIdentity,
  assertStageBProtectedMainCheckout,
  assertStageBCanonicalRepositoryUrl,
  assertStageBToolingCheckout,
  buildStageBProtectedMainCheckoutEvidence,
  readAuthenticatedGitHubProtectedMainIdentity,
  readStageBProtectedMainCheckoutFromGitHub,
  readStageBProtectedMainCheckout,
  STAGE_B_PROTECTED_CHECKOUT_FIELDS,
  STAGE_B_PROTECTED_CHECKOUT_REPOSITORY_STATE_FIELDS,
} from "../aws/stage-b-deployment-identity.mjs";
import { classifyStageBImageReusePath, imageReuseCompatibility, STAGE_B_IMAGE_REUSE_RULES_VERSION } from "../aws/validate-stage-b-image-reuse.mjs";

const toolingSha = "c".repeat(40);
const imageReleaseSha = "a".repeat(40);
const evidenceSha = "b".repeat(64);

const cleanRepositoryState = { remoteDefaultBranch: "main", shallow: false, mergeInProgress: false, rebaseInProgress: false, cherryPickInProgress: false };
const cleanCheckout = (overrides = {}) => buildStageBProtectedMainCheckoutEvidence({
  mode: "production",
  toolingSha,
  currentHead: toolingSha,
  originMainHead: toolingSha,
  isAncestor: true,
  porcelainStatus: "",
  repositoryState: { ...cleanRepositoryState },
  ...overrides,
});
const git = (cwd, args) => execFileSync("git", args, { cwd, encoding: "utf8" }).trim();
function createProtectedMainFixture() {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-protected-checkout-"));
  git(cwd, ["init", "-q"]);
  git(cwd, ["config", "user.email", "stage-b-test@example.invalid"]);
  git(cwd, ["config", "user.name", "Stage B Test"]);
  fs.writeFileSync(path.join(cwd, "tracked.txt"), "clean\n");
  git(cwd, ["add", "tracked.txt"]);
  git(cwd, ["commit", "-qm", "initial"]);
  const head = git(cwd, ["rev-parse", "HEAD"]);
  git(cwd, ["remote", "add", "origin", "https://github.com/T-ej2003/genuine-scan-main.git"]);
  git(cwd, ["update-ref", "refs/remotes/origin/main", head]);
  git(cwd, ["symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main"]);
  return { cwd, head };
}
function withProtectedMainCheckout(callback) {
  const fixture = createProtectedMainFixture();
  try { return callback(fixture, readStageBProtectedMainCheckout({ cwd: fixture.cwd, fetchOriginMain: false, requireCanonicalRepository: true })); }
  finally { fs.rmSync(fixture.cwd, { recursive: true, force: true }); }
}
function assertExactError(fn, message) {
  assert.throws(fn, (error) => error instanceof Error && error.message === message);
}

const plan = (overrides = {}) => ({
  variables: {
    tooling_sha: { value: toolingSha },
    image_release_sha: { value: imageReleaseSha },
    canonical_image_evidence_sha256: { value: evidenceSha },
    ...overrides,
  },
});

test("two-SHA plan identity joins tooling, image release, and canonical evidence", () => {
  assert.deepEqual(assertStageBDeploymentIdentity({
    plan: plan(),
    expectedToolingSha: toolingSha,
    expectedImageReleaseSha: imageReleaseSha,
    expectedCanonicalImageEvidenceSha256: evidenceSha,
    imageEvidence: { imageReleaseSha },
  }), { toolingSha, imageReleaseSha, canonicalImageEvidenceSha256: evidenceSha });
});

test("image evidence does not require toolingSha", () => {
  assert.doesNotThrow(() => assertStageBDeploymentIdentity({ plan: plan(), imageEvidence: { imageReleaseSha } }));
});

test("legacy single release identity and missing joins fail closed", () => {
  assert.throws(() => assertStageBDeploymentIdentity({ plan: { variables: { release_sha: { value: imageReleaseSha } } } }), /tooling_sha/);
  assert.throws(() => assertStageBDeploymentIdentity({ plan: plan({ image_release_sha: { value: toolingSha } }), imageEvidence: { imageReleaseSha } }), /image_release_sha|image evidence/);
  assert.throws(() => assertStageBDeploymentIdentity({ plan: plan({ canonical_image_evidence_sha256: { value: "d".repeat(64) } }), expectedCanonicalImageEvidenceSha256: evidenceSha }), /canonical image-evidence/);
});

test("tooling checkout must equal the plan tooling identity", () => {
  const cleanMain = cleanCheckout();
  assert.doesNotThrow(() => assertStageBToolingCheckout(toolingSha, toolingSha, cleanMain));
  assert.throws(() => assertStageBToolingCheckout(toolingSha, imageReleaseSha, { ...cleanMain, currentHead: imageReleaseSha }), /tooling HEAD/);
});

test("protected-main checkout is exact, complete, and clean", () => {
  const valid = cleanCheckout();
  assert.doesNotThrow(() => assertStageBProtectedMainCheckout(valid));
  for (const [field, value, error] of [
    ["originMainHead", imageReleaseSha, /origin\/main/],
    ["isAncestor", false, /ancestry/],
    ["porcelainStatus", " M tracked", /tracked modifications/],
    ["porcelainStatus", "?? untracked", /untracked/],
  ]) assert.throws(() => assertStageBProtectedMainCheckout({ ...valid, [field]: value }), error);
  assert.throws(() => assertStageBProtectedMainCheckout({ ...valid, repositoryState: { ...valid.repositoryState, shallow: true } }), /shallow/);
  assert.throws(() => assertStageBProtectedMainCheckout({ ...valid, repositoryState: { ...valid.repositoryState, mergeInProgress: true } }), /merge/);
  assert.throws(() => assertStageBProtectedMainCheckout({ ...valid, repositoryState: { ...valid.repositoryState, rebaseInProgress: true } }), /rebase/);
  assert.throws(() => assertStageBProtectedMainCheckout({ ...valid, repositoryState: { ...valid.repositoryState, cherryPickInProgress: true } }), /cherry-pick/);
  assert.throws(() => assertStageBProtectedMainCheckout({ ...valid, repositoryState: { ...valid.repositoryState, remoteDefaultBranch: "develop" } }), /default branch/);
  assert.throws(() => assertStageBProtectedMainCheckout({ ...valid, originMainHead: undefined }), /unavailable/);
  assert.doesNotThrow(() => assertStageBProtectedMainCheckout({ ...valid, originMainHead: imageReleaseSha, mode: "review" }));
  assert.throws(() => assertStageBProtectedMainCheckout({ ...valid, mode: "unsupported" }), /mode/);
});

test("protected-main repository identity accepts only the canonical GitHub repository", () => {
  for (const remote of [
    "https://github.com/T-ej2003/genuine-scan-main",
    "https://github.com/T-ej2003/genuine-scan-main.git",
    "git@github.com:T-ej2003/genuine-scan-main",
    "git@github.com:T-ej2003/genuine-scan-main.git",
  ]) assert.doesNotThrow(() => assertStageBCanonicalRepositoryUrl(remote));
  for (const remote of [
    "https://github.com/attacker/genuine-scan-main.git",
    "https://github.com/T-ej2003/other-repository.git",
    "https://github.com/T-ej2003/genuine-scan-main-fork.git",
    "https://github.com.evil/T-ej2003/genuine-scan-main.git",
    "https://github.com/T-ej2003/genuine-scan-main.git.evil",
    "https://github.com@evil.example/T-ej2003/genuine-scan-main.git",
    "https://gitlab.com/T-ej2003/genuine-scan-main.git",
    "not a remote URL",
  ]) assert.throws(() => assertStageBCanonicalRepositoryUrl(remote), /canonical|malformed/);
});

test("authenticated GitHub protected-main lookup is fixed to repository and branch", () => {
  const calls = [];
  const identity = readAuthenticatedGitHubProtectedMainIdentity({
    expectedSourceSha: toolingSha,
    githubRun: (command, args) => { calls.push({ command, args }); return JSON.stringify({ name: "main", protected: true, commit: { sha: toolingSha } }); },
  });
  assert.deepEqual(identity, { repository: "T-ej2003/genuine-scan-main", branch: "main", protectedMainSha: toolingSha });
  assert.deepEqual(calls, [{ command: "gh", args: ["api", "repos/T-ej2003/genuine-scan-main/branches/main"] }]);
  for (const response of [
    {},
    { name: "main", commit: { sha: toolingSha } },
    { name: "main", protected: false, commit: { sha: toolingSha } },
    { name: "main", protected: null, commit: { sha: toolingSha } },
    { name: "main", protected: "true", commit: { sha: toolingSha } },
    { name: "main", protected: 1, commit: { sha: toolingSha } },
    { name: "develop", commit: { sha: toolingSha } },
    { name: "main", protected: true, commit: { sha: imageReleaseSha } },
    { name: "main", commit: { sha: "not-a-sha" } },
    [],
    "main",
  ]) assert.throws(() => readAuthenticatedGitHubProtectedMainIdentity({ expectedSourceSha: toolingSha, githubRun: () => JSON.stringify(response) }), /malformed|SHA|source/);
  assert.throws(() => readAuthenticatedGitHubProtectedMainIdentity({ expectedSourceSha: toolingSha, githubRun: () => { throw new Error("GitHub unavailable"); } }), /lookup failed/);
});

test("GitHub protected-main checkout ignores mutable Git remotes and transport overrides", () => {
  const fixture = createProtectedMainFixture();
  try {
    git(fixture.cwd, ["remote", "set-url", "origin", "git@github.com:T-ej2003/genuine-scan-main.git"]);
    git(fixture.cwd, ["config", "core.sshCommand", "ssh -o ProxyCommand=attacker-mirror"]);
    const previousSshCommand = process.env.GIT_SSH_COMMAND;
    process.env.GIT_SSH_COMMAND = "ssh -o ProxyCommand=attacker-mirror";
    const gitCalls = [];
    try {
      const checkout = readStageBProtectedMainCheckoutFromGitHub({
        cwd: fixture.cwd,
        expectedSourceSha: fixture.head,
      githubRun: (command, args) => JSON.stringify({ name: "main", protected: true, commit: { sha: fixture.head } }),
        run: (args) => { gitCalls.push(args); return git(fixture.cwd, args); },
      });
      assert.equal(checkout.currentHead, fixture.head);
      assert.equal(gitCalls.some((args) => args[0] === "fetch" || args[0] === "remote" || args[0] === "ls-remote"), false);
    } finally {
      if (previousSshCommand === undefined) delete process.env.GIT_SSH_COMMAND;
      else process.env.GIT_SSH_COMMAND = previousSshCommand;
    }
  } finally { fs.rmSync(fixture.cwd, { recursive: true, force: true }); }
});

test("strict protected-main validation is joined to the plan tooling identity", () => {
  const identity = { toolingSha };
  const checkout = cleanCheckout();
  assert.doesNotThrow(() => assertStageBProtectedCheckoutMatchesDeploymentIdentity({ protectedMainCheckout: checkout, deploymentIdentity: identity }));
  assert.throws(() => assertStageBProtectedCheckoutMatchesDeploymentIdentity({ protectedMainCheckout: { ...checkout, toolingSha: imageReleaseSha }, deploymentIdentity: identity }), /does not match the approved plan tooling SHA/);
  assert.throws(() => assertStageBProtectedCheckoutMatchesDeploymentIdentity({ protectedMainCheckout: { ...checkout, currentHead: imageReleaseSha }, deploymentIdentity: identity }), /tooling HEAD/);
  assert.throws(() => assertStageBProtectedCheckoutMatchesDeploymentIdentity({ protectedMainCheckout: undefined, deploymentIdentity: identity }), /requires protected-main/);
});

test("reader returns the complete validated checkout contract accepted by its strict consumer", () => {
  withProtectedMainCheckout(({ head }, checkout) => {
    assert.equal(checkout.toolingSha, head);
    assert.deepEqual(Object.keys(checkout).sort(), [...STAGE_B_PROTECTED_CHECKOUT_FIELDS].sort());
    assert.deepEqual(Object.keys(checkout.repositoryState).sort(), [...STAGE_B_PROTECTED_CHECKOUT_REPOSITORY_STATE_FIELDS].sort());
    assert.deepEqual(assertStageBProtectedCheckoutMatchesDeploymentIdentity({ protectedMainCheckout: checkout, deploymentIdentity: { toolingSha: head } }), checkout);
  });
});

test("validated, returned, and consumed checkout field sets remain identical", () => {
  const checkout = cleanCheckout();
  const validated = assertStageBProtectedMainCheckout(checkout);
  assert.deepEqual(Object.keys(validated).sort(), [...STAGE_B_PROTECTED_CHECKOUT_FIELDS].sort());
  assert.deepEqual(Object.keys(validated.repositoryState).sort(), [...STAGE_B_PROTECTED_CHECKOUT_REPOSITORY_STATE_FIELDS].sort());
  assert.deepEqual(Object.keys(checkout).sort(), Object.keys(validated).sort());
});

const protectedCheckoutFailures = [
  ["remote default branch not main", (checkout) => { checkout.repositoryState.remoteDefaultBranch = "develop"; }, "Stage B protected remote default branch is not main."],
  ["HEAD differs from origin/main", (checkout) => { checkout.originMainHead = "d".repeat(40); }, "Stage B tooling SHA does not match origin/main."],
  ["tooling SHA differs from plan identity", (checkout, head) => { checkout.toolingSha = imageReleaseSha; }, "Stage B protected-main checkout tooling SHA does not match the approved plan tooling SHA."],
  ["tracked modification", (checkout) => { checkout.porcelainStatus = " M tracked"; }, "Stage B tooling checkout has tracked modifications."],
  ["staged modification", (checkout) => { checkout.porcelainStatus = "M  staged"; }, "Stage B tooling checkout has tracked modifications."],
  ["tracked deletion", (checkout) => { checkout.porcelainStatus = " D deleted"; }, "Stage B tooling checkout has tracked modifications."],
  ["untracked file", (checkout) => { checkout.porcelainStatus = "?? untracked"; }, "Stage B tooling checkout contains an untracked file."],
  ["shallow history", (checkout) => { checkout.repositoryState.shallow = true; }, "Stage B tooling checkout has shallow or incomplete history."],
  ["merge in progress", (checkout) => { checkout.repositoryState.mergeInProgress = true; }, "Stage B tooling checkout has a merge in progress."],
  ["rebase in progress", (checkout) => { checkout.repositoryState.rebaseInProgress = true; }, "Stage B tooling checkout has a rebase in progress."],
  ["cherry-pick in progress", (checkout) => { checkout.repositoryState.cherryPickInProgress = true; }, "Stage B tooling checkout has a cherry-pick in progress."],
  ["missing required evidence field", (checkout) => { delete checkout.repositoryState; }, "Stage B protected checkout evidence is missing field repositoryState."],
];
for (const [name, mutate, message] of protectedCheckoutFailures) {
  test(`reader round-trip rejects ${name}`, () => {
    withProtectedMainCheckout(({ head }, actualCheckout) => {
      const mutated = structuredClone(actualCheckout);
      mutate(mutated, head);
      assertExactError(() => assertStageBProtectedCheckoutMatchesDeploymentIdentity({ protectedMainCheckout: mutated, deploymentIdentity: { toolingSha: head } }), message);
    });
  });
}

test("image reuse compatibility binds the reviewed tooling input tree and exact classification", () => {
  assert.equal(classifyStageBImageReusePath("scripts/aws/production-green-stage-b-image-evidence.mjs").imageAffecting, false);
  assert.equal(classifyStageBImageReusePath("backend/src/index.ts").imageAffecting, true);
  for (const file of ["Dockerfile", "backend/package-lock.json", "package-lock.json", "scripts/rls/sql/generated/policy.sql", "unknown/runtime-input.bin"]) assert.equal(classifyStageBImageReusePath(file).imageAffecting, true);
  assert.equal(classifyStageBImageReusePath("documents/security/rls-program/notes.md").imageAffecting, false);
  const changedFiles = ["scripts/plan-production-green-stage-b.mjs"];
  const classifiedChangedFiles = [{ file: changedFiles[0], category: "toolingOnly", imageAffecting: false }];
  const report = { schemaVersion: 2, imageReleaseSha, comparisonBaseSha: imageReleaseSha, toolingSha, comparisonHeadIdentity: "tooling-input-tree-sha256", toolingInputTreeSha256: "d".repeat(64), comparisonHeadSha256: "d".repeat(64), classificationRulesVersion: STAGE_B_IMAGE_REUSE_RULES_VERSION, classifiedChangedFiles, trustedToolingOnlyPaths: [], imageReuseCompatible: true };
  assert.equal(imageReuseCompatibility({ imageReleaseSha, toolingSha, changedFiles, currentHead: toolingSha, toolingInputTreeSha256: "d".repeat(64), reviewedReport: report }).imageReuseCompatible, true);
  assert.throws(() => imageReuseCompatibility({ imageReleaseSha, toolingSha, changedFiles, currentHead: toolingSha, toolingInputTreeSha256: "d".repeat(64), reviewedReport: { ...report, imageReleaseSha: toolingSha } }), /different image release/);
  assert.throws(() => imageReuseCompatibility({ imageReleaseSha, toolingSha, changedFiles, currentHead: toolingSha, toolingInputTreeSha256: "e".repeat(64), reviewedReport: report }), /different tooling input tree/);
  assert.throws(() => imageReuseCompatibility({ imageReleaseSha, toolingSha, changedFiles, currentHead: toolingSha, toolingInputTreeSha256: "d".repeat(64), reviewedReport: { ...report, comparisonBaseSha: toolingSha } }), /comparison base/);
  assert.throws(() => imageReuseCompatibility({ imageReleaseSha, toolingSha, changedFiles, currentHead: toolingSha, toolingInputTreeSha256: "d".repeat(64), reviewedReport: { ...report, classificationRulesVersion: "old" } }), /classification rules/);
  assert.throws(() => imageReuseCompatibility({ imageReleaseSha, toolingSha, changedFiles, currentHead: toolingSha, toolingInputTreeSha256: "d".repeat(64), reviewedReport: { ...report, classifiedChangedFiles: [] } }), /classification/);
  assert.throws(() => imageReuseCompatibility({ imageReleaseSha, toolingSha, changedFiles: ["backend/src/index.ts"], currentHead: toolingSha, toolingInputTreeSha256: "d".repeat(64), reviewedReport: report }), /classification/);
});
