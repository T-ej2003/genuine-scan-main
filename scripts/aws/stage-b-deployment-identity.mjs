import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

const SHA_PATTERN = /^[a-f0-9]{40}$/;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/;

export const STAGE_B_DEPLOYMENT_IDENTITY_SCHEMA_VERSION = 1;
export const STAGE_B_PLAN_IDENTITY_VARIABLES = Object.freeze({
  toolingSha: "tooling_sha",
  imageReleaseSha: "image_release_sha",
  canonicalImageEvidenceSha256: "canonical_image_evidence_sha256",
});
export const STAGE_B_PROTECTED_CHECKOUT_FIELDS = Object.freeze([
  "mode",
  "toolingSha",
  "currentHead",
  "originMainHead",
  "isAncestor",
  "porcelainStatus",
  "repositoryState",
]);
export const STAGE_B_PROTECTED_CHECKOUT_REPOSITORY_STATE_FIELDS = Object.freeze([
  "remoteDefaultBranch",
  "shallow",
  "mergeInProgress",
  "rebaseInProgress",
  "cherryPickInProgress",
]);
export const STAGE_B_CANONICAL_REPOSITORY = "T-ej2003/genuine-scan-main";

function requireSha(value, label) {
  if (!SHA_PATTERN.test(String(value || ""))) throw new Error(`${label} must be a full 40-character commit SHA.`);
  return value;
}

export function assertStageBCanonicalRepositoryUrl(remoteUrl) {
  if (typeof remoteUrl !== "string" || remoteUrl.trim() !== remoteUrl || !remoteUrl) throw new Error("Stage B protected remote URL is malformed.");
  const approved = remoteUrl === "https://github.com/T-ej2003/genuine-scan-main"
    || remoteUrl === "https://github.com/T-ej2003/genuine-scan-main.git"
    || remoteUrl === "git@github.com:T-ej2003/genuine-scan-main"
    || remoteUrl === "git@github.com:T-ej2003/genuine-scan-main.git";
  if (!approved) throw new Error("Stage B protected remote is not the canonical production repository.");
  return STAGE_B_CANONICAL_REPOSITORY;
}

function requireDigest(value, label) {
  if (!DIGEST_PATTERN.test(String(value || ""))) throw new Error(`${label} must be a 64-character SHA256 digest.`);
  return value;
}

function planVariable(plan, name) {
  const value = plan?.variables?.[name]?.value;
  if (typeof value !== "string") throw new Error(`Stage B plan is missing required identity variable ${name}.`);
  return value;
}

export function assertStageBDeploymentIdentityValues({ toolingSha, imageReleaseSha, canonicalImageEvidenceSha256, expectedToolingSha, expectedImageReleaseSha, expectedCanonicalImageEvidenceSha256, imageEvidence } = {}) {
  requireSha(toolingSha, "toolingSha");
  requireSha(imageReleaseSha, "imageReleaseSha");
  requireDigest(canonicalImageEvidenceSha256, "canonicalImageEvidenceSha256");
  if (expectedToolingSha !== undefined && toolingSha !== expectedToolingSha) throw new Error("Stage B tooling SHA does not match the protected source.");
  if (expectedImageReleaseSha !== undefined && imageReleaseSha !== expectedImageReleaseSha) throw new Error("Stage B image release SHA does not match the authenticated image authorization.");
  if (expectedCanonicalImageEvidenceSha256 !== undefined && canonicalImageEvidenceSha256 !== expectedCanonicalImageEvidenceSha256) throw new Error("Stage B canonical image-evidence digest does not match the authenticated image authorization.");
  if (imageEvidence && imageEvidence.imageReleaseSha !== imageReleaseSha) throw new Error("Stage B image evidence imageReleaseSha does not match the authenticated image authorization.");
  return Object.freeze({ toolingSha, imageReleaseSha, canonicalImageEvidenceSha256 });
}

export function assertStageBDeploymentIdentity({
  plan,
  expectedToolingSha,
  expectedImageReleaseSha,
  expectedCanonicalImageEvidenceSha256,
  imageEvidence,
} = {}) {
  return assertStageBDeploymentIdentityValues({
    toolingSha: planVariable(plan, STAGE_B_PLAN_IDENTITY_VARIABLES.toolingSha),
    imageReleaseSha: planVariable(plan, STAGE_B_PLAN_IDENTITY_VARIABLES.imageReleaseSha),
    canonicalImageEvidenceSha256: planVariable(plan, STAGE_B_PLAN_IDENTITY_VARIABLES.canonicalImageEvidenceSha256),
    expectedToolingSha,
    expectedImageReleaseSha,
    expectedCanonicalImageEvidenceSha256,
    imageEvidence,
  });
}

function requireExactFields(value, fields, label) {
  if (!value || typeof value !== "object") throw new Error(`Stage B ${label} evidence is missing.`);
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  const missing = expected.filter((field) => !actual.includes(field));
  const extra = actual.filter((field) => !expected.includes(field));
  if (missing.length) throw new Error(`Stage B ${label} evidence is missing field ${missing[0]}.`);
  if (extra.length) throw new Error(`Stage B ${label} evidence has unsupported field ${extra[0]}.`);
}

export function buildStageBProtectedMainCheckoutEvidence(input = {}) {
  requireExactFields(input, STAGE_B_PROTECTED_CHECKOUT_FIELDS, "protected checkout");
  requireExactFields(input.repositoryState, STAGE_B_PROTECTED_CHECKOUT_REPOSITORY_STATE_FIELDS, "protected checkout repository state");
  return Object.freeze({
    ...input,
    repositoryState: Object.freeze({ ...input.repositoryState }),
  });
}

export function assertStageBProtectedMainCheckout(input = {}) {
  const evidence = buildStageBProtectedMainCheckoutEvidence(input);
  const { toolingSha, currentHead, originMainHead, isAncestor, porcelainStatus, repositoryState, mode } = evidence;
  requireSha(toolingSha, "toolingSha");
  if (currentHead !== toolingSha) throw new Error("Stage B tooling HEAD does not match toolingSha.");
  if (repositoryState.mergeInProgress) throw new Error("Stage B tooling checkout has a merge in progress.");
  if (repositoryState.rebaseInProgress) throw new Error("Stage B tooling checkout has a rebase in progress.");
  if (repositoryState.cherryPickInProgress) throw new Error("Stage B tooling checkout has a cherry-pick in progress.");
  if (porcelainStatus) {
    if (porcelainStatus.split("\n").some((line) => line.startsWith("??"))) throw new Error("Stage B tooling checkout contains an untracked file.");
    throw new Error("Stage B tooling checkout has tracked modifications.");
  }
  if (mode === "production") {
    if (repositoryState.remoteDefaultBranch !== "main") throw new Error("Stage B protected remote default branch is not main.");
    if (repositoryState.shallow) throw new Error("Stage B tooling checkout has shallow or incomplete history.");
    if (originMainHead === undefined || originMainHead === null) throw new Error("Stage B protected origin/main is unavailable.");
    if (originMainHead !== toolingSha) throw new Error("Stage B tooling SHA does not match origin/main.");
    if (isAncestor !== true) throw new Error("Stage B tooling ancestry in origin/main could not be proven.");
  } else if (mode !== "review") {
    throw new Error(`Unsupported Stage B tooling checkout mode: ${mode}.`);
  }
  return evidence;
}

export function assertStageBProtectedCheckoutMatchesDeploymentIdentity({ protectedMainCheckout, deploymentIdentity } = {}) {
  const expectedToolingSha = requireSha(deploymentIdentity?.toolingSha, "deploymentIdentity.toolingSha");
  if (!protectedMainCheckout) throw new Error("Strict Stage B validation requires protected-main checkout evidence.");
  if (protectedMainCheckout.toolingSha !== undefined && protectedMainCheckout.toolingSha !== expectedToolingSha) {
    throw new Error("Stage B protected-main checkout tooling SHA does not match the approved plan tooling SHA.");
  }
  return assertStageBProtectedMainCheckout({ ...protectedMainCheckout, toolingSha: expectedToolingSha });
}

export function assertStageBToolingCheckout(toolingSha, currentHead, checkout = {}) {
  return assertStageBProtectedMainCheckout({ toolingSha, currentHead, ...checkout });
}

function git(cwd, args, encoding = "utf8") {
  return execFileSync("git", args, { cwd, encoding }).trim();
}

function gitPath(cwd, name) {
  return git(cwd, ["rev-parse", "--git-path", name]);
}

function exists(cwd, name) {
  return fs.existsSync(path.resolve(cwd, gitPath(cwd, name)));
}

export function readFreshProtectedMainIdentity({ cwd = process.cwd(), expectedSourceSha, run = (args) => git(cwd, args) } = {}) {
  try {
    run(["fetch", "--no-tags", "origin", "main"]);
  } catch (error) {
    throw new Error(`Fresh protected-main fetch failed: ${error.message}`);
  }
  const freshRemoteMainSha = String(run(["rev-parse", "FETCH_HEAD"])).trim();
  const headSha = String(run(["rev-parse", "HEAD"])).trim();
  requireSha(freshRemoteMainSha, "Fresh remote main SHA");
  requireSha(headSha, "Current checkout HEAD");
  if (expectedSourceSha !== undefined && (headSha !== expectedSourceSha || freshRemoteMainSha !== expectedSourceSha)) {
    throw new Error("Requested source SHA does not match the freshly fetched protected main.");
  }
  return Object.freeze({ fetchSucceeded: true, freshRemoteMainSha, headSha });
}

export function readStageBProtectedMainCheckout({ cwd = process.cwd(), fetchOriginMain = true, expectedSourceSha, requireCanonicalRepository = false, run = (args) => git(cwd, args) } = {}) {
  if (requireCanonicalRepository) assertStageBCanonicalRepositoryUrl(String(run(["remote", "get-url", "origin"])).trim());
  const fresh = fetchOriginMain ? readFreshProtectedMainIdentity({ cwd, expectedSourceSha, run }) : undefined;
  const currentHead = fresh?.headSha || run(["rev-parse", "HEAD"]);
  let originMainHead = fresh?.freshRemoteMainSha;
  if (!fetchOriginMain) {
    try { originMainHead = String(run(["rev-parse", "refs/remotes/origin/main"])).trim(); } catch { originMainHead = undefined; }
  }
  let remoteDefaultBranch;
  try {
    remoteDefaultBranch = String(run(["symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"])).trim().replace(/^refs\/remotes\/origin\//, "");
  } catch {
    try { remoteDefaultBranch = /^ref: refs\/heads\/([^\s]+)\s+HEAD$/m.exec(run(["ls-remote", "--symref", "origin", "HEAD"]))?.[1]; } catch { remoteDefaultBranch = undefined; }
  }
  const isAncestor = originMainHead === undefined ? false : (() => {
    try { run(["merge-base", "--is-ancestor", currentHead, originMainHead]); return true; } catch { return false; }
  })();
  const porcelainStatus = String(run(["status", "--porcelain=v1", "--untracked-files=all"]));
  const repositoryState = {
    remoteDefaultBranch,
    shallow: run(["rev-parse", "--is-shallow-repository"]) === "true",
    mergeInProgress: exists(cwd, "MERGE_HEAD"),
    rebaseInProgress: exists(cwd, "rebase-merge") || exists(cwd, "rebase-apply"),
    cherryPickInProgress: exists(cwd, "CHERRY_PICK_HEAD"),
  };
  return assertStageBProtectedMainCheckout({ mode: "production", toolingSha: currentHead, currentHead, originMainHead, isAncestor, porcelainStatus, repositoryState });
}
