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

function requireSha(value, label) {
  if (!SHA_PATTERN.test(String(value || ""))) throw new Error(`${label} must be a full 40-character commit SHA.`);
  return value;
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

export function assertStageBDeploymentIdentity({
  plan,
  expectedToolingSha,
  expectedImageReleaseSha,
  expectedCanonicalImageEvidenceSha256,
  imageEvidence,
} = {}) {
  const toolingSha = requireSha(planVariable(plan, STAGE_B_PLAN_IDENTITY_VARIABLES.toolingSha), "tooling_sha");
  const imageReleaseSha = requireSha(planVariable(plan, STAGE_B_PLAN_IDENTITY_VARIABLES.imageReleaseSha), "image_release_sha");
  const canonicalImageEvidenceSha256 = requireDigest(planVariable(plan, STAGE_B_PLAN_IDENTITY_VARIABLES.canonicalImageEvidenceSha256), "canonical_image_evidence_sha256");
  if (expectedToolingSha !== undefined && toolingSha !== expectedToolingSha) throw new Error("Stage B plan tooling_sha does not match the approved tooling SHA.");
  if (expectedImageReleaseSha !== undefined && imageReleaseSha !== expectedImageReleaseSha) throw new Error("Stage B plan image_release_sha does not match the approved image release SHA.");
  if (expectedCanonicalImageEvidenceSha256 !== undefined && canonicalImageEvidenceSha256 !== expectedCanonicalImageEvidenceSha256) throw new Error("Stage B plan canonical image-evidence digest does not match the approved digest.");
  if (imageEvidence && imageEvidence.imageReleaseSha !== imageReleaseSha) throw new Error("Stage B image evidence imageReleaseSha does not match the plan image_release_sha.");
  return Object.freeze({ toolingSha, imageReleaseSha, canonicalImageEvidenceSha256 });
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

export function readStageBProtectedMainCheckout({ cwd = process.cwd(), fetchOriginMain = true } = {}) {
  if (fetchOriginMain) git(cwd, ["fetch", "--no-tags", "origin", "main"]);
  const currentHead = git(cwd, ["rev-parse", "HEAD"]);
  let originMainHead;
  try { originMainHead = git(cwd, ["rev-parse", "refs/remotes/origin/main"]); } catch { originMainHead = undefined; }
  let remoteDefaultBranch;
  try {
    remoteDefaultBranch = git(cwd, ["symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"]).replace(/^refs\/remotes\/origin\//, "");
  } catch {
    try { remoteDefaultBranch = /^ref: refs\/heads\/([^\s]+)\s+HEAD$/m.exec(git(cwd, ["ls-remote", "--symref", "origin", "HEAD"]))?.[1]; } catch { remoteDefaultBranch = undefined; }
  }
  const isAncestor = originMainHead === undefined ? false : (() => {
    try { git(cwd, ["merge-base", "--is-ancestor", currentHead, "refs/remotes/origin/main"]); return true; } catch { return false; }
  })();
  const porcelainStatus = git(cwd, ["status", "--porcelain=v1", "--untracked-files=all"]);
  const repositoryState = {
    remoteDefaultBranch,
    shallow: git(cwd, ["rev-parse", "--is-shallow-repository"]) === "true",
    mergeInProgress: exists(cwd, "MERGE_HEAD"),
    rebaseInProgress: exists(cwd, "rebase-merge") || exists(cwd, "rebase-apply"),
    cherryPickInProgress: exists(cwd, "CHERRY_PICK_HEAD"),
  };
  return assertStageBProtectedMainCheckout({ mode: "production", toolingSha: currentHead, currentHead, originMainHead, isAncestor, porcelainStatus, repositoryState });
}
