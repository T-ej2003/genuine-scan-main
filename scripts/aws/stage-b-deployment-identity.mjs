const SHA_PATTERN = /^[a-f0-9]{40}$/;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/;

export const STAGE_B_DEPLOYMENT_IDENTITY_SCHEMA_VERSION = 1;
export const STAGE_B_PLAN_IDENTITY_VARIABLES = Object.freeze({
  toolingSha: "tooling_sha",
  imageReleaseSha: "image_release_sha",
  canonicalImageEvidenceSha256: "canonical_image_evidence_sha256",
});

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

export function assertStageBToolingCheckout(toolingSha, currentHead) {
  requireSha(toolingSha, "toolingSha");
  if (currentHead !== toolingSha) throw new Error("Stage B tooling SHA does not match the checked-out tooling HEAD.");
  return toolingSha;
}
