export const PRODUCTION_ENVIRONMENT_CONTRACT = Object.freeze({
  name: "production",
  repository: "T-ej2003/genuine-scan-main",
  requiredBranch: "main",
});

export function assertProductionEnvironmentContract({ environment, branchPolicies } = {}) {
  if (!environment || typeof environment !== "object") throw new Error("Production environment response is missing.");
  if (environment.name !== PRODUCTION_ENVIRONMENT_CONTRACT.name) throw new Error("Production environment name is wrong.");
  const requiredReviewers = (environment.protection_rules || []).find((rule) => rule.type === "required_reviewers")?.reviewers || [];
  if (requiredReviewers.length === 0) throw new Error("Production environment must require at least one reviewer.");
  const branchPolicy = environment.deployment_branch_policy;
  if (branchPolicy?.custom_branch_policies !== true || branchPolicy?.protected_branches !== false) throw new Error("Production environment must use an explicit custom branch policy.");
  const policies = Array.isArray(branchPolicies) ? branchPolicies : [];
  if (policies.length !== 1 || policies[0].type !== "branch" || policies[0].name !== PRODUCTION_ENVIRONMENT_CONTRACT.requiredBranch) {
    throw new Error("Production environment must allow exactly the main branch.");
  }
  return { valid: true, name: environment.name, requiredReviewers: requiredReviewers.length, branchPolicies: policies.map(({ name, type }) => ({ name, type })) };
}

export function assertProductionEnvironmentRepository(repository) {
  if (repository !== PRODUCTION_ENVIRONMENT_CONTRACT.repository) throw new Error("Production environment repository is not the reviewed repository.");
  return true;
}

if (process.argv[1]?.endsWith("production-environment-contract.mjs")) {
  const environment = JSON.parse(process.env.PRODUCTION_ENVIRONMENT_JSON || "null");
  const branchPolicies = JSON.parse(process.env.PRODUCTION_BRANCH_POLICIES_JSON || "[]");
  process.stdout.write(`${JSON.stringify(assertProductionEnvironmentContract({ environment, branchPolicies }))}\n`);
}
