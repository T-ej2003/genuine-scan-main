import { STAGE_B_TERRAFORM_BACKEND } from "./stage-b-terraform-backend-contract.mjs";

export const STAGE_B_TERRAFORM_WORKSPACE = STAGE_B_TERRAFORM_BACKEND.workspaceName;

export function assertStageBTerraformWorkspace({ envWorkspace, observedWorkspace } = {}) {
  if (envWorkspace !== STAGE_B_TERRAFORM_WORKSPACE) throw new Error(`Stage B Terraform requires TF_WORKSPACE=${STAGE_B_TERRAFORM_WORKSPACE} for the direct production state key.`);
  if (observedWorkspace !== undefined && observedWorkspace !== STAGE_B_TERRAFORM_WORKSPACE) throw new Error(`Stage B Terraform workspace must be ${STAGE_B_TERRAFORM_WORKSPACE}; observed ${observedWorkspace || "empty"}.`);
  return STAGE_B_TERRAFORM_WORKSPACE;
}

export function assertStageBTerraformWorkspaceArguments(argv = []) {
  if (!Array.isArray(argv)) throw new Error("Stage B Terraform arguments are malformed.");
  const rejected = argv.find((value, index) => typeof value === "string" && (
    /^(?:--?workspace)(?:=|$)/.test(value)
    || /^(?:--?migrate-state|--?force-copy)(?:=|$)/.test(value)
    || (value === "workspace" && ["select", "new", "delete"].includes(argv[index + 1]))
  ));
  if (rejected) throw new Error(`Stage B direct production backend rejects workspace or migration argument: ${rejected}.`);
  return true;
}
