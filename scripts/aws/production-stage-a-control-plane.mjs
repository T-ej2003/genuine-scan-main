import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
const REQUIRED_LOGICAL_ADDRESS = "aws_vpc_security_group_ingress_rule.runtime_endpoints_https";
const exact = (value, expected, message) => { if (value !== expected) throw new Error(message); };

export function assertStageAPlan(plan, { endpointSecurityGroupId, runtimeSecurityGroupId } = {}) {
  if (!plan || !Array.isArray(plan.resource_changes) || !endpointSecurityGroupId || !runtimeSecurityGroupId) throw new Error("Stage A plan inputs are incomplete.");
  const expectedAddress = `${REQUIRED_LOGICAL_ADDRESS}[${JSON.stringify(runtimeSecurityGroupId)}]`;
  const unexpected = plan.resource_changes.filter((change) => change.address !== expectedAddress && (change.change?.actions || []).some((action) => !["no-op", "read"].includes(action)));
  if (unexpected.length) throw new Error("Stage A plan contains an unreviewed mutation.");
  const reviewed = plan.resource_changes.filter((change) => change.address === expectedAddress);
  if (reviewed.length !== 1) throw new Error("Stage A plan must contain exactly one reviewed ingress instance.");
  const change = reviewed[0];
  const actions = change.change?.actions || [];
  if (JSON.stringify(actions) !== JSON.stringify(["create"]) && JSON.stringify(actions) !== JSON.stringify(["no-op"])) throw new Error("Stage A plan contains an unreviewed ingress action.");
  const after = change.change?.after || {};
  exact(after.security_group_id, endpointSecurityGroupId, "Stage A plan endpoint security group is wrong.");
  exact(after.referenced_security_group_id, runtimeSecurityGroupId, "Stage A plan runtime security group is wrong.");
  exact(String(after.from_port), "443", "Stage A plan ingress port is wrong.");
  exact(String(after.to_port), "443", "Stage A plan ingress port is wrong.");
  exact(after.ip_protocol, "tcp", "Stage A plan ingress protocol is wrong.");
  if (after.cidr_ipv4 !== null || after.cidr_ipv6 !== null || after.prefix_list_id !== null) throw new Error("Stage A plan ingress source is not the reviewed security group.");
  return { valid: true, changes: actions[0] === "create" ? 1 : 0, address: change.address, actions, alreadyConverged: actions[0] === "no-op" };
}

export async function runStageAControlPlane({ adapter, endpointSecurityGroupId, runtimeSecurityGroupId, sourceSha } = {}) {
  if (!adapter || typeof adapter.createSavedPlan !== "function" || typeof adapter.applySavedPlan !== "function" || typeof adapter.describeIngress !== "function") throw new Error("Stage A control-plane adapter is incomplete.");
  const saved = await adapter.createSavedPlan();
  if (sourceSha && saved?.sourceSha !== sourceSha) throw new Error("Stage A saved plan is not bound to the protected-main source SHA.");
  if (!/^[a-f0-9]{64}$/.test(saved?.savedPlanSha256 || "")) throw new Error("Stage A saved plan bytes are not hash-bound.");
  const plan = saved?.plan;
  const validation = assertStageAPlan(plan, { endpointSecurityGroupId, runtimeSecurityGroupId });
  if (!validation.alreadyConverged) await adapter.applySavedPlan(saved);
  const rule = await adapter.describeIngress({ endpointSecurityGroupId, runtimeSecurityGroupId, protocol: "tcp", fromPort: 443, toPort: 443 });
  if (rule?.present !== true) throw new Error("Stage A endpoint ingress postcondition is absent.");
  return { valid: true, ...validation, appliedExactSavedPlan: !validation.alreadyConverged, postconditionVerified: true, evidenceRef: saved.evidenceRef, evidenceSha256: saved.evidenceSha256, mutationCount: validation.alreadyConverged ? 0 : 1 };
}

export function createTerraformStageAAdapter({ terraform = "terraform", root = "infra/aws/terraform/production-green-stage-a", backendArgs = [], planPath, run, describeIngress, sourceSha, region = "eu-west-2" } = {}) {
  if (typeof run !== "function" || typeof describeIngress !== "function" || !path.isAbsolute(planPath || "")) throw new Error("Stage A Terraform adapter is incomplete.");
  if (sourceSha && !/^[a-f0-9]{40}$/.test(sourceSha)) throw new Error("Stage A source SHA is invalid.");
  if (!/^[a-z]{2}-[a-z]+-[0-9]$/.test(region)) throw new Error("Stage A region is invalid.");
  let savedPlanSha256 = null;
  return {
    async createSavedPlan() {
      await run([terraform, `-chdir=${root}`, "init", "-upgrade=false", "-input=false", ...backendArgs]);
      await run([terraform, `-chdir=${root}`, "plan", "-input=false", "-out", planPath]);
      const plan = JSON.parse(await run([terraform, `-chdir=${root}`, "show", "-json", planPath]));
      const bytes = fs.readFileSync(planPath);
      savedPlanSha256 = createHash("sha256").update(bytes).digest("hex");
      return { plan, planPath, savedPlanSha256, sourceSha, region, terraformRoot: root, evidenceRef: `terraform-plan:${planPath}`, evidenceSha256: savedPlanSha256 };
    },
    async applySavedPlan(saved) {
      if (!saved || saved.planPath !== planPath || saved.savedPlanSha256 !== savedPlanSha256 || createHash("sha256").update(fs.readFileSync(planPath)).digest("hex") !== savedPlanSha256) throw new Error("Stage A saved plan changed after validation.");
      await run([terraform, `-chdir=${root}`, "apply", "-input=false", planPath]);
    },
    describeIngress,
  };
}
