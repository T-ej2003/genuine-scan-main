import { createHash, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
const REQUIRED_LOGICAL_ADDRESS = "aws_vpc_security_group_ingress_rule.runtime_endpoints_https";
const SHA256 = /^[a-f0-9]{64}$/;
const exact = (value, expected, message) => { if (value !== expected) throw new Error(message); };
export const STAGE_A_CHECKER_POLICY = Object.freeze({
  address: "aws_iam_role_policy.checker_assume_target",
  type: "aws_iam_role_policy",
  role: "mscqr-production-independent-checker",
  name: "mscqr-production-independent-checker-role-chain",
  sid: "AssumeExactRlsIndependentChecker",
  action: "sts:AssumeRole",
  resource: "arn:aws:iam::368992683803:role/mscqr-production-rls-independent-checker",
});
const exactActions = (actual, expected) => JSON.stringify(actual) === JSON.stringify(expected);

function readAndVerifyPlanSha256(planPath, expectedSha256) {
  if (!SHA256.test(expectedSha256 || "")) throw new Error("Stage A preserved plan SHA-256 is missing or malformed.");
  let bytes;
  try { bytes = fs.readFileSync(planPath); } catch { throw new Error("Stage A preserved plan is missing or unreadable."); }
  const actualSha256 = createHash("sha256").update(bytes).digest("hex");
  const expected = Buffer.from(expectedSha256, "hex");
  const actual = Buffer.from(actualSha256, "hex");
  if (!timingSafeEqual(actual, expected)) throw new Error("Stage A preserved plan SHA-256 does not match the bootstrap binding.");
  return actualSha256;
}

export function assertStageAPlan(plan, { endpointSecurityGroupId, runtimeSecurityGroupId } = {}) {
  if (!plan || !Array.isArray(plan.resource_changes) || !endpointSecurityGroupId || !runtimeSecurityGroupId) throw new Error("Stage A plan inputs are incomplete.");
  const expectedAddress = `${REQUIRED_LOGICAL_ADDRESS}[${JSON.stringify(runtimeSecurityGroupId)}]`;
  const changes = plan.resource_changes.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry) || typeof entry.address !== "string" || !entry.address.trim()) throw new Error("Stage A plan contains a malformed resource entry.");
    if (!entry.change || typeof entry.change !== "object" || Array.isArray(entry.change)) throw new Error("Stage A plan resource change is malformed.");
    const actions = entry.change.actions;
    if (!Array.isArray(actions) || actions.length === 0 || !actions.every((action) => typeof action === "string")) throw new Error("Stage A plan resource actions are malformed.");
    return { entry, actions };
  });
  const unexpected = changes.filter(({ entry, actions }) => entry.address !== expectedAddress && entry.address !== STAGE_A_CHECKER_POLICY.address
    && !exactActions(actions, ["no-op"]) && !exactActions(actions, ["read"]));
  if (unexpected.length) throw new Error("Stage A plan contains an unreviewed mutation.");
  const reviewed = changes.filter(({ entry }) => entry.address === expectedAddress);
  if (reviewed.length !== 1) throw new Error("Stage A plan must contain exactly one reviewed ingress instance.");
  const checker = changes.filter(({ entry }) => entry.address === STAGE_A_CHECKER_POLICY.address);
  if (checker.length !== 1) throw new Error("Stage A plan must contain exactly one reviewed checker role-chain policy.");
  const { entry: change, actions } = reviewed[0];
  if (!exactActions(actions, ["create"]) && !exactActions(actions, ["no-op"])) throw new Error("Stage A plan contains an unreviewed ingress action.");
  const { entry: checkerChange, actions: checkerActions } = checker[0];
  exact(checkerChange.type, STAGE_A_CHECKER_POLICY.type, "Stage A checker role-chain policy type is wrong.");
  if (!exactActions(checkerActions, ["create"]) && !exactActions(checkerActions, ["no-op"])) throw new Error("Stage A checker role-chain policy action is wrong.");
  const checkerAfter = checkerChange.change?.after;
  if (!checkerAfter || typeof checkerAfter !== "object" || Array.isArray(checkerAfter)) throw new Error("Stage A checker role-chain policy body is missing.");
  exact(checkerAfter.role, STAGE_A_CHECKER_POLICY.role, "Stage A checker role is wrong.");
  exact(checkerAfter.name, STAGE_A_CHECKER_POLICY.name, "Stage A checker policy name is wrong.");
  if (typeof checkerAfter.policy !== "string") throw new Error("Stage A checker policy document is missing.");
  let checkerPolicy;
  try { checkerPolicy = JSON.parse(checkerAfter.policy); } catch { throw new Error("Stage A checker policy document is malformed."); }
  if (!checkerPolicy || checkerPolicy.Version !== "2012-10-17" || !Array.isArray(checkerPolicy.Statement) || checkerPolicy.Statement.length !== 1
    || Object.keys(checkerPolicy).sort().join(",") !== "Statement,Version") throw new Error("Stage A checker policy envelope is not exact.");
  const [statement] = checkerPolicy.Statement;
  if (!statement || Object.keys(statement).sort().join(",") !== "Action,Effect,Resource,Sid"
    || statement.Sid !== STAGE_A_CHECKER_POLICY.sid || statement.Effect !== "Allow"
    || statement.Action !== STAGE_A_CHECKER_POLICY.action || statement.Resource !== STAGE_A_CHECKER_POLICY.resource) {
    throw new Error("Stage A checker policy semantics are not exact.");
  }
  const after = change.change?.after || {};
  exact(after.security_group_id, endpointSecurityGroupId, "Stage A plan endpoint security group is wrong.");
  exact(after.referenced_security_group_id, runtimeSecurityGroupId, "Stage A plan runtime security group is wrong.");
  exact(String(after.from_port), "443", "Stage A plan ingress port is wrong.");
  exact(String(after.to_port), "443", "Stage A plan ingress port is wrong.");
  exact(after.ip_protocol, "tcp", "Stage A plan ingress protocol is wrong.");
  if (after.cidr_ipv4 !== null || after.cidr_ipv6 !== null || after.prefix_list_id !== null) throw new Error("Stage A plan ingress source is not the reviewed security group.");
  const mutationCount = [actions, checkerActions].filter((value) => exactActions(value, ["create"])).length;
  return { valid: true, changes: mutationCount, address: change.address, actions, checkerActions, alreadyConverged: exactActions(actions, ["no-op"]) && exactActions(checkerActions, ["no-op"]) };
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
  return { valid: true, ...validation, appliedExactSavedPlan: !validation.alreadyConverged, postconditionVerified: true, evidenceRef: saved.evidenceRef, evidenceSha256: saved.evidenceSha256, mutationCount: validation.changes };
}

export function createTerraformStageAAdapter({ terraform = "terraform", root = "infra/aws/terraform/production-green-stage-a", backendArgs = [], planPath, stageAPlanSha256, run, describeIngress, sourceSha, region = "eu-west-2" } = {}) {
  if (typeof run !== "function" || typeof describeIngress !== "function" || !path.isAbsolute(planPath || "")) throw new Error("Stage A Terraform adapter is incomplete.");
  if (sourceSha && !/^[a-f0-9]{40}$/.test(sourceSha)) throw new Error("Stage A source SHA is invalid.");
  if (!/^[a-z]{2}-[a-z]+-[0-9]$/.test(region)) throw new Error("Stage A region is invalid.");
  let savedPlanSha256 = null;
  return {
    async createSavedPlan() {
      if (fs.existsSync(planPath)) {
        readAndVerifyPlanSha256(planPath, stageAPlanSha256);
        await run([terraform, `-chdir=${root}`, "init", "-upgrade=false", "-input=false", "-backend=false"]);
      } else {
        if (stageAPlanSha256 !== undefined) throw new Error("Stage A preserved plan is missing.");
        await run([terraform, `-chdir=${root}`, "init", "-upgrade=false", "-input=false", ...backendArgs]);
        await run([terraform, `-chdir=${root}`, "plan", "-input=false", "-out", planPath]);
      }
      const plan = JSON.parse(await run([terraform, `-chdir=${root}`, "show", "-json", planPath]));
      const bytes = fs.readFileSync(planPath);
      savedPlanSha256 = createHash("sha256").update(bytes).digest("hex");
      if (stageAPlanSha256 !== undefined) readAndVerifyPlanSha256(planPath, stageAPlanSha256);
      return { plan, planPath, savedPlanSha256, sourceSha, region, terraformRoot: root, evidenceRef: `terraform-plan:${planPath}`, evidenceSha256: savedPlanSha256 };
    },
    async applySavedPlan(saved) {
      if (!saved || saved.planPath !== planPath || saved.savedPlanSha256 !== savedPlanSha256) throw new Error("Stage A saved plan changed after validation.");
      const currentSha256 = stageAPlanSha256 === undefined ? createHash("sha256").update(fs.readFileSync(planPath)).digest("hex") : readAndVerifyPlanSha256(planPath, stageAPlanSha256);
      if (currentSha256 !== savedPlanSha256) throw new Error("Stage A saved plan changed after validation.");
      await run([terraform, `-chdir=${root}`, "apply", "-input=false", planPath]);
    },
    describeIngress,
  };
}
