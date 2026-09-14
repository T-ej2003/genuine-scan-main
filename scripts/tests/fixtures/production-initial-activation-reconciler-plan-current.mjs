import fs from "node:fs";

const root = "infra/aws/terraform/production-initial-activation-policy-reconciler";
const trust = fs.readFileSync(`${root}/bootstrap-operator-policy-authorizer-trust-policy.json`, "utf8");
const policy = fs.readFileSync(`${root}/bootstrap-operator-policy-authorizer-permissions-policy.json`, "utf8");
const reconcilerPolicy = fs.readFileSync(`${root}/permissions-policy.json`, "utf8");
const tags = { Component: "bootstrap-operator-policy-authorization", Environment: "production", ManagedBy: "Terraform", Stack: "production-initial-activation-policy-reconciler" };
const roleName = "mscqr-production-bootstrap-operator-policy-authorizer";
const policyName = "MSCQRProductionBootstrapOperatorPolicyAuthorizer";

const resource = (type, name, expressions) => ({ address: `${type}.${name}`, mode: "managed", type, name, provider_config_key: "aws", expressions, schema_version: 0 });
const authorizerResources = () => [
  resource("aws_iam_role", "bootstrap_operator_policy_authorizer", { assume_role_policy: { references: ["path.module"] }, description: { constant_value: "GitHub OIDC-only read-only authorizer for the exact bootstrap-operator legacy transition." }, max_session_duration: { constant_value: 3600 }, name: { constant_value: roleName }, tags: { references: ["local.tags"] } }),
  resource("aws_iam_policy", "bootstrap_operator_policy_authorizer", { description: { constant_value: "Exact read-only binding verification for bootstrap-operator policy authorization." }, name: { constant_value: policyName }, policy: { references: ["path.module"] }, tags: { references: ["local.tags"] } }),
  resource("aws_iam_role_policy_attachment", "bootstrap_operator_policy_authorizer", { policy_arn: { references: ["aws_iam_policy.bootstrap_operator_policy_authorizer.arn", "aws_iam_policy.bootstrap_operator_policy_authorizer"] }, role: { references: ["aws_iam_role.bootstrap_operator_policy_authorizer.name", "aws_iam_role.bootstrap_operator_policy_authorizer"] } }),
];

export const currentInstallationPlan = (plan, { legacyAuthorizer = false } = {}) => {
  const current = structuredClone(plan);
  const allCreate = current.resource_changes.every(({ change }) => JSON.stringify(change.actions) === JSON.stringify(["create"]));
  const legacy = legacyAuthorizer || allCreate;
  const actions = legacy ? ["create"] : ["no-op"];
  const roleTemplate = current.resource_changes.find(({ address }) => address === "aws_iam_role.reconciler");
  const policyTemplate = current.resource_changes.find(({ address }) => address === "aws_iam_policy.reconciler");
  const attachmentTemplate = current.resource_changes.find(({ address }) => address === "aws_iam_role_policy_attachment.reconciler");
  const reconciler = current.resource_changes.find(({ address }) => address === "aws_iam_policy.reconciler");
  reconciler.change.after.policy = reconcilerPolicy;
  if ((legacy || reconciler.change.actions[0] === "update") && reconciler.change.actions[0] !== "create") {
    reconciler.change.actions = ["update"];
    reconciler.change.after.arn = "arn:aws:iam::368992683803:policy/MSCQRProductionInitialActivationPolicyReconciler";
    reconciler.change.before = { ...structuredClone(reconciler.change.after), policy: JSON.stringify({ ...JSON.parse(reconcilerPolicy), Statement: [...JSON.parse(reconcilerPolicy).Statement, ...JSON.parse(policy).Statement.filter(({ Sid }) => Sid !== "IdentifyCurrentSession")] }) };
  } else if (reconciler.change.actions[0] === "no-op") {
    reconciler.change.before.policy = reconcilerPolicy;
  }
  const clone = (template, address, type, name, after) => ({ ...structuredClone(template), address, type, name, change: { ...structuredClone(template.change), actions, before: actions[0] === "create" ? null : after, after } });
  const role = { ...structuredClone(roleTemplate.change.after), assume_role_policy: trust, description: "GitHub OIDC-only read-only authorizer for the exact bootstrap-operator legacy transition.", name: roleName, tags, tags_all: tags, ...(legacy ? {} : { arn: `arn:aws:iam::368992683803:role/${roleName}` }) };
  const managedPolicy = { ...structuredClone(policyTemplate.change.after), description: "Exact read-only binding verification for bootstrap-operator policy authorization.", name: policyName, policy, tags, tags_all: tags, ...(legacy ? {} : { arn: `arn:aws:iam::368992683803:policy/${policyName}` }) };
  const attachment = { ...structuredClone(attachmentTemplate.change.after), role: roleName, ...(legacy ? {} : { policy_arn: `arn:aws:iam::368992683803:policy/${policyName}` }) };
  current.configuration.root_module.resources.push(...authorizerResources());
  const additions = [
    clone(roleTemplate, "aws_iam_role.bootstrap_operator_policy_authorizer", "aws_iam_role", "bootstrap_operator_policy_authorizer", role),
    clone(policyTemplate, "aws_iam_policy.bootstrap_operator_policy_authorizer", "aws_iam_policy", "bootstrap_operator_policy_authorizer", managedPolicy),
    clone(attachmentTemplate, "aws_iam_role_policy_attachment.bootstrap_operator_policy_authorizer", "aws_iam_role_policy_attachment", "bootstrap_operator_policy_attachment", attachment),
  ];
  additions.at(-1).name = "bootstrap_operator_policy_authorizer";
  if (legacy) {
    for (const addition of additions.slice(0, 2)) {
      delete addition.change.after.arn;
      addition.change.after_unknown = { ...addition.change.after_unknown, arn: true };
    }
    const attach = additions.at(-1);
    delete attach.change.after.policy_arn;
    attach.change.after_unknown = { ...attach.change.after_unknown, policy_arn: true };
  } else {
    delete additions.at(-1).change.after_unknown.policy_arn;
  }
  current.resource_changes.push(...additions);
  return current;
};

export const currentInstallationState = (raw) => {
  const state = JSON.parse(raw);
  const existing = new Set(state.resources.map(({ type, name }) => `${type}.${name}`));
  const resources = [
    ["aws_iam_role", { assume_role_policy: trust, description: "GitHub OIDC-only read-only authorizer for the exact bootstrap-operator legacy transition.", force_detach_policies: false, max_session_duration: 3600, name: roleName, path: "/", permissions_boundary: null, tags, tags_all: tags, arn: `arn:aws:iam::368992683803:role/${roleName}` }],
    ["aws_iam_policy", { delay_after_policy_creation_in_ms: null, description: "Exact read-only binding verification for bootstrap-operator policy authorization.", name: policyName, path: "/", policy, tags, tags_all: tags, arn: `arn:aws:iam::368992683803:policy/${policyName}` }],
    ["aws_iam_role_policy_attachment", { role: roleName, policy_arn: `arn:aws:iam::368992683803:policy/${policyName}` }],
  ];
  for (const [type, attributes] of resources) if (!existing.has(`${type}.bootstrap_operator_policy_authorizer`)) state.resources.push({ mode: "managed", type, name: "bootstrap_operator_policy_authorizer", instances: [{ attributes }] });
  return JSON.stringify(state);
};
