import fs from "node:fs";

const root = "infra/aws/terraform/production-initial-activation-policy-reconciler";
const trust = fs.readFileSync(`${root}/bootstrap-operator-policy-authorizer-trust-policy.json`, "utf8");
const policy = fs.readFileSync(`${root}/bootstrap-operator-policy-authorizer-permissions-policy.json`, "utf8");
const readerTrust = fs.readFileSync(`${root}/broker-recovery-successor-evidence-reader-trust-policy.json`, "utf8");
const readerPolicy = fs.readFileSync(`${root}/broker-recovery-successor-evidence-reader-permissions-policy.json`, "utf8");
const reconcilerPolicy = fs.readFileSync(`${root}/permissions-policy.json`, "utf8");
const tags = { Component: "bootstrap-operator-policy-authorization", Environment: "production", ManagedBy: "Terraform", Stack: "production-initial-activation-policy-reconciler" };
const roleName = "mscqr-production-bootstrap-operator-policy-authorizer";
const policyName = "MSCQRProductionBootstrapOperatorPolicyAuthorizer";
const readerTags = { Component: "broker-recovery-successor-evidence", Environment: "production", ManagedBy: "Terraform", Stack: "production-initial-activation-policy-reconciler" };
const readerRoleName = "mscqr-production-broker-recovery-successor-evidence-reader";
const readerPolicyName = "MSCQRProductionBrokerRecoverySuccessorEvidenceRead";

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
  const managedPolicy = { ...structuredClone(policyTemplate.change.after), description: "Exact read-only binding verification for bootstrap-operator policy authorization.", name: policyName, policy, tags, tags_all: tags, ...(legacy ? {} : { arn: `arn:aws:iam::368992683803:policy/${policyName}`, id: `arn:aws:iam::368992683803:policy/${policyName}` }) };
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
    delete additions[1].change.after.id;
    const attach = additions.at(-1);
    delete attach.change.after.policy_arn;
    attach.change.after_unknown = { ...attach.change.after_unknown, policy_arn: true };
  } else {
    delete additions.at(-1).change.after_unknown.policy_arn;
  }
  current.resource_changes.push(...additions);
  const readerRole = { ...structuredClone(roleTemplate.change.after), assume_role_policy: readerTrust, description: "Temporary GitHub OIDC reader for exact broker successor lineage evidence.", name: readerRoleName, tags: readerTags, tags_all: readerTags, ...(legacy ? {} : { arn: `arn:aws:iam::368992683803:role/${readerRoleName}` }) };
  const readerManagedPolicy = { ...structuredClone(policyTemplate.change.after), description: "Read only the two immutable component broker successor lineage objects.", name: readerPolicyName, policy: readerPolicy, tags: readerTags, tags_all: readerTags, ...(legacy ? {} : { arn: `arn:aws:iam::368992683803:policy/${readerPolicyName}`, id: `arn:aws:iam::368992683803:policy/${readerPolicyName}` }) };
  const readerAttachment = { ...structuredClone(attachmentTemplate.change.after), role: readerRoleName, ...(legacy ? {} : { policy_arn: `arn:aws:iam::368992683803:policy/${readerPolicyName}` }) };
  current.configuration.root_module.resources.push(
    resource("aws_iam_role", "broker_recovery_successor_evidence_reader", { assume_role_policy: { references: ["path.module"] }, description: { constant_value: "Temporary GitHub OIDC reader for exact broker successor lineage evidence." }, max_session_duration: { constant_value: 3600 }, name: { references: ["local.broker_recovery_successor_evidence_reader_role_name"] }, tags: { references: ["local.tags"] } }),
    resource("aws_iam_policy", "broker_recovery_successor_evidence_reader", { description: { constant_value: "Read only the two immutable component broker successor lineage objects." }, name: { references: ["local.broker_recovery_successor_evidence_reader_policy_name"] }, policy: { references: ["path.module"] }, tags: { references: ["local.tags"] } }),
    resource("aws_iam_role_policy_attachment", "broker_recovery_successor_evidence_reader", { policy_arn: { references: ["aws_iam_policy.broker_recovery_successor_evidence_reader.arn", "aws_iam_policy.broker_recovery_successor_evidence_reader"] }, role: { references: ["aws_iam_role.broker_recovery_successor_evidence_reader.name", "aws_iam_role.broker_recovery_successor_evidence_reader"] } }),
  );
  const readerAdditions = [
    clone(roleTemplate, "aws_iam_role.broker_recovery_successor_evidence_reader", "aws_iam_role", "broker_recovery_successor_evidence_reader", readerRole),
    clone(policyTemplate, "aws_iam_policy.broker_recovery_successor_evidence_reader", "aws_iam_policy", "broker_recovery_successor_evidence_reader", readerManagedPolicy),
    clone(attachmentTemplate, "aws_iam_role_policy_attachment.broker_recovery_successor_evidence_reader", "aws_iam_role_policy_attachment", "broker_recovery_successor_evidence_reader", readerAttachment),
  ];
  if (legacy) {
    for (const addition of readerAdditions.slice(0, 2)) { delete addition.change.after.arn; addition.change.after_unknown = { ...addition.change.after_unknown, arn: true }; }
    delete readerAdditions[1].change.after.id;
    delete readerAdditions.at(-1).change.after.policy_arn; readerAdditions.at(-1).change.after_unknown = { ...readerAdditions.at(-1).change.after_unknown, policy_arn: true };
  } else delete readerAdditions.at(-1).change.after_unknown.policy_arn;
  current.resource_changes.push(...readerAdditions);
  Object.assign(current.configuration.root_module.outputs, {
    broker_recovery_successor_evidence_reader_permissions_policy_sha256: { expression: { references: ["path.module"] } },
    broker_recovery_successor_evidence_reader_policy_arn: { expression: { references: ["aws_iam_policy.broker_recovery_successor_evidence_reader.arn", "aws_iam_policy.broker_recovery_successor_evidence_reader"] } },
    broker_recovery_successor_evidence_reader_role_arn: { expression: { references: ["aws_iam_role.broker_recovery_successor_evidence_reader.arn", "aws_iam_role.broker_recovery_successor_evidence_reader"] } },
    broker_recovery_successor_evidence_reader_trust_policy_sha256: { expression: { references: ["path.module"] } },
  });
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
  const readerResources = [
    ["aws_iam_role", { assume_role_policy: readerTrust, description: "Temporary GitHub OIDC reader for exact broker successor lineage evidence.", force_detach_policies: false, max_session_duration: 3600, name: readerRoleName, path: "/", permissions_boundary: null, tags: readerTags, tags_all: readerTags, arn: `arn:aws:iam::368992683803:role/${readerRoleName}` }],
    ["aws_iam_policy", { delay_after_policy_creation_in_ms: null, description: "Read only the two immutable component broker successor lineage objects.", name: readerPolicyName, path: "/", policy: readerPolicy, tags: readerTags, tags_all: readerTags, arn: `arn:aws:iam::368992683803:policy/${readerPolicyName}` }],
    ["aws_iam_role_policy_attachment", { role: readerRoleName, policy_arn: `arn:aws:iam::368992683803:policy/${readerPolicyName}` }],
  ];
  for (const [type, attributes] of readerResources) if (!existing.has(`${type}.broker_recovery_successor_evidence_reader`)) state.resources.push({ mode: "managed", type, name: "broker_recovery_successor_evidence_reader", instances: [{ attributes }] });
  return JSON.stringify(state);
};
