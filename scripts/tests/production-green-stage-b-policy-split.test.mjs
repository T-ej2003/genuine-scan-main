import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import { assertStageBPlan } from "../plan-production-green-stage-b.mjs";

const paths = {
  v2: "documents/ops/iam/MSCQRProductionGreenStageBProviderRecovery-v2.json",
  v3: "documents/ops/iam/MSCQRProductionGreenStageBProviderRecovery-v3.json",
  v4: "documents/ops/iam/MSCQRProductionGreenStageBProviderRecovery-v4.json",
  audit: "documents/ops/iam/MSCQRProductionGreenStageBReferenceAuditReadOnly-v1.json",
  finalWrite: "documents/ops/iam/MSCQRProductionGreenStageBFinalApplyWrite-v1.json",
};
const read = (path) => fs.readFileSync(path, "utf8");
const parse = (path) => JSON.parse(read(path));
const policies = Object.fromEntries(Object.entries(paths).map(([name, path]) => [name, parse(path)]));
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const actionsOf = (statement) => Array.isArray(statement.Action) ? statement.Action : [statement.Action];
const statementOf = (policy, sid) => policy.Statement.find((statement) => statement.Sid === sid);
const statementsForAction = (policy, action) => policy.Statement.filter((statement) => actionsOf(statement).includes(action));
const canonical = (policy) => ({
  Version: policy.Version,
  Statement: [...policy.Statement].sort((a, b) => a.Sid.localeCompare(b.Sid)),
});
const awsCharacterCount = (policy) => JSON.stringify(policy).replace(/\s/g, "").length;

const movedSids = [
  "ListAttachedRolePoliciesReadOnly",
  "ListStageBServicesReadOnly",
  "DescribeStageBServicesReadOnly",
  "ListStageBTasksReadOnly",
  "DescribeStageBTasksReadOnly",
  "DescribeStageBTaskDefinitionsReadOnly",
  "ReadStageBBrokerConfiguration",
];
const controlSids = [
  "TagExactStageBLogs",
  "CreateExactStageBLogs",
  "SetExactStageBLogRetention",
  "ListExactStageBLogTagsReadOnly",
  "ReadExactStageBReadOnlyCanaryRoles",
  "ListExactStageBReadOnlyCanaryRolePolicies",
  "ListAttachedExactStageBReadOnlyCanaryRolePolicies",
  "ReadExactStageBReadOnlyCanaryExecutionRolePolicy",
  "TagExactReplayTable",
  "TagExactStageBTaskDefinitions",
];
const finalWriteSids = [
  "RegisterExactStageBReadOnlyCanaryTaskDefinition",
  "UpdateExactStageBBrokerFunctionRelease",
];
const stageBTaskFamilies = [
  "mscqr-production-rls-green-backend-candidate",
  "mscqr-production-rls-green-worker-candidate",
  "mscqr-production-full-rls-green-application-canary",
  "mscqr-production-full-rls-green-full-rls-admin-bootstrap",
  "mscqr-production-full-rls-green-full-rls-admin-ownership",
  "mscqr-production-full-rls-green-full-rls-capability-preflight",
  "mscqr-production-full-rls-green-full-rls-role-provision",
  "mscqr-production-full-rls-green-full-rls-role-verify",
  "mscqr-production-full-rls-green-full-rls-rollback",
  "mscqr-production-full-rls-green-full-rls-runtime-policy",
  "mscqr-production-full-rls-green-full-rls-verification",
  "mscqr-production-full-rls-green-read-only-canary",
];
const stageBLogGroups = [
  "/ecs/mscqr-production/rls-green-backend",
  "/ecs/mscqr-production/rls-green-canary",
  "/ecs/mscqr-production/rls-green-worker",
  "/ecs/mscqr-production/rls-green-read-only-canary",
];
const arn = (family) => `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:*`;
const logArn = (name) => `arn:aws:logs:eu-west-2:368992683803:log-group:${name}:*`;
const exactLogArn = (name) => `arn:aws:logs:eu-west-2:368992683803:log-group:${name}`;
const clusterArn = "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main";
const mutationActions = new Set([
  "ecs:TagResource",
  "ecs:RegisterTaskDefinition",
  "ecs:RunTask",
  "ecs:StopTask",
  "ecs:UpdateService",
  "ecs:DeleteService",
]);

test("all policy artifacts parse and historical v2/v3 remain byte-stable", () => {
  assert.equal(sha256(read(paths.v2)), "dccfa7c5cf64c266fd9ea1deabd78f6ed1b43b20132f729642cc5e2ceb65bc71");
  assert.equal(sha256(read(paths.v3)), "ff39b4afe356a06378e45d5941809739c172b007df1dc489ff66632247becf7e");
  assert.deepEqual(statementOf(policies.v2, "DescribeStageBTaskDefinitionsReadOnly").Resource, stageBTaskFamilies.map(arn));
});

test("v4 and the companion policy fit the AWS managed-policy document limit", () => {
  assert.equal(awsCharacterCount(policies.v3), 6651);
  assert.equal(awsCharacterCount(policies.v4), 5580);
  assert.equal(awsCharacterCount(policies.audit), 1785);
  assert.ok(awsCharacterCount(policies.finalWrite) < 6144);
  assert.ok(awsCharacterCount(policies.v4) < 6144);
  assert.ok(awsCharacterCount(policies.audit) < 6144);
});

test("v4 plus the companion policy preserves v3 recovery permissions without deregistration authority", () => {
  const correctedV3 = {
    Version: policies.v3.Version,
    Statement: policies.v3.Statement.filter((statement) => statement.Action !== "ecs:DeregisterTaskDefinition"),
  };
  correctedV3.Statement.push(statementOf(policies.v4, "SetExactStageBLogRetention"));
  correctedV3.Statement.push(statementOf(policies.v4, "ListExactStageBLogTagsReadOnly"));
  correctedV3.Statement.push(statementOf(policies.v4, "ReadExactStageBReadOnlyCanaryRoles"));
  correctedV3.Statement.push(statementOf(policies.v4, "ListExactStageBReadOnlyCanaryRolePolicies"));
  correctedV3.Statement.push(statementOf(policies.v4, "ListAttachedExactStageBReadOnlyCanaryRolePolicies"));
  correctedV3.Statement.push(statementOf(policies.v4, "ReadExactStageBReadOnlyCanaryExecutionRolePolicy"));
  assert.deepEqual(canonical(correctedV3), canonical({
    Version: policies.v3.Version,
    Statement: [...policies.v4.Statement, ...policies.audit.Statement],
  }));
});

test("the split has exactly seven moved statements, ten provider-control statements, and two final-write statements", () => {
  assert.deepEqual(policies.audit.Statement.map(({ Sid }) => Sid), movedSids);
  assert.deepEqual(policies.v4.Statement.map(({ Sid }) => Sid), controlSids);
  assert.deepEqual(policies.finalWrite.Statement.map(({ Sid }) => Sid), finalWriteSids);
  assert.deepEqual(policies.v4.Statement.map(({ Sid }) => Sid).filter((sid) => movedSids.includes(sid)), []);
  assert.deepEqual(policies.audit.Statement.map(({ Sid }) => Sid).filter((sid) => controlSids.includes(sid)), []);
  assert.equal(new Set([...movedSids, ...controlSids, ...finalWriteSids]).size, 19);
  for (const sid of movedSids) assert.deepEqual(statementOf(policies.audit, sid), statementOf(policies.v3, sid));
  for (const sid of controlSids.filter((sid) => !["SetExactStageBLogRetention", "ListExactStageBLogTagsReadOnly", "ReadExactStageBReadOnlyCanaryRoles", "ListExactStageBReadOnlyCanaryRolePolicies", "ListAttachedExactStageBReadOnlyCanaryRolePolicies", "ReadExactStageBReadOnlyCanaryExecutionRolePolicy"].includes(sid))) {
    assert.deepEqual(statementOf(policies.v4, sid), statementOf(policies.v3, sid));
  }
});

test("DescribeTaskDefinition is isolated, wildcard-only, and read-only", () => {
  const matches = statementsForAction(policies.audit, "ecs:DescribeTaskDefinition");
  assert.equal(matches.length, 1);
  assert.deepEqual(matches[0], {
    Sid: "DescribeStageBTaskDefinitionsReadOnly",
    Effect: "Allow",
    Action: "ecs:DescribeTaskDefinition",
    Resource: "*",
    Condition: { StringEquals: { "aws:RequestedRegion": "eu-west-2" } },
  });
});

test("deregistration authority is absent and retention remains resource-scoped", () => {
  for (const policy of [policies.v4, policies.audit]) {
    for (const statement of policy.Statement) {
      if (actionsOf(statement).some((action) => mutationActions.has(action))) {
        assert.notEqual(statement.Resource, "*");
      }
    }
  }
  assert.equal(statementsForAction(policies.v4, "ecs:DeregisterTaskDefinition").length, 0);
  assert.equal(statementsForAction(policies.audit, "ecs:DeregisterTaskDefinition").length, 0);
  assert.notEqual(statementOf(policies.v4, "SetExactStageBLogRetention").Resource, "*");
  assert.equal(policies.audit.Statement.some((statement) => actionsOf(statement).some((action) => mutationActions.has(action))), false);
});

test("retry write companion is exact and tag-constrained", () => {
  const taskDefinition = statementOf(policies.finalWrite, "RegisterExactStageBReadOnlyCanaryTaskDefinition");
  assert.deepEqual(taskDefinition, {
    Sid: "RegisterExactStageBReadOnlyCanaryTaskDefinition",
    Effect: "Allow",
    Action: "ecs:RegisterTaskDefinition",
    Resource: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-full-rls-green-read-only-canary:*",
    Condition: {
      StringEquals: {
        "aws:RequestedRegion": "eu-west-2",
        "aws:RequestTag/Environment": "production",
        "aws:RequestTag/ManagedBy": "Terraform",
        "aws:RequestTag/Component": "full-rls-green-stage-b",
      },
      "ForAllValues:StringEquals": { "aws:TagKeys": ["Environment", "ManagedBy", "Component"] },
    },
  });
  assert.equal(taskDefinition.Resource.includes("mscqr-backend"), false);
  assert.equal(taskDefinition.Resource.includes("mscqr-frontend"), false);

  const broker = "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker";
  const brokerStatement = statementOf(policies.finalWrite, "UpdateExactStageBBrokerFunctionRelease");
  assert.deepEqual(brokerStatement.Action, [
    "lambda:UpdateFunctionConfiguration",
    "lambda:UpdateFunctionCode",
    "lambda:PublishVersion",
    "lambda:UpdateAlias",
  ]);
  assert.equal(brokerStatement.Resource, broker);
  assert.deepEqual(brokerStatement.Condition.StringEquals, {
    "aws:RequestedRegion": "eu-west-2",
    "aws:ResourceTag/Environment": "production",
    "aws:ResourceTag/ManagedBy": "Terraform",
    "aws:ResourceTag/Component": "full-rls-green-stage-b",
  });
  assert.equal(statementsForAction(policies.finalWrite, "lambda:AddPermission").length, 0);
  assert.equal(statementsForAction(policies.finalWrite, "lambda:InvokeFunction").length, 0);
  assert.equal(policies.finalWrite.Statement.some((statement) => actionsOf(statement).some((action) => action.startsWith("lambda:") && statement.Resource === "*")), false);
});

test("unrelated ECS and CloudWatch Logs mutations remain denied", () => {
  const actions = [...policies.v4.Statement, ...policies.audit.Statement].flatMap(actionsOf);
  for (const forbidden of [
    "ecs:RunTask", "ecs:StopTask", "ecs:UpdateService", "ecs:DeleteService",
    "logs:DeleteLogGroup", "logs:PutResourcePolicy", "logs:DeleteResourcePolicy", "logs:AssociateKmsKey",
    "logs:DisassociateKmsKey", "logs:CreateExportTask", "logs:StartQuery", "logs:StopQuery",
  ]) assert.equal(actions.includes(forbidden), false, forbidden);
});

test("cluster, broker, and exact twelve-family restrictions remain unchanged", () => {
  const listServices = statementOf(policies.audit, "ListStageBServicesReadOnly");
  const describeServices = statementOf(policies.audit, "DescribeStageBServicesReadOnly");
  const listTasks = statementOf(policies.audit, "ListStageBTasksReadOnly");
  const describeTasks = statementOf(policies.audit, "DescribeStageBTasksReadOnly");
  for (const statement of [listServices, describeServices, listTasks, describeTasks]) {
    assert.equal(statement.Condition.StringEquals["aws:RequestedRegion"], "eu-west-2");
    assert.equal(statement.Condition.StringEquals["ecs:cluster"], clusterArn);
  }
  assert.deepEqual(statementOf(policies.audit, "ReadStageBBrokerConfiguration").Resource, [
    "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker",
    "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker:*",
  ]);
  assert.deepEqual(statementOf(policies.v4, "TagExactStageBTaskDefinitions").Resource, stageBTaskFamilies.map(arn));
  assert.deepEqual(statementOf(policies.v4, "SetExactStageBLogRetention").Resource, stageBLogGroups.map(logArn));
  assert.equal(stageBTaskFamilies.length, 12);
});

test("ListTagsForResource is read-only and limited to the four exact Stage B log groups", () => {
  const statement = statementOf(policies.v4, "ListExactStageBLogTagsReadOnly");
  assert.deepEqual(statement, {
    Sid: "ListExactStageBLogTagsReadOnly",
    Effect: "Allow",
    Action: "logs:ListTagsForResource",
    Resource: stageBLogGroups.map(exactLogArn),
    Condition: { StringEquals: { "aws:RequestedRegion": "eu-west-2" } },
  });
  assert.equal(statement.Resource.some((resource) => resource.endsWith(":*")), false);
  assert.equal(statement.Resource.includes(exactLogArn("/ecs/mscqr-production/unrelated")), false);
  assert.equal(statementsForAction(policies.audit, "logs:ListTagsForResource").length, 0);
});

test("iam:GetRole is limited to the two imported read-only-canary roles", () => {
  const statement = statementOf(policies.v4, "ReadExactStageBReadOnlyCanaryRoles");
  assert.deepEqual(statement, {
    Sid: "ReadExactStageBReadOnlyCanaryRoles",
    Effect: "Allow",
    Action: "iam:GetRole",
    Resource: [
      "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-execution",
      "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-task",
    ],
  });
  assert.equal(statementsForAction(policies.v4, "iam:GetRole").length, 1);
  assert.equal(statement.Resource.includes("arn:aws:iam::368992683803:role/Unrelated"), false);
  assert.equal(statement.Resource.includes("*"), false);
  assert.equal(statementsForAction(policies.audit, "iam:GetRole").length, 0);
  assert.equal(policies.v4.Statement.some((candidate) => actionsOf(candidate).some((action) => action.startsWith("iam:") && candidate.Resource === "*")), false);
});

test("iam:ListRolePolicies is limited to the two imported read-only-canary roles", () => {
  const statement = statementOf(policies.v4, "ListExactStageBReadOnlyCanaryRolePolicies");
  assert.deepEqual(statement, {
    Sid: "ListExactStageBReadOnlyCanaryRolePolicies",
    Effect: "Allow",
    Action: "iam:ListRolePolicies",
    Resource: [
      "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-execution",
      "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-task",
    ],
  });
  assert.equal(statementsForAction(policies.v4, "iam:ListRolePolicies").length, 1);
  assert.equal(statement.Resource.includes("arn:aws:iam::368992683803:role/Unrelated"), false);
  assert.equal(statement.Resource.includes("*"), false);
  assert.equal(statementsForAction(policies.audit, "iam:ListRolePolicies").length, 0);
  assert.equal(policies.v4.Statement.some((candidate) => actionsOf(candidate).some((action) => action.startsWith("iam:") && candidate.Resource === "*")), false);
});

test("Terraform role refresh reads are complete and narrowly scoped", () => {
  const roles = [
    "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-execution",
    "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-task",
  ];
  assert.deepEqual(statementOf(policies.v4, "ListAttachedExactStageBReadOnlyCanaryRolePolicies"), {
    Sid: "ListAttachedExactStageBReadOnlyCanaryRolePolicies",
    Effect: "Allow",
    Action: "iam:ListAttachedRolePolicies",
    Resource: roles,
  });
  assert.deepEqual(statementOf(policies.v4, "ReadExactStageBReadOnlyCanaryExecutionRolePolicy"), {
    Sid: "ReadExactStageBReadOnlyCanaryExecutionRolePolicy",
    Effect: "Allow",
    Action: "iam:GetRolePolicy",
    Resource: roles[0],
  });
  assert.equal(statementsForAction(policies.v4, "iam:ListAttachedRolePolicies").length, 1);
  assert.equal(statementsForAction(policies.v4, "iam:GetRolePolicy").length, 1);
  assert.equal(statementsForAction(policies.audit, "iam:GetRolePolicy").length, 0);
  assert.equal(statementOf(policies.v4, "ReadExactStageBReadOnlyCanaryExecutionRolePolicy").Resource === roles[1], false);
  assert.equal(policies.v4.Statement.some((candidate) => actionsOf(candidate).some((action) => action.startsWith("iam:") && candidate.Resource === "*")), false);
});

test("the three source-controlled policies carry only the reviewed read, recovery, and retry actions", () => {
  const actions = [...policies.v4.Statement, ...policies.audit.Statement, ...policies.finalWrite.Statement].flatMap(actionsOf);
  for (const forbidden of [
    "ecs:RunTask", "ecs:StopTask", "ecs:UpdateService", "ecs:DeleteService", "lambda:InvokeFunction",
    "iam:CreateRole", "iam:UpdateAssumeRolePolicy", "iam:PutRolePolicy",
    "iam:AttachRolePolicy", "iam:PassRole", "sts:AssumeRole",
    "secretsmanager:GetSecretValue", "kms:Decrypt", "rds:Connect", "route53:ChangeResourceRecordSets",
    "elasticloadbalancing:ModifyListener",
  ]) assert.equal(actions.includes(forbidden), false, forbidden);
  assert.equal(actions.includes("iam:GetRole"), true);
  assert.equal(actions.includes("iam:ListRolePolicies"), true);
  assert.equal(actions.includes("iam:ListAttachedRolePolicies"), true);
  assert.equal(actions.includes("iam:GetRolePolicy"), true);
  assert.equal(actions.includes("lambda:GetFunctionConfiguration"), true);
  assert.equal(actions.includes("ecs:RegisterTaskDefinition"), true);
  assert.equal(actions.includes("lambda:UpdateFunctionConfiguration"), true);
  assert.equal(actions.includes("lambda:UpdateFunctionCode"), true);
  assert.equal(actions.includes("lambda:PublishVersion"), true);
  assert.equal(actions.includes("lambda:UpdateAlias"), true);
});

test("validator rejects blue and unknown task-definition families and addresses", () => {
  const plan = (address, family) => ({
    resource_changes: [{ address, type: "aws_ecs_task_definition", change: { actions: ["create"], after: { family } } }],
  });
  for (const family of ["mscqr-backend", "mscqr-frontend", "unknown-task-family"]) {
    assert.throws(() => assertStageBPlan(plan(`aws_ecs_task_definition.candidate["${family}"]`, family)));
  }
  assert.throws(() => assertStageBPlan(plan("aws_ecs_task_definition.unknown[\"backend\"]", stageBTaskFamilies[0])));
});

test("the runbook targets v4 and the companion policy for the separately authorized live update", () => {
  const runbook = read("documents/ops/iam/PRODUCTION_GREEN_STAGE_B_PROVIDER_RECOVERY_2026-07-29.md");
  assert.match(runbook, /MSCQRProductionGreenStageBProviderRecovery-v4\.json/);
  assert.match(runbook, /MSCQRProductionGreenStageBReferenceAuditReadOnly-v1\.json/);
  assert.match(runbook, /MSCQRProductionGreenStageBFinalApplyWrite-v1\.json/);
  assert.match(runbook, /FINAL_WRITE_POLICY_NAME/);
  assert.match(runbook, /mscqr-production-release-deployer/);
  assert.match(runbook, /attach-role-policy/);
  assert.match(runbook, /507/);
  assert.match(runbook, /6,144/);
  assert.match(runbook, /actual AWS-managed-policy\s+version ID/i);
});

test("historical policy bytes remain unchanged while the active v4 correction is explicit", () => {
  assert.equal(sha256(read(paths.v4)), "9beed6d3a684fd98f16fabdf63ef02a231bb9cf60e6af906e432c70eeeabd62a");
  assert.equal(sha256(read(paths.audit)), "56b299c2f21973a3117e89e5147658406d3ba823efab2b5548ac1b0d9f93dde6");
});

test("runbook is companion-first and verifies complete policy attachments before provider mutation", () => {
  const runbook = read("documents/ops/iam/PRODUCTION_GREEN_STAGE_B_PROVIDER_RECOVERY_2026-07-29.md");
  const providerUpdate = runbook.indexOf('PROVIDER_VERSION_ID="$(aws iam create-policy-version');
  const finalWriteSetup = runbook.indexOf("# D. Final-write companion create/update");
  const finalWriteAttach = runbook.indexOf('aws iam attach-role-policy --role-name "$ROLE_NAME" --policy-arn "$FINAL_WRITE_POLICY_ARN"');
  const finalWriteVerify = runbook.indexOf('verify_complete_policy_entities "$FINAL_WRITE_POLICY_ARN" "$FINAL_WRITE_POLICY_NAME"');
  const finalAttachmentCheck = runbook.lastIndexOf("# G. Final three-policy role verification");
  assert.ok(providerUpdate > 0);
  assert.ok(finalWriteSetup > 0 && finalWriteSetup < providerUpdate);
  assert.ok(finalWriteAttach > finalWriteSetup && finalWriteAttach < providerUpdate);
  assert.ok(finalWriteVerify > finalWriteAttach && finalWriteVerify < providerUpdate);
  assert.ok(finalAttachmentCheck > providerUpdate);
  for (const marker of [
    "# A. Pre-mutation validation",
    "# B. Companion create/update",
    "# C. Companion attach and complete verification",
    "# D. Final-write companion create/update",
    "# E. Provider v4 update",
    "# F. Provider and unchanged audit verification",
    "# G. Final three-policy role verification",
    "H. Root/admin logout and fresh MFA release session",
  ]) assert.ok(runbook.indexOf(marker) >= 0, marker);
  for (const marker of [
    "aws iam create-policy",
    "AUDIT_VERSION_ID=\"$(aws iam create-policy-version",
    "aws iam attach-role-policy --role-name \"$ROLE_NAME\" --policy-arn \"$AUDIT_POLICY_ARN\"",
    "cmp <(jq -S . \"$AUDIT_DOCUMENT\") <(jq -S . \"$TMP_DIR/live-audit-policy.json\")",
    'reject_unexpected_entities "$PROVIDER_POLICY_ARN" "$TMP_DIR/provider-entities.json" true',
    'reject_unexpected_entities "$AUDIT_POLICY_ARN" "$TMP_DIR/audit-entities.json" false',
    'verify_complete_policy_entities "$AUDIT_POLICY_ARN" "$AUDIT_POLICY_NAME"',
    "simulate_audit_read iam:ListAttachedRolePolicies",
  ]) assert.ok(runbook.indexOf(marker) >= 0 && runbook.indexOf(marker) < providerUpdate, marker);
  for (const marker of [
    "FINAL_WRITE_VERSION_COUNT",
    "FINAL_WRITE_DEFAULT_VERSION_ID",
    "if cmp <(jq -S . \"$FINAL_WRITE_DOCUMENT\")",
    "if [[ \"$FINAL_WRITE_ATTACHED\" = false ]]",
    "aws iam create-policy --policy-name \"$FINAL_WRITE_POLICY_NAME\"",
    'verify_complete_policy_entities "$FINAL_WRITE_POLICY_ARN" "$FINAL_WRITE_POLICY_NAME"',
  ]) assert.ok(runbook.indexOf(marker) > finalWriteSetup && runbook.indexOf(marker) < providerUpdate, marker);
  assert.ok(runbook.indexOf("aws iam list-policy-versions") < providerUpdate);
  assert.ok(runbook.indexOf("aws iam get-account-summary") < providerUpdate);
  assert.ok(runbook.indexOf("aws iam list-entities-for-policy") < providerUpdate);
  assert.ok(runbook.indexOf('verify_complete_policy_entities "$PROVIDER_POLICY_ARN" "$PROVIDER_POLICY_NAME"') > providerUpdate);
  assert.match(runbook, /\.Policy\.AttachmentCount/);
  assert.match(runbook, /\.Policy\.PermissionsBoundaryUsageCount/);
  assert.match(runbook, /\.PolicyRoles \| length/);
  assert.match(runbook, /\.PolicyGroups \| length/);
  assert.match(runbook, /\.PolicyUsers \| length/);
  assert.match(runbook, /mscqr-production-release-deployer/);
  assert.match(runbook, /do not automatically roll back/i);
});
