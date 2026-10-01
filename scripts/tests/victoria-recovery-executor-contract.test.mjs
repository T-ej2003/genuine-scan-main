import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { renderTaskDefinition } from "../aws/register-victoria-recovery-task-definition.mjs";
import { VICTORIA_RECOVERY_IMPLEMENTATION_FILES } from "../aws/victoria-recovery-authorization.mjs";

const read = (file) => fs.readFileSync(new URL(file, import.meta.url), "utf8");
const env = () => ({
  VICTORIA_RECOVERY_EXECUTION_ROLE_ARN: "arn:aws:iam::368992683803:role/mscqr-production-victoria-recovery-execution",
  VICTORIA_RECOVERY_TASK_ROLE_ARN: "arn:aws:iam::368992683803:role/mscqr-production-victoria-recovery-task",
  VICTORIA_RECOVERY_IMAGE: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-victoria-recovery@sha256:${"a".repeat(64)}`,
  VICTORIA_RDS_HOST: "mscqr-prod.cluster-abcdefghijkl.eu-west-2.rds.amazonaws.com",
  VICTORIA_RECOVERY_EVIDENCE_BUCKET: "mscqr-victoria-recovery-evidence",
  VICTORIA_RECOVERY_EVIDENCE_KMS_KEY_ARN: "arn:aws:kms:eu-west-2:368992683803:key/123e4567-e89b-42d3-a456-426614174001",
  VICTORIA_RECOVERY_SIGNING_KEY_ARN: "arn:aws:kms:eu-west-2:368992683803:key/123e4567-e89b-42d3-a456-426614174000",
  VICTORIA_RECOVERY_LOG_GROUP: "/ecs/mscqr-production/victoria-recovery",
});

test("registered task definition has only the fixed image, entrypoint, roles, and no command override", () => {
  const task = renderTaskDefinition(env());
  const [container] = task.containerDefinitions;
  assert.equal(task.family, "mscqr-production-victoria-recovery");
  assert.deepEqual(container.entryPoint, ["node", "/app/backend/scripts/victoria-failed-onboarding-recovery.mjs"]);
  assert.deepEqual(container.command, []);
  assert.equal(container.readonlyRootFilesystem, true);
  assert.equal(container.privileged, false);
  assert.deepEqual(container.secrets, undefined);
  assert.equal(Object.hasOwn(container, "portMappings"), false);
  assert.equal(container.environment.some(({ name }) => /email|database|sql|command|target/i.test(name)), false);
});

test("task renderer rejects substituted image, roles, endpoint, evidence bucket, and signer", () => {
  for (const [key, value] of Object.entries({
    VICTORIA_RECOVERY_IMAGE: "public/image:latest",
    VICTORIA_RECOVERY_TASK_ROLE_ARN: "arn:aws:iam::368992683803:role/admin",
    VICTORIA_RECOVERY_EXECUTION_ROLE_ARN: "arn:aws:iam::368992683803:role/admin",
    VICTORIA_RDS_HOST: "public.example.com",
    VICTORIA_RECOVERY_EVIDENCE_BUCKET: "OTHER_BUCKET",
    VICTORIA_RECOVERY_EVIDENCE_KMS_KEY_ARN: "arn:aws:kms:us-east-1:111122223333:key/123e4567-e89b-42d3-a456-426614174001",
    VICTORIA_RECOVERY_SIGNING_KEY_ARN: "arn:aws:kms:us-east-1:111122223333:key/123e4567-e89b-42d3-a456-426614174000",
  })) assert.throws(() => renderTaskDefinition({ ...env(), [key]: value }), key);
});

test("workflow and broker accept one fixed operation and always attempt authority cleanup", () => {
  const workflow = read("../../.github/workflows/execute-victoria-onboarding-recovery.yml");
  const broker = read("../../infra/aws/terraform/lambda/victoria-recovery-broker/index.mjs");
  const taskCleanup = read("../../infra/aws/terraform/lambda/victoria-recovery-broker/task-cleanup.mjs");
  const infrastructure = read("../../infra/aws/terraform/production-victoria-recovery/main.tf");
  assert.match(infrastructure, /timeout\s+=\s+120/);
  assert.match(infrastructure, /aws_cloudwatch_event_rule" "task_stopped/);
  assert.match(infrastructure, /lastStatus\s+=\s+\["STOPPED"\]/);
  assert.match(infrastructure, /source_arn\s+=\s+aws_cloudwatch_event_rule\.task_stopped\.arn/);
  assert.match(workflow, /environment: production-victoria-recovery/);
  assert.match(workflow, /if: always\(\) && steps\.authorize\.outputs\.nonce != ''/);
  assert.match(workflow, /"phase":"cleanup"/);
  assert.doesNotMatch(workflow, /workflow_dispatch:\s*\n\s+inputs:/);
  assert.doesNotMatch(workflow, /mfa\s*[:=]\s*true/i);
  assert.match(broker, /event\.operation !== OPERATION/);
  assert.match(broker, /RECOVERY_BROKER_REQUEST_INVALID/);
  assert.match(broker, /\["PENDING", "RUNNING"\]/);
  assert.match(broker, /activeRecoveryTasks\(cluster\)/);
  assert.match(broker, /StopTaskCommand/);
  assert.doesNotMatch(broker, /ListTasksCommand\(\{ cluster, startedBy: event\.nonce, (?:family|desiredStatus):/);
  assert.match(broker, /AuthorizationNonce/);
  assert.match(broker, /SourceSha/);
  assert.match(broker, /cleanupStoppedTaskEvent/);
  assert.match(broker, /networkAuthorityRevoked, taskStopped/);
  assert.match(broker, /noTaskLaunchProven: !runTaskAttempted/);
  assert.ok(broker.indexOf("AuthorizeSecurityGroupIngressCommand({") > broker.indexOf("try {", broker.indexOf("let runTaskAttempted")),
    "ingress creation must be inside the launch cleanup boundary");
  assert.doesNotMatch(broker, /SecurityGroupRuleIds: \[ingress\.SecurityGroupRules\[0\]\.SecurityGroupRuleId\]/);
  assert.match(broker, /stopVictoriaRecoveryTasks/);
  assert.match(broker, /persistVictoriaRecoveryCleanup/);
  assert.doesNotMatch(broker, /ListTasksCommand\(\{ cluster, startedBy: event\.nonce, desiredStatus:/);
  assert.match(taskCleanup, /listTasks\(\{ cluster, startedBy: nonce \}\)/);
  assert.match(taskCleanup, /RECOVERY_CLEANUP_INCOMPLETE_EVIDENCE_PERSISTED/);
  assert.ok(taskCleanup.indexOf("await putEvidence(receipt)") < taskCleanup.indexOf("RECOVERY_CLEANUP_INCOMPLETE_EVIDENCE_PERSISTED"),
    "cleanup failure evidence is written before the broker fails");
  assert.match(broker, /containerOverrides: \[\{ name: "recovery", environment:/);
  assert.doesNotMatch(broker, /containerOverrides: \[\{[^}]*command\s*:/s);
  assert.match(broker, /AuthorizeSecurityGroupIngressCommand/);
  assert.match(broker, /RevokeSecurityGroupIngressCommand/);
  assert.match(workflow, /victoria-recovery-result\.mjs --result/);
  assert.doesNotMatch(workflow, /r\.targetEmail|r\.targetDatabase|r\.pruneComplete/);
  assert.match(infrastructure, /ingress\s+=\s+\[\]\s+egress\s+=\s+\[\]/);
  assert.match(infrastructure, /resource "aws_vpc_security_group_egress_rule" "dns_udp"/);
  assert.match(infrastructure, /resource "aws_vpc_security_group_egress_rule" "dns_tcp"/);
  assert.match(infrastructure, /\$\{cidrhost\(var\.vpc_cidr_block, 2\)\}\/32/);
  assert.doesNotMatch(infrastructure, /aws_vpc_security_group_ingress_rule/);
});

test("broker IAM permits only tag-on-RunTask for the fixed recovery task identity", () => {
  const infrastructure = read("../../infra/aws/terraform/production-victoria-recovery/main.tf");
  const broker = read("../../infra/aws/terraform/lambda/victoria-recovery-broker/index.mjs");
  assert.match(broker, /new RunTaskCommand\(\{[\s\S]*?tags: \[\{ key: "Operation", value: OPERATION \}, \{ key: "AuthorizationNonce", value: event\.nonce \}, \{ key: "SourceSha", value: event\.sourceSha \}\]/);
  assert.match(infrastructure, /Action = "ecs:TagResource", Resource = "arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/\*"/);
  assert.match(infrastructure, /"ecs:CreateAction" = "RunTask"/);
  assert.match(infrastructure, /"aws:RequestTag\/Operation" = local\.common_tags\.Operation/);
  assert.match(infrastructure, /"aws:TagKeys" = \["Operation", "AuthorizationNonce", "SourceSha"\]/);
  assert.doesNotMatch(infrastructure, /Action = "ecs:TagResource", Resource = "\*"/);
  assert.match(infrastructure, /s3:GetObject"[^\n]+\/authorizations\/\*"[^\n]+\/tasks\/\*"/);
  assert.match(infrastructure, /Action = "ecs:DescribeTaskDefinition", Resource = "\*"/);
  assert.doesNotMatch(infrastructure, /kms:Encrypt/);
  assert.match(infrastructure, /s3:x-amz-server-side-encryption-aws-kms-key-id/);
  for (const source of [broker, read("../../backend/scripts/victoria-failed-onboarding-recovery.mjs")]) {
    assert.match(source, /ServerSideEncryption: "aws:kms", SSEKMSKeyId:/);
  }
  assert.match(read("../aws/publish-victoria-recovery-authorization.mjs"), /--ssekms-key-id/);
});

test("database failure and postcondition failure abort the Prisma serializable transaction", () => {
  const sql = read("../../backend/src/rls-waves/session-c/c05/victoriaRecovery.template.sql");
  const executor = read("../../backend/scripts/victoria-failed-onboarding-recovery.mjs");
  assert.match(sql, /pg_advisory_xact_lock\(hashtextextended\('platform:' \|\| target_email, 0\)\)/);
  assert.match(sql, /VICTORIA_RECOVERY_USER_COMPARE_AND_SET_FAILED/);
  assert.match(sql, /VICTORIA_RECOVERY_POSTCONDITION_FAILED/);
  assert.match(sql, /VICTORIA_RECOVERY_AUDIT_PRESERVATION_FAILED/);
  assert.match(executor, /isolationLevel: "Serializable"/);
  assert.match(executor, /transactionError/);
  assert.match(executor, /cleanupError/);
});

test("every source bound into the authorization checksum is present in the executor image", () => {
  const dockerfile = read("../../infra/aws/terraform/production-victoria-recovery/Dockerfile");
  const terraform = read("../../infra/aws/terraform/production-victoria-recovery/main.tf");
  for (const source of VICTORIA_RECOVERY_IMPLEMENTATION_FILES) {
    assert.ok(dockerfile.includes(` ${source} /app/${source}`), `executor image must contain checksum source ${source}`);
    assert.ok(terraform.includes(`filename  = "${source}"`) || terraform.includes(`filename = "${source}"`), `broker archive must contain checksum source ${source}`);
  }
  const executor = read("../../backend/scripts/victoria-failed-onboarding-recovery.mjs");
  assert.match(executor, /container\.Image !== image/);
  assert.match(executor, /\(\?:@\)\?sha256:/);
  assert.match(executor, /4\[0-9a-f\]\{3\}-\[89ab\]\[0-9a-f\]\{3\}/);
  assert.doesNotMatch(executor, /4\[0-9a-f\]\{4\}-\[89ab\]/);
});
