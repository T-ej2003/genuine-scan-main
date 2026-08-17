import { STAGE_B } from "../../aws/production-green-stage-b-contract.mjs";
import { STAGE_A_CHECKER_PUBLICATION_POLICY, STAGE_A_CHECKER_ROLE_TRUST } from "../../aws/production-stage-a-control-plane.mjs";

export const STAGE_A_LINEAGE = "02afb75a-f902-ab8a-f4c1-751d4aef7837";
export const STAGE_A_STATE_OBJECT = "mscqr/production/rls-green/stage-a/terraform.tfstate";

const roleSecrets = Object.fromEntries(["app", "read", "preauth", "worker", "scheduled", "operator", "migration"].map((role) => [role, `arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/database-url/${role}-abc123`]));
const resource = (type, name, attributes) => ({ type, name, mode: "managed", instances: [{ schema_version: 0, attributes }] });
const policy = (value) => JSON.stringify(value);

export function productionStageAState({ serial = 42, endpointSecurityGroupId = "sg-0123456789abcdef0", mutate } = {}) {
  const state = {
    version: 4,
    serial,
    lineage: STAGE_A_LINEAGE,
    outputs: { stage_b_prerequisites: { value: {
      approval_kms_key_arn: STAGE_B.approvalKmsKeyArn,
      approval_secret_arn: STAGE_B.approvalSecretArn,
      executor_role_arn: STAGE_B.executorRoleArn,
      broker_role_arn: STAGE_B.brokerRoleArn,
      database_security_group_id: STAGE_B.databaseSecurityGroupId,
      executor_security_group_id: STAGE_B.executorSecurityGroupId,
      executor_log_group_name: "/ecs/mscqr-production/full-rls-green",
      executor_log_group_arn: "arn:aws:logs:eu-west-2:368992683803:log-group:/ecs/mscqr-production/full-rls-green:*",
      broker_log_group_name: "/aws/lambda/mscqr-production-rls-approval-broker",
      broker_log_group_arn: "arn:aws:logs:eu-west-2:368992683803:log-group:/aws/lambda/mscqr-production-rls-approval-broker:*",
      runtime_secret_arns: roleSecrets,
      read_only_canary_database_secret_arn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase4/read-only-canary-database-url-abc123",
    } } },
    resources: [
      ...["ecr.api", "ecr.dkr", "logs", "secretsmanager", "kms"].map((service) => resource("aws_vpc_endpoint", "executor", { vpc_id: "vpc-0123456789abcdef0", service_name: `com.amazonaws.${STAGE_B.region}.${service}`, subnet_ids: [...STAGE_B.privateSubnetIds] })),
      resource("aws_db_instance", "green", { identifier: "mscqr-production-rls-green" }),
      resource("aws_security_group", "executor_endpoints", { id: endpointSecurityGroupId }),
      resource("aws_security_group", "database", { id: STAGE_B.databaseSecurityGroupId }),
      resource("aws_security_group", "executor", { id: STAGE_B.executorSecurityGroupId }),
      resource("aws_iam_role", "executor", { arn: STAGE_B.executorRoleArn, assume_role_policy: policy({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: "ecs-tasks.amazonaws.com" }, Action: "sts:AssumeRole" }] }) }),
      resource("aws_iam_role", "broker", { arn: STAGE_B.brokerRoleArn, assume_role_policy: policy({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: "lambda.amazonaws.com" }, Action: "sts:AssumeRole" }] }) }),
      resource("aws_iam_role", "checker", { arn: STAGE_B.checkerRoleArn, assume_role_policy: policy({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: STAGE_A_CHECKER_ROLE_TRUST.principal }, Action: STAGE_A_CHECKER_ROLE_TRUST.action }] }) }),
      resource("aws_kms_key", "approval", { arn: STAGE_B.approvalKmsKeyArn }),
      resource("aws_kms_key", "root_drop", { arn: "arn:aws:kms:eu-west-2:368992683803:key/11111111-1111-1111-1111-111111111111", key_usage: "SIGN_VERIFY", customer_master_key_spec: "RSA_3072", policy: policy({ Version: "2012-10-17", Statement: [
        { Sid: "AccountAdministration", Effect: "Allow", Principal: { AWS: "arn:aws:iam::368992683803:root" }, Action: "kms:*", Resource: "*" },
        { Sid: "DenyNonRootRootDropSigning", Effect: "Deny", Principal: "*", Action: ["kms:Sign", "kms:Verify"], Resource: "*", Condition: { StringNotEquals: { "aws:PrincipalArn": "arn:aws:iam::368992683803:root" } } },
        { Sid: "ReleaseReadsRootDropKey", Effect: "Allow", Principal: { AWS: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer" }, Action: ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetPublicKey", "kms:ListResourceTags"], Resource: "*" },
      ] }) }),
      resource("aws_kms_alias", "root_drop", { arn: STAGE_B.rootDropKmsKeyArn, target_key_arn: "arn:aws:kms:eu-west-2:368992683803:key/11111111-1111-1111-1111-111111111111" }),
      resource("aws_secretsmanager_secret", "approval", { arn: STAGE_B.approvalSecretArn }),
      resource("aws_iam_role_policy", "checker_assume_target", { policy: policy({ Version: "2012-10-17", Statement: [{ Sid: "AssumeExactRlsIndependentChecker", Effect: "Allow", Action: "sts:AssumeRole", Resource: "arn:aws:iam::368992683803:role/mscqr-production-rls-independent-checker" }] }) }),
      resource("aws_iam_role_policy", "checker", { policy: policy({ Version: "2012-10-17", Statement: [{ Sid: "SignExactStageBApproval", Effect: "Allow", Action: STAGE_A_CHECKER_PUBLICATION_POLICY.kmsAction, Resource: STAGE_A_CHECKER_PUBLICATION_POLICY.kmsResource }, { Sid: "PublishExactStageBApproval", Effect: "Allow", Action: STAGE_A_CHECKER_PUBLICATION_POLICY.publishAction, Resource: STAGE_A_CHECKER_PUBLICATION_POLICY.publishResource }] }) }),
    ],
  };
  return mutate ? mutate(state) || state : state;
}

export function productionStageAIngress(endpointSecurityGroupId = "sg-0123456789abcdef0") {
  return { present: true, endpointSecurityGroupId, runtimeSecurityGroupId: STAGE_B.executorSecurityGroupId, direction: "ingress", protocol: "tcp", fromPort: 443, toPort: 443 };
}
