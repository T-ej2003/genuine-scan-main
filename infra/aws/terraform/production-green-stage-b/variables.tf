variable "account_id" { type = string }
variable "aws_region" { type = string }
variable "vpc_id" { type = string }
variable "private_subnet_ids" { type = set(string) }
variable "ecs_cluster_arn" { type = string }
variable "stage_a_database_security_group_id" { type = string }
variable "stage_a_executor_security_group_id" { type = string }
variable "stage_a_executor_task_role_arn" { type = string }
variable "stage_a_broker_role_arn" { type = string }
variable "stage_a_executor_log_group_name" { type = string }
variable "stage_a_executor_log_group_arn" { type = string }
variable "stage_a_broker_log_group_name" { type = string }
variable "stage_a_broker_log_group_arn" { type = string }
variable "stage_a_runtime_secret_arns" { type = map(string) }
variable "stage_a_executor_networking_ready" { type = bool }
variable "approval_secret_arn" { type = string }
variable "approval_kms_key_arn" { type = string }
variable "receipt_bucket_arn" { type = string }
variable "broker_package_path" { type = string }
variable "release_sha" { type = string }
variable "source_contract_sha256" { type = string }
variable "migration_set_digest" { type = string }
variable "package_checksum_sha256" { type = string }
variable "backend_image" { type = string }
variable "worker_image" { type = string }
variable "executor_image" { type = string }
variable "canary_image" { type = string }
variable "read_only_canary_image" { type = string }
variable "read_only_canary_database_secret_arn" { type = string }
variable "log_retention_days" {
  type    = number
  default = 30
}

check "production_only" {
  assert {
    condition     = var.account_id == "368992683803" && var.aws_region == "eu-west-2" && terraform.workspace == "production"
    error_message = "Stage B requires the production workspace in eu-west-2 account 368992683803."
  }
}

check "stage_a_bindings" {
  assert {
    condition = (
      var.vpc_id != "" &&
      var.ecs_cluster_arn == "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main" &&
      var.stage_a_database_security_group_id == "sg-0703d3f227f35b81c" &&
      var.stage_a_executor_security_group_id == "sg-051a24aedff773761" &&
      var.stage_a_executor_task_role_arn == "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-executor-task" &&
      var.stage_a_broker_role_arn == "arn:aws:iam::368992683803:role/mscqr-production-rls-approval-broker" &&
      var.stage_a_executor_log_group_name == "/ecs/mscqr-production/full-rls-green" &&
      var.stage_a_broker_log_group_name == "/aws/lambda/mscqr-production-rls-approval-broker" &&
      can(regex("^arn:aws:logs:eu-west-2:368992683803:log-group:/ecs/mscqr-production/full-rls-green(?::\\*)?$", var.stage_a_executor_log_group_arn)) &&
      can(regex("^arn:aws:logs:eu-west-2:368992683803:log-group:/aws/lambda/mscqr-production-rls-approval-broker(?::\\*)?$", var.stage_a_broker_log_group_arn)) &&
      var.stage_a_executor_networking_ready
    )
    error_message = "Stage B requires the exact applied Stage A database, executor, broker, log, and reviewed-network bindings."
  }
}

check "stage_a_runtime_secrets" {
  assert {
    condition = (
      toset(keys(var.stage_a_runtime_secret_arns)) == toset(["app", "read", "preauth", "worker", "scheduled", "operator", "migration"]) &&
      alltrue([
        for role, arn in var.stage_a_runtime_secret_arns :
        can(regex("^arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/database-url/${role}-[A-Za-z0-9]+$", arn))
      ])
    )
    error_message = "Stage B requires every exact Stage A runtime-role secret ARN and no additional secret."
  }
}

check "stage_a_release_resources" {
  assert {
    condition = (
      var.approval_secret_arn == "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/approval-e0shho" &&
      var.approval_kms_key_arn == "arn:aws:kms:eu-west-2:368992683803:key/437cdebd-95e7-4aba-8f0f-2ca08edb0478" &&
      var.receipt_bucket_arn == "arn:aws:s3:::mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an" &&
      length(var.private_subnet_ids) == 2 &&
      toset(var.private_subnet_ids) == toset(["subnet-068d949017bd2ce45", "subnet-07e0a76e3a5241138"]) &&
      fileexists(var.broker_package_path)
    )
    error_message = "Stage B requires the exact reviewed Stage A release resources, private subnets, and local broker package."
  }
}

check "release_bindings" {
  assert {
    condition     = can(regex("^[a-f0-9]{40}$", var.release_sha)) && can(regex("^[a-f0-9]{64}$", var.source_contract_sha256)) && can(regex("^[a-f0-9]{64}$", var.migration_set_digest)) && can(regex("^[a-f0-9]{64}$", var.package_checksum_sha256))
    error_message = "Stage B requires complete release and sealed-package digests."
  }
}

check "immutable_images" {
  assert {
    condition     = alltrue([for image in [var.backend_image, var.worker_image, var.executor_image, var.canary_image, var.read_only_canary_image] : can(regex("^368992683803\\.dkr\\.ecr\\.eu-west-2\\.amazonaws\\.com/mscqr-(backend|worker)@sha256:[a-f0-9]{64}$", image))])
    error_message = "Stage B accepts immutable reviewed ECR digests only."
  }
}

check "read_only_canary_secret" {
  assert {
    condition     = can(regex("^arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase4/read-only-canary-database-url-[A-Za-z0-9]+$", var.read_only_canary_database_secret_arn))
    error_message = "Phase 4 requires the exact dedicated read-only canary database secret ARN."
  }
}
