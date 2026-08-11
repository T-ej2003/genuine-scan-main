variable "account_id" { type = string }
variable "aws_region" { type = string }
variable "deployment_environment" { type = string }
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
variable "stage_b_recovery_only" {
  type    = bool
  default = false
}
variable "production_rotation_enabled" {
  type    = bool
  default = false
}
variable "production_rotation_cleanup_enabled" {
  type    = bool
  default = false
}
variable "production_rotation_secret_value_from" {
  type = object({
    jwt_current               = string
    jwt_previous              = string
    qr_private_current        = string
    qr_public_current         = string
    qr_current_version        = string
    qr_public_previous        = string
    qr_previous_version       = string
    artifact_private_current  = string
    artifact_public_current   = string
    artifact_active_version   = string
    artifact_public_keys_json = string
  })
  default = {
    jwt_current               = ""
    jwt_previous              = ""
    qr_private_current        = ""
    qr_public_current         = ""
    qr_current_version        = ""
    qr_public_previous        = ""
    qr_previous_version       = ""
    artifact_private_current  = ""
    artifact_public_current   = ""
    artifact_active_version   = ""
    artifact_public_keys_json = ""
  }
  validation {
    condition = !var.production_rotation_enabled || alltrue([
      for value in values(var.production_rotation_secret_value_from) : can(regex("^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:.+:[A-Za-z0-9_-]+::$", value))
    ])
    error_message = "Production rotation task definitions require exact Secrets Manager JSON-key valueFrom references when enabled."
  }
}
variable "stage_b_recovery_alias_target_version" {
  type     = string
  nullable = true
  default  = null
  validation {
    condition     = var.stage_b_recovery_alias_target_version == null || can(regex("^[1-9][0-9]*$", var.stage_b_recovery_alias_target_version))
    error_message = "Stage B recovery alias targets must be positive published Lambda version strings; $LATEST is forbidden."
  }
}
variable "stage_b_recovery_broker_environment" {
  type    = map(string)
  default = {}
}
variable "stage_b_recovery_task_definition_arns" {
  type    = map(string)
  default = {}
}
variable "stage_b_recovery_execution_secret_arns" {
  type    = map(list(string))
  default = {}
}
variable "tooling_sha" { type = string }
variable "image_release_sha" { type = string }
variable "canonical_image_evidence_sha256" { type = string }
variable "source_contract_sha256" { type = string }
variable "migration_set_digest" { type = string }
variable "package_checksum_sha256" { type = string }
variable "backend_image" { type = string }
variable "worker_image" { type = string }
variable "executor_image" { type = string }
variable "canary_image" { type = string }
variable "read_only_canary_image" { type = string }
variable "stage_a_read_only_canary_database_secret_arn" { type = string }
variable "retained_candidate_task_definitions" {
  type = map(object({
    kind       = string
    definition = string
  }))
  default = {}
  validation {
    condition = alltrue([
      for history_key, entry in var.retained_candidate_task_definitions :
      can(regex("^[a-f0-9]{7,40}-(backend|worker|canary|read_only_canary)$", history_key)) &&
      can(regex("^(backend|worker|canary|read_only_canary)$", entry.kind)) &&
      can(jsondecode(entry.definition).family)
    ])
    error_message = "Retained candidate task definitions require revision-keyed history entries and valid JSON definitions."
  }
}
variable "retained_executor_task_definitions" {
  type = map(object({
    mode       = string
    definition = string
  }))
  default = {}
  validation {
    condition = alltrue([
      for history_key, entry in var.retained_executor_task_definitions :
      can(regex("^[a-f0-9]{7,40}-full-rls-(admin-bootstrap|admin-ownership|capability-preflight|role-provision|role-verify|rollback|runtime-policy|verification)$", history_key)) &&
      can(regex("^full-rls-(admin-bootstrap|admin-ownership|capability-preflight|role-provision|role-verify|rollback|runtime-policy|verification)$", entry.mode)) &&
      can(jsondecode(entry.definition).family)
    ])
    error_message = "Retained executor task definitions require revision-keyed history entries and valid JSON definitions."
  }
}
variable "log_retention_days" {
  type    = number
  default = 30
}

check "production_only" {
  assert {
    condition     = var.account_id == "368992683803" && var.aws_region == "eu-west-2" && var.deployment_environment == "production"
    error_message = "Stage B requires the production deployment environment in eu-west-2 account 368992683803."
  }
}

check "production_rotation_contract" {
  assert {
    condition = (!var.production_rotation_cleanup_enabled || var.production_rotation_enabled) && (!var.production_rotation_enabled || (
      alltrue([
        for value in values(var.production_rotation_secret_value_from) : can(regex("^arn:aws:secretsmanager:${var.aws_region}:${var.account_id}:secret:.+:[A-Za-z0-9_-]+::$", value))
      ]) &&
      var.production_rotation_secret_value_from.jwt_current != var.production_rotation_secret_value_from.jwt_previous &&
      var.production_rotation_secret_value_from.qr_public_current != var.production_rotation_secret_value_from.qr_public_previous &&
      var.production_rotation_secret_value_from.qr_current_version != var.production_rotation_secret_value_from.qr_previous_version &&
      var.production_rotation_secret_value_from.artifact_active_version != ""
    ))
    error_message = "Production rotation current and previous secret references/version references must be distinct."
  }
}

check "recovery_mode_bindings" {
  assert {
    condition = var.stage_b_recovery_only ? (
      var.stage_b_recovery_alias_target_version != null &&
      toset(keys(var.stage_b_recovery_broker_environment)) == toset([
        "BROKER_APPROVAL_EXPECTED_JSON", "BROKER_APPROVAL_SECRET_ARN", "BROKER_CLUSTER_ARN",
        "BROKER_EXECUTOR_SECURITY_GROUP_ID", "BROKER_IMAGES_JSON", "BROKER_PRIVATE_SUBNETS_JSON",
        "BROKER_RECEIPT_BUCKET", "BROKER_REPLAY_TABLE", "BROKER_TASK_DEFINITIONS_JSON", "BROKER_TASK_TEMPLATE_HASHES_JSON"
      ]) &&
      toset(keys(var.stage_b_recovery_task_definition_arns)) == toset([
        "full-rls-admin-bootstrap", "full-rls-admin-ownership", "full-rls-application-canary",
        "full-rls-capability-preflight", "full-rls-role-provision", "full-rls-role-verify",
        "full-rls-rollback", "full-rls-runtime-policy", "full-rls-verification"
      ]) &&
      toset(keys(var.stage_b_recovery_execution_secret_arns)) == toset(["backend", "worker", "executor", "canary", "read_only_canary"])
      ) : (
      var.stage_b_recovery_alias_target_version == null &&
      length(var.stage_b_recovery_broker_environment) == 0 &&
      length(var.stage_b_recovery_task_definition_arns) == 0 &&
      length(var.stage_b_recovery_execution_secret_arns) == 0
    )
    error_message = "Stage B recovery-only mode must be completely state-bound; normal releases must not carry recovery overrides."
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
    condition     = can(regex("^[a-f0-9]{40}$", var.tooling_sha)) && can(regex("^[a-f0-9]{40}$", var.image_release_sha)) && can(regex("^[a-f0-9]{64}$", var.canonical_image_evidence_sha256)) && can(regex("^[a-f0-9]{64}$", var.source_contract_sha256)) && can(regex("^[a-f0-9]{64}$", var.migration_set_digest)) && can(regex("^[a-f0-9]{64}$", var.package_checksum_sha256))
    error_message = "Stage B requires tooling, image-release, image-evidence, and sealed-package digests."
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
    condition     = can(regex("^arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase4/read-only-canary-database-url-[A-Za-z0-9]+$", var.stage_a_read_only_canary_database_secret_arn))
    error_message = "Phase 4 requires the exact dedicated read-only canary database secret ARN from Stage A prerequisites."
  }
}

check "retained_task_definition_families" {
  assert {
    condition = alltrue([
      for history_key, entry in var.retained_candidate_task_definitions :
      jsondecode(entry.definition).family == (
        entry.kind == "canary" ? "mscqr-production-full-rls-green-application-canary" :
        entry.kind == "read_only_canary" ? "mscqr-production-full-rls-green-read-only-canary" :
        "mscqr-production-rls-green-${entry.kind}-candidate"
      )
      ]) && alltrue([
      for history_key, entry in var.retained_executor_task_definitions :
      jsondecode(entry.definition).family == "mscqr-production-full-rls-green-${entry.mode}"
    ])
    error_message = "Retained task-definition history must preserve the exact Stage B family for each keyed entry."
  }
}
