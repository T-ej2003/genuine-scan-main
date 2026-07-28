variable "aws_region" {
  type        = string
  description = "AWS region for the ECS/ECR stack."

  validation {
    condition     = var.aws_region == "eu-west-2"
    error_message = "Production infrastructure is locked to eu-west-2."
  }
}

variable "name_prefix" {
  type        = string
  description = "Resource prefix, for example mscqr-prod."
}

variable "tags" {
  type        = map(string)
  description = "Common AWS tags."
  default     = {}
}

variable "cluster_name" {
  type        = string
  description = "ECS cluster name."
}

variable "vpc_id" {
  type        = string
  description = "VPC ID for ECS services."
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnets for ECS services."
}

variable "service_security_group_ids" {
  type        = list(string)
  description = "Security groups attached to ECS tasks."
}

variable "backend_execution_role_arn" {
  type        = string
  description = "Execution role ARN for backend task definition."
}

variable "backend_task_role_arn" {
  type        = string
  description = "Task role ARN for backend task definition."
}

variable "worker_execution_role_arn" {
  type        = string
  description = "Execution role ARN for worker task definition."
}

variable "worker_task_role_arn" {
  type        = string
  description = "Task role ARN for worker task definition."
}

variable "backend_container_definitions_json" {
  type        = string
  description = "Full JSON string for backend container definitions."
}

variable "worker_container_definitions_json" {
  type        = string
  description = "Full JSON string for worker container definitions."
}

variable "backend_cpu" {
  type        = string
  description = "Backend task CPU units."
  default     = "512"
}

variable "backend_memory" {
  type        = string
  description = "Backend task memory in MiB."
  default     = "1024"
}

variable "worker_cpu" {
  type        = string
  description = "Worker task CPU units."
  default     = "512"
}

variable "worker_memory" {
  type        = string
  description = "Worker task memory in MiB."
  default     = "1024"
}

variable "backend_desired_count" {
  type        = number
  description = "Desired backend task count."
  default     = 2
}

variable "worker_desired_count" {
  type        = number
  description = "Desired worker task count."
  default     = 1
}

variable "backend_container_name" {
  type        = string
  description = "Backend container definition name."
  default     = "backend"
}

variable "worker_container_name" {
  type        = string
  description = "Worker container definition name."
  default     = "worker"
}

variable "backend_container_port" {
  type        = number
  description = "Backend container port for ALB target group registration."
  default     = 4000
}

variable "backend_target_group_arn" {
  type        = string
  description = "ALB target group ARN for backend service. Leave null for internal-only service bootstrap."
  default     = null
}

variable "backend_health_check_grace_period_seconds" {
  type        = number
  description = "Backend health check grace period."
  default     = 120
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch log retention days."
  default     = 30
}

variable "ecr_keep_release_images" {
  type        = number
  description = "How many recent release images to retain in ECR."
  default     = 120
}

variable "ecr_untagged_expiry_days" {
  type        = number
  description = "How many days untagged ECR images are kept."
  default     = 7
}

variable "enable_container_insights" {
  type        = bool
  description = "Enable ECS Container Insights."
  default     = true
}

variable "enable_full_rls_green_infrastructure" {
  type        = bool
  description = "Provision the isolated production green database, approval key, roles, and secret handles without enabling execution."
  default     = false
}

variable "enable_full_rls_green_executor" {
  type        = bool
  description = "Provision release-bound fixed task definitions and the reviewed approval broker."
  default     = false
}

variable "activate_full_rls_green_runtime" {
  type        = bool
  description = "Replace backend and worker database secret wiring with the complete green restricted-runtime set."
  default     = false
}

variable "full_rls_green_release_sha" {
  type        = string
  description = "Exact release commit approved for the production green package."
  default     = ""
  validation {
    condition     = !var.enable_full_rls_green_executor || can(regex("^[a-f0-9]{40}$", var.full_rls_green_release_sha))
    error_message = "full_rls_green_release_sha must be a full Git commit SHA."
  }
}

variable "full_rls_green_source_contract_sha256" {
  type        = string
  description = "Approved clean-room package source contract digest."
  default     = ""
  validation {
    condition     = !var.enable_full_rls_green_executor || can(regex("^[a-f0-9]{64}$", var.full_rls_green_source_contract_sha256))
    error_message = "full_rls_green_source_contract_sha256 must be sha256."
  }
}

variable "full_rls_green_migration_set_digest" {
  type        = string
  description = "Approved ordered Prisma migration-set digest."
  default     = ""
  validation {
    condition     = !var.enable_full_rls_green_executor || can(regex("^[a-f0-9]{64}$", var.full_rls_green_migration_set_digest))
    error_message = "full_rls_green_migration_set_digest must be sha256."
  }
}

variable "full_rls_green_package_checksum_sha256" {
  type        = string
  description = "Approved generated package checksum-manifest digest."
  default     = ""
  validation {
    condition     = !var.enable_full_rls_green_executor || can(regex("^[a-f0-9]{64}$", var.full_rls_green_package_checksum_sha256))
    error_message = "full_rls_green_package_checksum_sha256 must be sha256."
  }
}

variable "full_rls_green_executor_image" {
  type        = string
  description = "Immutable production RLS executor ECR image."
  default     = ""
  validation {
    condition     = !var.enable_full_rls_green_executor || can(regex("^[0-9]{12}\\.dkr\\.ecr\\.eu-west-2\\.amazonaws\\.com/mscqr-backend@sha256:[a-f0-9]{64}$", var.full_rls_green_executor_image))
    error_message = "full_rls_green_executor_image must be an immutable production backend digest."
  }
}

variable "full_rls_green_backend_image" {
  type        = string
  description = "Immutable current backend image used for the pre-traffic green application canary."
  default     = ""
  validation {
    condition     = !var.enable_full_rls_green_executor || can(regex("^[0-9]{12}\\.dkr\\.ecr\\.eu-west-2\\.amazonaws\\.com/mscqr-backend@sha256:[a-f0-9]{64}$", var.full_rls_green_backend_image))
    error_message = "full_rls_green_backend_image must be an immutable production backend digest."
  }
}

variable "full_rls_green_db_subnet_ids" {
  type        = list(string)
  description = "Private subnet IDs for the isolated production green PostgreSQL instance."
  default     = []
}

variable "full_rls_green_db_instance_class" {
  type        = string
  description = "RDS instance class for production green."
  default     = "db.t4g.medium"
}

variable "full_rls_green_checker_principal_arns" {
  type        = list(string)
  description = "Independent human principals allowed to assume the approval signer role with MFA."
  default     = []
  validation {
    condition = !var.enable_full_rls_green_infrastructure || (
      length(var.full_rls_green_checker_principal_arns) > 0
      && alltrue([for arn in var.full_rls_green_checker_principal_arns : can(regex("^arn:aws:iam::368992683803:(user|role)/", arn))])
    )
    error_message = "At least one exact IAM checker principal is required when production green is enabled."
  }
}

variable "full_rls_receipt_bucket_arn" {
  type        = string
  description = "Production artifact bucket ARN used only for immutable full-RLS receipts."
  default     = ""
  validation {
    condition = !var.enable_full_rls_green_infrastructure || can(regex(
      "^arn:aws:s3:::mscqr-production-[a-z0-9-]+-artifacts-368992683803$",
      var.full_rls_receipt_bucket_arn
    ))
    error_message = "full_rls_receipt_bucket_arn must identify the reviewed production artifacts bucket."
  }
}

variable "full_rls_green_release_role_arn" {
  type        = string
  description = "Exact protected-workflow IAM role allowed to verify approvals, invoke the reviewed broker alias, and read receipts."
  default     = ""
  validation {
    condition = !var.enable_full_rls_green_executor || can(regex(
      "^arn:aws:iam::368992683803:role/mscqr-production-release-deployer$",
      var.full_rls_green_release_role_arn
    ))
    error_message = "full_rls_green_release_role_arn must be the reviewed production release deployer role."
  }
}
