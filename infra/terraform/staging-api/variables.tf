variable "aws_region" {
  type        = string
  description = "AWS region for the staging API stack."
  default     = "eu-west-2"

  validation {
    condition     = var.aws_region == "eu-west-2"
    error_message = "The staging API plan is currently approved only for eu-west-2."
  }
}

variable "account_id" {
  type        = string
  description = "AWS account ID expected for staging resources."

  validation {
    condition     = var.account_id == "368992683803"
    error_message = "account_id must be the reviewed staging account 368992683803."
  }
}

variable "database_role_cutover_operator_principal_arn" {
  type        = string
  description = "Exact dedicated IAM user allowed to assume the staging database-role cutover role with MFA."
  default     = "arn:aws:iam::368992683803:user/mscqr-staging-database-role-cutover-user"

  validation {
    condition     = var.database_role_cutover_operator_principal_arn == "arn:aws:iam::368992683803:user/mscqr-staging-database-role-cutover-user"
    error_message = "Only the dedicated staging database-role cutover user may be trusted."
  }
}

variable "environment" {
  type        = string
  description = "Deployment environment. Production values are forbidden in this staging module."
  default     = "staging"

  validation {
    condition     = contains(["staging", "stg"], lower(var.environment))
    error_message = "environment must be staging or stg; prod/production is forbidden."
  }
}

variable "vpc_id" {
  type        = string
  description = "VPC ID used as network fabric for isolated staging resources."
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "Public subnets for the staging ALB."

  validation {
    condition     = length(var.public_subnet_ids) >= 2
    error_message = "At least two public subnet IDs are required for the staging ALB."
  }
}

variable "app_private_subnet_ids" {
  type        = list(string)
  description = "Private app subnets for staging ECS tasks and staging Redis/Valkey."

  validation {
    condition     = length(var.app_private_subnet_ids) >= 2
    error_message = "At least two private app subnet IDs are required."
  }
}

variable "db_private_subnet_ids" {
  type        = list(string)
  description = "Private DB subnets for the staging RDS subnet group."

  validation {
    condition     = length(var.db_private_subnet_ids) >= 2
    error_message = "At least two private DB subnet IDs are required."
  }
}

variable "allowed_operator_cidrs" {
  type        = list(string)
  description = "Temporary operator or CI CIDR ranges allowed to reach the staging ALB over HTTP."
  default     = []

  validation {
    condition = length(var.allowed_operator_cidrs) > 0 && alltrue([
      for cidr in var.allowed_operator_cidrs :
      can(cidrhost(cidr, 0)) &&
      cidr != "0.0.0.0/0" &&
      cidr != "::/0" &&
      (
        can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/", cidr))
        ? try(tonumber(regex("/([0-9]+)$", cidr)[0]), -1) >= 24 && try(tonumber(regex("/([0-9]+)$", cidr)[0]), -1) <= 32
        : try(tonumber(regex("/([0-9]+)$", cidr)[0]), -1) >= 120 && try(tonumber(regex("/([0-9]+)$", cidr)[0]), -1) <= 128
      )
    ])
    error_message = "allowed_operator_cidrs must be valid narrow CIDRs. IPv4 must be /24 through /32; IPv6 must be /120 through /128. 0.0.0.0/0 and ::/0 are forbidden."
  }
}

variable "backend_image_uri" {
  type        = string
  description = "Exact digest-pinned backend image URI shared by the staging service and blue database-role executor."

  validation {
    condition     = can(regex("^368992683803\\.dkr\\.ecr\\.eu-west-2\\.amazonaws\\.com/mscqr-backend@sha256:[a-f0-9]{64}$", var.backend_image_uri))
    error_message = "backend_image_uri must be the exact digest-pinned MSCQR staging backend image in eu-west-2."
  }
}

variable "desired_count" {
  type        = number
  description = "Desired count for the staging backend ECS service."
  default     = 1

  validation {
    condition     = var.desired_count >= 0 && var.desired_count <= 2
    error_message = "Staging desired_count must be between 0 and 2 for cost control."
  }
}

variable "task_cpu" {
  type        = number
  description = "Staging backend task CPU units."
  default     = 1024
}

variable "task_memory" {
  type        = number
  description = "Staging backend task memory in MiB."
  default     = 2048
}

variable "db_instance_class" {
  type        = string
  description = "RDS instance class for staging Postgres."
  default     = "db.t4g.small"
}

variable "redis_node_type" {
  type        = string
  description = "ElastiCache Valkey node type for staging."
  default     = "cache.t4g.micro"
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch log retention for staging backend logs."
  default     = 14
}

variable "exec_log_retention_days" {
  type        = number
  description = "CloudWatch log retention for staging ECS Exec session logs."
  default     = 30

  validation {
    condition     = var.exec_log_retention_days >= 30 && var.exec_log_retention_days <= 365
    error_message = "exec_log_retention_days must be between 30 and 365 days."
  }
}

variable "db_allocated_storage_gb" {
  type        = number
  description = "Initial staging RDS storage in GiB."
  default     = 30
}

variable "db_engine_version" {
  type        = string
  description = "PostgreSQL engine version for staging. Match production major version when supported."
  default     = "18.4"
}

variable "activate_full_rls_green_runtime" {
  type        = bool
  description = "Switch the staging backend to the verified full-RLS green runtime credentials."
  default     = false
}

variable "full_rls_green_executor_image_uri" {
  type        = string
  description = "Immutable staging full-RLS executor image reference."
  validation {
    condition     = can(regex("@sha256:[a-f0-9]{64}$", var.full_rls_green_executor_image_uri))
    error_message = "The full-RLS executor image must use an immutable sha256 digest."
  }
}

variable "full_rls_green_release_sha" {
  type        = string
  description = "Exact release commit bound to the staging full-RLS package."
  validation {
    condition     = can(regex("^[a-f0-9]{40}$", var.full_rls_green_release_sha))
    error_message = "The full-RLS release SHA must be a full Git commit SHA."
  }
}

variable "full_rls_green_source_contract_sha256" {
  type        = string
  description = "Certified source-contract hash embedded in the staging full-RLS executor."
  validation {
    condition     = can(regex("^[a-f0-9]{64}$", var.full_rls_green_source_contract_sha256))
    error_message = "The full-RLS source contract must be a sha256 value."
  }
}

variable "full_rls_green_package_checksum_sha256" {
  type        = string
  description = "Certified checksum-manifest hash embedded in the staging full-RLS executor."
  validation {
    condition     = can(regex("^[a-f0-9]{64}$", var.full_rls_green_package_checksum_sha256))
    error_message = "The full-RLS package checksum must be a sha256 value."
  }
}

variable "staging_secret_arns" {
  type = object({
    database_url                    = string
    redis_url                       = string
    jwt_secret_current              = string
    qr_sign_private_key             = string
    qr_sign_public_key              = string
    ip_hash_salt_current            = string
    token_hash_secret_current       = string
    scan_fingerprint_secret         = string
    printer_sse_sign_secret_current = string
    customer_verify_otp_secret      = string
    customer_verify_token_secret    = string
    incident_hash_salt_current      = string
    auth_mfa_encryption_key         = string
    rls_green_admin_database_url    = string
  })
  description = "Secrets Manager ARNs for staging runtime secrets. Values must point under mscqr/staging/* and contain no secret material."
  sensitive   = true

  validation {
    condition = alltrue([
      for arn in values(var.staging_secret_arns) :
      can(regex(":secret:mscqr/staging/", arn)) && !can(regex("(?i):secret:mscqr/(prod|production)/", arn))
    ])
    error_message = "All staging_secret_arns must reference Secrets Manager names under mscqr/staging/* and must not reference prod/production."
  }

  validation {
    condition     = can(regex(":secret:mscqr/staging/rls-green/phase2/database-url/admin-[A-Za-z0-9]{6}$", var.staging_secret_arns.rls_green_admin_database_url))
    error_message = "rls_green_admin_database_url must reference the exact isolated staging green administrator secret."
  }
}

variable "tags" {
  type        = map(string)
  description = "Additional tags for staging resources."
  default     = {}
}
