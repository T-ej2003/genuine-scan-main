variable "account_id" { type = string }
variable "aws_region" { type = string }
variable "vpc_id" { type = string }
variable "private_subnet_ids" { type = set(string) }
variable "stage_a_executor_security_group_id" { type = string }
variable "stage_a_executor_task_role_arn" { type = string }
variable "stage_a_broker_role_arn" { type = string }
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
check "release_bindings" {
  assert {
    condition     = can(regex("^[a-f0-9]{40}$", var.release_sha)) && can(regex("^[a-f0-9]{64}$", var.source_contract_sha256)) && can(regex("^[a-f0-9]{64}$", var.migration_set_digest)) && can(regex("^[a-f0-9]{64}$", var.package_checksum_sha256))
    error_message = "Stage B requires complete release and sealed-package digests."
  }
}
check "immutable_images" {
  assert {
    condition     = alltrue([for image in [var.backend_image, var.worker_image, var.executor_image, var.canary_image] : can(regex("^368992683803\\.dkr\\.ecr\\.eu-west-2\\.amazonaws\\.com/mscqr-(backend|worker)@sha256:[a-f0-9]{64}$", image))])
    error_message = "Stage B accepts immutable reviewed ECR digests only."
  }
}
