variable "aws_region" {
  type = string
  validation {
    condition     = var.aws_region == "eu-west-2"
    error_message = "Production green infrastructure is locked to eu-west-2."
  }
}

variable "vpc_id" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "runtime_security_group_ids" { type = set(string) }
variable "checker_principal_arns" {
  type = set(string)
  validation {
    condition     = length(var.checker_principal_arns) > 0 && alltrue([for arn in var.checker_principal_arns : can(regex("^arn:aws:iam::368992683803:(user|role)/", arn))])
    error_message = "checker_principal_arns must contain approved exact account principals."
  }
}
variable "release_role_arn" {
  type = string
  validation {
    condition     = can(regex("^arn:aws:iam::368992683803:role/mscqr-production-release-deployer$", var.release_role_arn))
    error_message = "release_role_arn must be the external protected production release role."
  }
}
variable "receipt_bucket_arn" {
  type = string
  validation {
    condition     = can(regex("^arn:aws:s3:::mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an$", var.receipt_bucket_arn))
    error_message = "receipt_bucket_arn must be the reviewed production artifact bucket ARN."
  }
}
variable "db_instance_class" {
  type    = string
  default = "db.t4g.medium"
}
variable "log_retention_days" {
  type    = number
  default = 30
}
variable "tags" {
  type    = map(string)
  default = {}
}

check "checker_is_independent_of_release_deployer" {
  assert {
    condition     = !contains(var.checker_principal_arns, var.release_role_arn)
    error_message = "An approval checker must be distinct from the protected release deployer."
  }
}
