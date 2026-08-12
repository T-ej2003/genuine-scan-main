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
variable "s3_prefix_list_id" {
  type = string
  validation {
    condition     = can(regex("^pl-[a-f0-9]{8,17}$", var.s3_prefix_list_id))
    error_message = "s3_prefix_list_id must identify the reviewed regional S3 managed prefix list."
  }
}
variable "vpc_dns_resolver_cidr" {
  type = string
  validation {
    condition     = can(cidrhost(var.vpc_dns_resolver_cidr, 0)) && endswith(var.vpc_dns_resolver_cidr, "/32")
    error_message = "vpc_dns_resolver_cidr must be the exact VPC resolver address as a /32."
  }
}
variable "checker_principal_arns" {
  type = set(string)
  validation {
    condition     = var.checker_principal_arns == toset(["arn:aws:iam::368992683803:role/mscqr-production-independent-checker"])
    error_message = "checker_principal_arns must contain only the exact MFA-gated independent checker role."
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
