variable "vpc_id" { type = string }
variable "vpc_cidr_block" {
  type = string
  validation {
    condition     = can(cidrnetmask(var.vpc_cidr_block)) && can(cidrhost(var.vpc_cidr_block, 2))
    error_message = "Use the production VPC IPv4 CIDR so the task can reach the VPC DNS resolver."
  }
}
variable "private_subnet_ids" { type = list(string) }
variable "service_endpoint_security_group_ids" { type = list(string) }
variable "active_database_host" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]*\\.eu-west-2\\.rds\\.amazonaws\\.com$", var.active_database_host))
    error_message = "Use the private eu-west-2 RDS endpoint."
  }
}
variable "active_database_resource_id" {
  type = string
  validation {
    condition     = can(regex("^(?:db|cluster)-[A-Z0-9]+$", var.active_database_resource_id))
    error_message = "Use the active mscqr_production RDS instance or Aurora cluster resource ID."
  }
}
variable "active_database_security_group_id" { type = string }
variable "evidence_bucket_name" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,62}$", var.evidence_bucket_name))
    error_message = "Use a unique evidence bucket name."
  }
}
