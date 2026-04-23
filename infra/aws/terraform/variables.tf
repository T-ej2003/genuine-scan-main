variable "aws_region" {
  type        = string
  description = "AWS region for the ECS/ECR stack."
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
