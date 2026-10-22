variable "phase3_iam_source_sha" {
  description = "Exact protected-main source bound into the saved Phase 3 IAM plan."
  type        = string
  default     = null

  validation {
    condition     = var.phase3_iam_source_sha == null || can(regex("^[a-f0-9]{40}$", var.phase3_iam_source_sha))
    error_message = "phase3_iam_source_sha must be a full lowercase Git SHA."
  }
}
