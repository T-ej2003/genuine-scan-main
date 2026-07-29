terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  # Coordinates are supplied by the MFA-backed operator with -backend-config.
  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.41.0, < 7.0"
    }
  }
}
