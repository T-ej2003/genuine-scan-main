terraform {
  required_version = ">= 1.10.0, < 2.0.0"

  # Backend coordinates are supplied by the MFA-backed operator.
  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.41.0, < 7.0"
    }
  }
}
