terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  # Coordinates are supplied only for the one-time, independently approved bootstrap.
  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.41.0, < 7.0"
    }
  }
}
