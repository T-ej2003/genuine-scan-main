terraform {
  required_version = "= 1.15.8"
  backend "s3" {
    bucket              = "mscqr-production-terraform-state-368992683803-eu-west-2"
    key                 = "mscqr/production/component-deployment-state/terraform.tfstate"
    region              = "eu-west-2"
    encrypt             = true
    use_lockfile        = true
    max_retries         = 0
    allowed_account_ids = ["368992683803"]
  }
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.65.0"
    }
  }
}
