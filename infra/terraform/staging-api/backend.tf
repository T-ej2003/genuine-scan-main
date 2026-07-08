terraform {
  backend "s3" {
    bucket              = "mscqr-staging-terraform-state-368992683803"
    key                 = "staging-api/terraform.tfstate"
    region              = "eu-west-2"
    encrypt             = true
    use_lockfile        = true
    allowed_account_ids = ["368992683803"]
  }
}
