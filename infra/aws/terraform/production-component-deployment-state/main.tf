locals {
  tags = { ManagedBy = "Terraform", Environment = "production", Stack = "production-component-deployment-state" }
}

resource "aws_dynamodb_table" "component_deployment_state" {
  name         = "mscqr-production-component-deployment-state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "stateKey"
  attribute {
    name = "stateKey"
    type = "S"
  }
  point_in_time_recovery {
    enabled = true
  }
  server_side_encryption {
    enabled = true
  }
  tags = local.tags
}

// IAM roles and documents are owned exclusively by the guarded installer.
// This first-install root must never acquire IAM document-writing authority.
