import {
  to = aws_iam_role.legacy_github_actions_deploy
  id = "github-actions-mscqr-deploy"
}

resource "aws_iam_role" "legacy_github_actions_deploy" {
  name                 = "github-actions-mscqr-deploy"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "RetiredLegacyGitHubDeploymentRole"
      Effect    = "Deny"
      Principal = { AWS = "*" }
      Action    = "sts:AssumeRoleWithWebIdentity"
    }]
  })

  lifecycle {
    prevent_destroy = true
  }
}
