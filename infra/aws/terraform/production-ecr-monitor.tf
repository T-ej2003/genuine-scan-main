locals {
  ecr_monitor_repositories = [
    aws_ecr_repository.backend.arn,
    "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-web",
    aws_ecr_repository.worker.arn,
  ]
  ecr_monitor_metric_namespace = "MSCQR/ProductionEcrProtection"
  ecr_alert_topic_arn          = "arn:aws:sns:eu-west-2:368992683803:mscqr-prod-alerts"
}

resource "aws_iam_role_policy" "legacy_image_publisher_protection_read" {
  name = "mscqr-production-ecr-protection-read"
  role = "github-actions-mscqr-deploy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "ecr:GetRepositoryPolicy"
        Resource  = local.ecr_monitor_repositories
        Condition = { StringEquals = { "aws:RequestedRegion" = "eu-west-2" } }
      },
      {
        Effect   = "Deny"
        Action   = ["ecr:PutLifecyclePolicy", "ecr:BatchDeleteImage", "ecr:DeleteRepository", "ecr:UpdateImageStorageClass"]
        Resource = local.ecr_monitor_repositories
      }
    ]
  })
}

resource "aws_iam_role" "ecr_monitor" {
  name = "mscqr-production-ecr-monitor"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = "arn:aws:iam::368992683803:oidc-provider/token.actions.githubusercontent.com" }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "token.actions.githubusercontent.com:aud"                 = "sts.amazonaws.com"
        "token.actions.githubusercontent.com:sub"                 = "repo:T-ej2003/genuine-scan-main:environment:production-ecr-monitor"
        "token.actions.githubusercontent.com:repository_id"       = "1145608538"
        "token.actions.githubusercontent.com:repository_owner_id" = "183396573"
        "token.actions.githubusercontent.com:ref"                 = "refs/heads/main"
        "token.actions.githubusercontent.com:workflow"            = "Production ECR Image Monitor"
      } }
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy" "ecr_monitor" {
  name = "mscqr-production-ecr-monitor"
  role = aws_iam_role.ecr_monitor.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["ecr:DescribeRepositories", "ecr:DescribeImages", "ecr:BatchGetImage", "ecr:GetLifecyclePolicy", "ecr:GetRepositoryPolicy"], Resource = local.ecr_monitor_repositories },
      { Effect = "Allow", Action = "ecs:DescribeServices", Resource = [
        "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2",
        "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-frontend-servi-euw2",
      ], Condition = { ArnEquals = { "ecs:cluster" = "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main" } } },
      { Effect = "Allow", Action = "ecs:ListTasks", Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = "eu-west-2" }, ArnEquals = { "ecs:cluster" = "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main" } } },
      { Effect = "Allow", Action = "ecs:DescribeTaskDefinition", Resource = "*", Condition = { StringEquals = { "aws:RequestedRegion" = "eu-west-2" } } },
      { Effect = "Allow", Action = "ecs:DescribeTasks", Resource = "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/*", Condition = { ArnEquals = { "ecs:cluster" = "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main" } } },
      { Effect = "Allow", Action = "dynamodb:GetItem", Resource = "arn:aws:dynamodb:eu-west-2:368992683803:table/mscqr-production-component-deployment-state", Condition = { "ForAllValues:StringEquals" = { "dynamodb:LeadingKeys" = ["production#T-ej2003/genuine-scan-main"] } } },
      { Effect = "Allow", Action = "s3:ListBucket", Resource = "arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2", Condition = { StringLike = { "s3:prefix" = "env:/production/mscqr/production/rls-green/stage-b/apply-attempts/green-backend-recovery/*" } } },
      { Effect = "Allow", Action = "s3:GetObject", Resource = "arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/env:/production/mscqr/production/rls-green/stage-b/apply-attempts/green-backend-recovery/*" },
      { Effect = "Allow", Action = "cloudwatch:PutMetricData", Resource = "*", Condition = { StringEquals = { "cloudwatch:namespace" = local.ecr_monitor_metric_namespace, "aws:RequestedRegion" = "eu-west-2" } } },
    ]
  })
}

resource "aws_cloudwatch_metric_alarm" "ecr_protection" {
  for_each = {
    critical = "CRITICALFindings"
    high     = "HIGHFindings"
    warning  = "WARNINGFindings"
    unknown  = "UNKNOWNFindings"
  }
  alarm_name          = "mscqr-production-ecr-${each.key}"
  namespace           = local.ecr_monitor_metric_namespace
  metric_name         = each.value
  statistic           = "Maximum"
  period              = 900
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [local.ecr_alert_topic_arn]
  ok_actions          = [local.ecr_alert_topic_arn]
  tags                = local.common_tags
}

resource "aws_cloudwatch_event_rule" "ecr_protection_change" {
  name = "mscqr-production-ecr-protection-change"
  event_pattern = jsonencode({
    source        = ["aws.ecr"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource       = ["ecr.amazonaws.com"]
      eventName         = ["BatchDeleteImage", "DeleteRepository", "PutLifecyclePolicy", "DeleteLifecyclePolicy", "SetRepositoryPolicy", "DeleteRepositoryPolicy", "PutImageTagMutability", "PutImageScanningConfiguration", "UpdateImageStorageClass"]
      requestParameters = { repositoryName = ["mscqr-backend", "mscqr-web", "mscqr-worker"] }
    }
  })
  tags = local.common_tags
}

resource "aws_iam_role" "ecr_alert_event_target" {
  name = "mscqr-production-ecr-alert-events"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = "368992683803" }
        ArnEquals = { "aws:SourceArn" = [
          aws_cloudwatch_event_rule.ecr_protection_change.arn,
          aws_cloudwatch_event_rule.ecr_image_action.arn,
        ] }
      }
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy" "ecr_alert_event_target" {
  name = "mscqr-production-ecr-alert-publish"
  role = aws_iam_role.ecr_alert_event_target.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sns:Publish", Resource = local.ecr_alert_topic_arn }]
  })
}

resource "aws_cloudwatch_event_target" "ecr_protection_change" {
  rule       = aws_cloudwatch_event_rule.ecr_protection_change.name
  target_id  = "existing-production-alerts"
  arn        = local.ecr_alert_topic_arn
  role_arn   = aws_iam_role.ecr_alert_event_target.arn
  depends_on = [aws_iam_role_policy.ecr_alert_event_target]
  input_transformer {
    input_paths = {
      event      = "$.detail.eventName"
      repository = "$.detail.requestParameters.repositoryName"
    }
    input_template = "{\"type\":\"ECR_PROTECTION_CHANGE\",\"event\":\"<event>\",\"repository\":\"<repository>\"}"
  }
}

resource "aws_cloudwatch_event_rule" "ecr_image_action" {
  name = "mscqr-production-ecr-image-action"
  event_pattern = jsonencode({
    source        = ["aws.ecr"]
    "detail-type" = ["ECR Image Action"]
    detail = {
      "action-type"     = ["DELETE"]
      "repository-name" = ["mscqr-backend", "mscqr-web", "mscqr-worker"]
    }
  })
  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "ecr_image_action" {
  rule       = aws_cloudwatch_event_rule.ecr_image_action.name
  target_id  = "existing-production-alerts"
  arn        = local.ecr_alert_topic_arn
  role_arn   = aws_iam_role.ecr_alert_event_target.arn
  depends_on = [aws_iam_role_policy.ecr_alert_event_target]
  input_transformer {
    input_paths = {
      action     = "$.detail.action-type"
      digest     = "$.detail.image-digest"
      repository = "$.detail.repository-name"
    }
    input_template = "{\"type\":\"ECR_IMAGE_ACTION\",\"action\":\"<action>\",\"repository\":\"<repository>\",\"digest\":\"<digest>\"}"
  }
}
