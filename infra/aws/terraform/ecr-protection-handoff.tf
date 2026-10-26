# If a historical root state contains these addresses, relinquish them without destroying live resources.
removed {
  from = aws_ecr_repository_policy.backend_delete_guard

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_ecr_repository_policy.web_delete_guard

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_ecr_repository_policy.worker_delete_guard

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role_policy.legacy_image_publisher_protection_read

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role.ecr_monitor

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role_policy.ecr_monitor

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_cloudwatch_metric_alarm.ecr_protection

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_cloudwatch_event_rule.ecr_protection_change

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_cloudwatch_event_rule.ecr_image_action

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_cloudwatch_event_target.ecr_protection_change

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_cloudwatch_event_target.ecr_image_action

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_sns_topic_policy.ecr_alerts

  lifecycle {
    destroy = false
  }
}
