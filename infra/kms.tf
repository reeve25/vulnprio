# One customer-managed key for S3, DynamoDB, ECR, Lambda env vars, logs and SNS: one policy to audit, $1/month.
resource "aws_kms_key" "this" {
  description         = "${var.name} data at rest"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.kms.json
}

data "aws_iam_policy_document" "kms" {
  # In a key policy, Resource "*" means "this key". Root access delegates control to IAM policies,
  # which is what lets the Lambda/CI role policies grant kms:* actions at all (AWS default key policy).
  #checkov:skip=CKV_AWS_109:key policy; "*" is this key, root statement is the AWS-recommended default
  #checkov:skip=CKV_AWS_111:key policy; "*" is this key, root statement is the AWS-recommended default
  #checkov:skip=CKV_AWS_356:key policy; "*" is this key, not all resources
  statement {
    sid       = "AccountRoot"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  # CloudWatch Logs encrypts with the key itself; the encryption-context condition limits it to our two log groups.
  statement {
    sid       = "CloudWatchLogs"
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values = [
        "arn:aws:logs:${var.region}:${local.account_id}:log-group:${local.lambda_log_group}",
        "arn:aws:logs:${var.region}:${local.account_id}:log-group:${local.api_log_group}",
      ]
    }
  }

  # Without this, alarms silently fail to publish to the KMS-encrypted SNS topic.
  statement {
    sid       = "CloudWatchAlarmsToSns"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    condition { # confused-deputy guard: only alarms in this account
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}
