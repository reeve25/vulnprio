resource "aws_lambda_function" "this" {
  #checkov:skip=CKV_AWS_117:no private resources to reach; a VPC would force a NAT gateway (~$32/mo) for KEV/EPSS/NVD calls
  #checkov:skip=CKV_AWS_116:invoked synchronously by API Gateway only; a DLQ applies to async invocations
  #checkov:skip=CKV_AWS_272:code signing covers zip packages; container images are pinned by immutable ECR tag
  function_name                  = var.name
  role                           = aws_iam_role.lambda.arn
  package_type                   = "Image"
  image_uri                      = "${aws_ecr_repository.this.repository_url}:${var.image_tag}"
  architectures                  = ["x86_64"] # matches the CI-built image
  memory_size                    = 1024
  timeout                        = 29                       # API Gateway's integration limit is 30 s; fail inside it, not after
  reserved_concurrent_executions = var.reserved_concurrency # cost/abuse ceiling
  kms_key_arn                    = aws_kms_key.this.arn

  environment {
    variables = {
      VULNPRIO_TABLE  = aws_dynamodb_table.this.name
      VULNPRIO_BUCKET = aws_s3_bucket.raw.id
    }
  }
  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_cloudwatch_log_group.lambda] # else Lambda auto-creates an unencrypted, never-expiring group
}

resource "aws_cloudwatch_log_group" "lambda" {
  #checkov:skip=CKV_AWS_338:operational logs, not audit logs; 30 days keeps storage cost down (var.log_retention_days)
  name              = local.lambda_log_group
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
}

resource "aws_iam_role" "lambda" {
  name = "${var.name}-lambda"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "lambda.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy" "lambda" {
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

data "aws_iam_policy_document" "lambda" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"] # :* = log streams inside this group
  }
  statement {
    sid       = "Table"
    actions   = ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:Query", "dynamodb:BatchWriteItem"]
    resources = [aws_dynamodb_table.this.arn]
  }
  statement {
    sid       = "RawUploads"
    actions   = ["s3:PutObject"] # write-only: the app never reads raw uploads back
    resources = ["${aws_s3_bucket.raw.arn}/raw/*"]
  }
  statement {
    sid       = "Kms"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.this.arn]
  }
  statement {
    sid       = "XRay"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"] # these actions don't support resource-level permissions
  }
}
