# Needs Terraform >= 1.11 (override_during); the config itself works on >= 1.9.
# Offline: mock_provider fakes every AWS call, so no credentials and nothing is created.
# The mocked provider returns random strings for policy JSON, so we assert on the
# aws_iam_policy_document inputs (statement blocks), which is what generates that JSON.
mock_provider "aws" {
  override_during = plan # generate mock computed values (ARNs) at plan time, not unknown (Terraform >= 1.11)

  mock_data "aws_iam_policy_document" {
    defaults = { json = "{}" } # provider validates policy args as JSON
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::vulnprio-raw-123456789012" }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
}

variables {
  image_tag = "test"
}

run "least_privilege_and_invariants" {
  command = plan

  assert {
    condition = alltrue(flatten([
      for s in data.aws_iam_policy_document.lambda.statement : [for a in s.actions : a != "*" && !endswith(a, ":*")]
    ]))
    error_message = "Lambda policy must not use '*' or service-wide wildcard actions (s3:*, dynamodb:*)."
  }

  assert {
    condition     = one([for s in data.aws_iam_policy_document.lambda.statement : s.actions if s.sid == "RawUploads"]) == toset(["s3:PutObject"])
    error_message = "Lambda may only PutObject to S3."
  }

  assert {
    condition     = endswith(one(one([for s in data.aws_iam_policy_document.lambda.statement : s.resources if s.sid == "RawUploads"])), "/raw/*")
    error_message = "Lambda S3 access must be scoped to the raw/ prefix."
  }

  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.raw.block_public_acls,
      aws_s3_bucket_public_access_block.raw.block_public_policy,
      aws_s3_bucket_public_access_block.raw.ignore_public_acls,
      aws_s3_bucket_public_access_block.raw.restrict_public_buckets,
    ])
    error_message = "All four S3 public access block settings must be true."
  }

  assert {
    condition     = aws_dynamodb_table.this.point_in_time_recovery[0].enabled
    error_message = "DynamoDB point-in-time recovery must be enabled."
  }

  assert {
    condition = one(one([
      for c in one(data.aws_iam_policy_document.github_trust.statement).condition : c.values
      if c.variable == "token.actions.githubusercontent.com:sub"
    ])) == "repo:reeve25/vulnprio:ref:refs/heads/main"
    error_message = "CI role must be assumable only from this repo's main branch."
  }

  assert {
    condition     = alltrue([for r in aws_apigatewayv2_route.iam : r.authorization_type == "AWS_IAM"]) && length(aws_apigatewayv2_route.iam) == 4
    error_message = "Every non-health route must require IAM (SigV4) auth."
  }
}
