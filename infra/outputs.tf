output "api_url" {
  value = aws_apigatewayv2_api.this.api_endpoint
}

output "ecr_repository_url" {
  value = aws_ecr_repository.this.repository_url
}

output "github_actions_role_arn" {
  value = aws_iam_role.github.arn
}

output "table_name" {
  value = aws_dynamodb_table.this.name
}

output "bucket_name" {
  value = aws_s3_bucket.raw.id
}

output "dashboard_url" {
  value = "https://${var.region}.console.aws.amazon.com/cloudwatch/home?region=${var.region}#dashboards:name=${aws_cloudwatch_dashboard.this.dashboard_name}"
}
