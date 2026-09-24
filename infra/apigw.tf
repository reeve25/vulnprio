resource "aws_apigatewayv2_api" "this" {
  name          = var.name
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.this.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.this.invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 29000
}

# SigV4-signed callers only (CI via OIDC role); no shared API keys (DECISIONS #15).
resource "aws_apigatewayv2_route" "iam" {
  for_each           = toset(["POST /scans", "GET /scans", "GET /scans/{scan_id}", "GET /scans/{scan_id}/findings"])
  api_id             = aws_apigatewayv2_api.this.id
  route_key          = each.key
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
  authorization_type = "AWS_IAM"
}

resource "aws_apigatewayv2_route" "healthz" {
  #checkov:skip=CKV_AWS_309:public liveness probe, returns {"ok": true} and touches no data
  api_id             = aws_apigatewayv2_api.this.id
  route_key          = "GET /healthz"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
  authorization_type = "NONE"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.this.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit = 20
    throttling_rate_limit  = 10
  }
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api.arn
    format = jsonencode({
      requestId        = "$context.requestId"
      routeKey         = "$context.routeKey"
      status           = "$context.status"
      latency          = "$context.responseLatency"
      integrationError = "$context.integrationErrorMessage"
      caller           = "$context.identity.userArn"
      sourceIp         = "$context.identity.sourceIp"
    })
  }
}

resource "aws_cloudwatch_log_group" "api" {
  #checkov:skip=CKV_AWS_338:operational logs, not audit logs; 30 days keeps storage cost down (var.log_retention_days)
  name              = local.api_log_group
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
}

resource "aws_lambda_permission" "apigw" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.this.execution_arn}/*/*" # this API only, not any API in the account
}
