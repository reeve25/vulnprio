resource "aws_sns_topic" "alarms" {
  name              = "${var.name}-alarms"
  kms_master_key_id = aws_kms_key.this.arn
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alarm_email == null ? 0 : 1
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

locals {
  fn  = { FunctionName = aws_lambda_function.this.function_name }
  api = { ApiId = aws_apigatewayv2_api.this.id }
}

# All alarms: missing data = OK, so a quiet service with no traffic doesn't page.
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${var.name}-lambda-errors"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = local.fn
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
}

resource "aws_cloudwatch_metric_alarm" "lambda_throttles" {
  alarm_name          = "${var.name}-lambda-throttles"
  namespace           = "AWS/Lambda"
  metric_name         = "Throttles"
  dimensions          = local.fn
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
}

resource "aws_cloudwatch_metric_alarm" "api_5xx_rate" {
  alarm_name          = "${var.name}-api-5xx-rate"
  alarm_description   = "More than 1% of API requests returned 5xx over 15 minutes"
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]

  metric_query {
    id          = "rate"
    expression  = "IF(requests > 0, 100 * errors / requests, 0)" # guard divide-by-zero on idle periods
    label       = "5xx %"
    return_data = true
  }
  metric_query {
    id = "errors"
    metric {
      namespace   = "AWS/ApiGateway"
      metric_name = "5xx"
      dimensions  = local.api
      stat        = "Sum"
      period      = 900
    }
  }
  metric_query {
    id = "requests"
    metric {
      namespace   = "AWS/ApiGateway"
      metric_name = "Count"
      dimensions  = local.api
      stat        = "Sum"
      period      = 900
    }
  }
}

# KEV/EPSS misses (NVD excluded) summed per hour: one flaky call doesn't page, a second in the hour does.
# Hourly, not N consecutive short periods: CI traffic is bursty, and empty periods would keep a
# day-long outage from ever paging.
resource "aws_cloudwatch_metric_alarm" "enrichment_errors" {
  alarm_name          = "${var.name}-enrichment-errors"
  namespace           = "vulnprio"
  metric_name         = "EnrichmentErrors"
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 2
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
}

# Early warning before ingest hits API Gateway's 30 s hard limit (DECISIONS #14).
resource "aws_cloudwatch_metric_alarm" "ingest_p99" {
  alarm_name          = "${var.name}-ingest-p99"
  namespace           = "vulnprio"
  metric_name         = "IngestDuration"
  extended_statistic  = "p99"
  period              = 900
  evaluation_periods  = 1
  threshold           = 20000
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
}

resource "aws_cloudwatch_dashboard" "this" {
  dashboard_name = var.name
  dashboard_body = jsonencode({
    widgets = [
      { type = "metric", width = 12, height = 6, properties = {
        title = "API requests & 5xx", region = var.region, stat = "Sum", period = 300
        metrics = [
          ["AWS/ApiGateway", "Count", "ApiId", aws_apigatewayv2_api.this.id],
          ["AWS/ApiGateway", "5xx", "ApiId", aws_apigatewayv2_api.this.id],
        ]
      } },
      { type = "metric", width = 12, height = 6, properties = {
        title = "Latency p50/p99 (ms)", region = var.region, period = 300
        metrics = [
          ["AWS/ApiGateway", "Latency", "ApiId", aws_apigatewayv2_api.this.id, { stat = "p50" }],
          ["AWS/ApiGateway", "Latency", "ApiId", aws_apigatewayv2_api.this.id, { stat = "p99" }],
          ["vulnprio", "IngestDuration", { stat = "p50" }],
          ["vulnprio", "IngestDuration", { stat = "p99" }],
        ]
      } },
      { type = "metric", width = 12, height = 6, properties = {
        title = "Lambda", region = var.region, period = 300
        metrics = [
          ["AWS/Lambda", "Errors", "FunctionName", var.name, { stat = "Sum" }],
          ["AWS/Lambda", "Throttles", "FunctionName", var.name, { stat = "Sum" }],
          ["AWS/Lambda", "ConcurrentExecutions", "FunctionName", var.name, { stat = "Maximum" }],
          ["AWS/Lambda", "Duration", "FunctionName", var.name, { stat = "p99", yAxis = "right" }],
        ]
      } },
      { type = "metric", width = 6, height = 6, properties = {
        title   = "Findings ingested vs act-now", region = var.region, stat = "Sum", period = 3600
        metrics = [["vulnprio", "FindingsIngested"], ["vulnprio", "ActNowFindings"]]
      } },
      { type = "metric", width = 6, height = 6, properties = {
        title   = "Enrichment errors", region = var.region, stat = "Sum", period = 900
        metrics = [["vulnprio", "EnrichmentErrors"]]
      } },
    ]
  })
}
