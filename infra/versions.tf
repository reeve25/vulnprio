terraform {
  required_version = ">= 1.11" # tests/ use mock_provider override_during (1.11+); validate parses tests too
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Validated only, never applied (DECISIONS #9). A real deployment would keep state remotely:
  # backend "s3" {
  #   bucket       = "my-tfstate-bucket"
  #   key          = "vulnprio/terraform.tfstate"
  #   region       = "us-east-1"
  #   encrypt      = true
  #   use_lockfile = true # S3-native state locking (Terraform >= 1.10); no DynamoDB lock table needed
  # }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = "vulnprio" }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  # Built as strings (not resource refs) because the KMS key policy must name them before the log groups exist.
  lambda_log_group = "/aws/lambda/${var.name}"
  api_log_group    = "/aws/apigateway/${var.name}"
}
