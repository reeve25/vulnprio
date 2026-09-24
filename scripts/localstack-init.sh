#!/bin/bash
# Creates the same table/bucket shape as infra/ (minus KMS), inside LocalStack.
set -euo pipefail
awslocal dynamodb create-table --table-name vulnprio \
  --attribute-definitions AttributeName=PK,AttributeType=S AttributeName=SK,AttributeType=S \
  --key-schema AttributeName=PK,KeyType=HASH AttributeName=SK,KeyType=RANGE \
  --billing-mode PAY_PER_REQUEST
awslocal dynamodb update-time-to-live --table-name vulnprio \
  --time-to-live-specification Enabled=true,AttributeName=ttl
awslocal s3 mb s3://vulnprio-raw
