# GitHub Actions gets short-lived credentials by exchanging its OIDC token; no long-lived access keys exist.
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  # thumbprint_list omitted: AWS validates GitHub's certificate against its own trusted CAs.
}

resource "aws_iam_role" "github" {
  name               = "${var.name}-github-actions"
  assume_role_policy = data.aws_iam_policy_document.github_trust.json
}

data "aws_iam_policy_document" "github_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    # Exact match: only workflows on this repo's main branch. Forks, PRs and other branches can't assume it.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role_policy" "github" {
  role   = aws_iam_role.github.id
  policy = data.aws_iam_policy_document.github.json
}

data "aws_iam_policy_document" "github" {
  statement {
    sid       = "EcrLogin"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"] # account-level action, no resource-level permissions
  }
  statement {
    sid = "EcrPush"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:PutImage",
      # Pull rights: UpdateFunctionCode on an image function checks the caller can read the image.
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = [aws_ecr_repository.this.arn]
  }
  statement {
    sid       = "Deploy"
    actions   = ["lambda:UpdateFunctionCode"]
    resources = [aws_lambda_function.this.arn]
  }
  statement {
    sid       = "PushScan" # CI runs `vulnprio push` to upload its own image scan
    actions   = ["execute-api:Invoke"]
    resources = ["${aws_apigatewayv2_api.this.execution_arn}/$default/POST/scans"]
  }
}
