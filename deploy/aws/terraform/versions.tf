# SPDX-License-Identifier: Apache-2.0
terraform {
  required_version = ">= 1.11, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region              = var.region
  profile             = var.aws_profile
  allowed_account_ids = [var.allowed_account_id]
  default_tags {
    tags = { project = "lindm", purpose = "ci-proof" }
  }
}
