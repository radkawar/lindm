# SPDX-License-Identifier: Apache-2.0
# Transfer authenticated releases and client-encrypted backups, never signing custody.
resource "aws_s3_bucket" "release_transfer" {
  bucket_prefix = "${var.name}-release-"
  force_destroy = true
  tags          = { Name = "${var.name}-release-transfer" }
}
resource "aws_s3_bucket_public_access_block" "release_transfer" {
  bucket                  = aws_s3_bucket.release_transfer.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "release_transfer" {
  bucket = aws_s3_bucket.release_transfer.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_s3_bucket_policy" "release_transfer" {
  bucket = aws_s3_bucket.release_transfer.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "RequireTLS", Effect = "Deny", Principal = "*", Action = "s3:*"
      Resource  = [aws_s3_bucket.release_transfer.arn, "${aws_s3_bucket.release_transfer.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}
resource "aws_iam_role_policy" "release_transfer" {
  name = "authenticated-release-transfer"
  role = aws_iam_role.instance["server"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow", Action = "s3:GetObject"
      Resource = "${aws_s3_bucket.release_transfer.arn}/release.tar"
    }]
  })
}
resource "aws_iam_role_policy" "encrypted_backup_transfer" {
  name = "encrypted-backup-transfer"
  role = aws_iam_role.instance["server"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"]
      Resource = [
        "${aws_s3_bucket.release_transfer.arn}/backup.age",
        "${aws_s3_bucket.release_transfer.arn}/security-backup.age"
      ]
    }]
  })
}
output "release_transfer_bucket" { value = aws_s3_bucket.release_transfer.id }
