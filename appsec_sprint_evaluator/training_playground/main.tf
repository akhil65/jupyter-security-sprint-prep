provider "aws" {
  region = "us-east-1"
}

# TRAINING EXAMPLE — Intentionally misconfigured S3 bucket.
# Demonstrates what Trivy / Checkov will flag for IaC scanning.
#
# FIX NOTES (for sprint discussion):
# The `acl` argument was DEPRECATED in AWS provider v4 and REMOVED in v5.
# Modern Terraform uses separate resources for ACLs and public access blocks.
# The two resources below show both the vulnerable pattern AND the correct fix.

# --- VULNERABLE: public bucket using deprecated ACL (provider v3 style) ---
# Uncomment only if using AWS provider < 4.0 to reproduce the finding:
#
# resource "aws_s3_bucket" "insecure_legacy" {
#   bucket = "my-tf-test-bucket-for-sprint-legacy"
#   acl    = "public-read"  # insecure — deprecated in v4, removed in v5
# }

# --- VULNERABLE (modern syntax): missing public access block ---
# This is what Trivy/Checkov flags with AVD-AWS-0057 on provider v4+:
resource "aws_s3_bucket" "insecure" {
  bucket = "my-tf-test-bucket-for-sprint"

  tags = {
    Name        = "Sprint training bucket"
    Environment = "Dev"
  }
}

# Missing aws_s3_bucket_public_access_block → bucket is publicly accessible.
# Trivy will flag: "Bucket does not have public access block enabled."

# --- SECURE: add this resource to fix the finding ---
# resource "aws_s3_bucket_public_access_block" "secure" {
#   bucket                  = aws_s3_bucket.insecure.id
#   block_public_acls       = true
#   block_public_policy     = true
#   ignore_public_acls      = true
#   restrict_public_buckets = true
# }
