provider "aws" {
  region = "us-east-1"
}

# Vulnerability: Publicly readable S3 bucket (IaC Scanning / Trivy / Checkov)
resource "aws_s3_bucket" "b" {
  bucket = "my-tf-test-bucket-for-sprint"
  acl    = "public-read" # insecure

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}
