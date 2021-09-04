resource "aws_s3_bucket" "state" {
  bucket = "dflook-terraform-registry"
  acl    = "private"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket = aws_s3_bucket.state.bucket

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_dynamodb_table" "state" {
  name           = "dflook-terraform-registry-state"
  billing_mode   = "PAY_PER_REQUEST"

  hash_key       = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }
}
