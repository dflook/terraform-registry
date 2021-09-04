terraform {
  backend "s3" {
    region = "eu-west-1"
    bucket = "dflook-terraform-registry"
    key    = "terraform-state/infra"
    dynamodb_table = "dflook-terraform-registry-state"
  }
}
