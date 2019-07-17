module "my_test" {
  source = "terraform.flook.org/pe/vpc/aws"
  version = "0.0.1"
}

output "blah" {
  value = "${module.my_test.bucket_name}"
}

provider "aws" {
  region = "eu-west-2"
}