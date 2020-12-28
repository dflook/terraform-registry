module "hello" {
  source = "terraform-dev.flook.org/dflook/example_module/aws"
}

output "word" {
  value = "${module.hello.word}"
}
