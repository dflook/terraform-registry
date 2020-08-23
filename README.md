# AWS Serverless Terraform Registry

This is a lightweight Terraform module registry

## Upgrading

Some resources have changed in ways that Cloudformation is unable to update in place, so it's a two-step process.

1. Update the existing Cloudformation stack with the v1.0.0 template. Temporarily change the DomainName stack parameter
   to something different.
2. Update the Cloudformation stack again using the same template and change the DomainName parameter back.