# Terraform Registry

The cloudformation template creates a terraform registry, with an api gateway endpoint.
If you want to setup a registry at a custom endpoint, set that up after deploying.

Modules live in an s3 bucket.
Public modules can be downloaded anonymously.
Private modules must use an api key.

## Endpoints

GET /
    List modules - PAGED
GET /<namespace>
    List modules in namespace
GET /search - PAGED
    Search modules
GET /<namespace>/<name> - PAGED
    List latest version of each provider for a module
GET /<namespace>/<name>/<provider>
    Latest Version for a Specific Module Provider
GET /<namespace>/<name>/<provider>/download
    This endpoint downloads the latest version of a module for a single provider.    
GET /<namespace>/<name>/<provider>/versions
    List versions of a module
GET /<namespace>/<name>/<provider</<version>
    This endpoint returns the specified version of a module for a single provider.
GET /<namespace>/<name>/<provider>/<version>/download
    Download module version
