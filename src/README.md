# Terraform Registry

The cloudformation template creates a terraform registry, with an api gateway endpoint.
If you want to setup a registry at a custom endpoint, set that up after deploying.

Modules live in an s3 bucket.
Public modules can be downloaded anonymously.
Private modules must use an api key.

## Endpoints

GET /.well-known/terraform.json
*   Service Discovery endpoint
GET /download<ext>?url=<b64 encoded url>
*   Redirect to the url parameter
GET /v1/
    List modules - PAGED
GET /v1/<namespace>
    List modules in namespace
GET /v1/search - PAGED
    Search modules
GET /v1/<namespace>/<name> - PAGED
    List latest version of each provider for a module
GET /v1/<namespace>/<name>/<provider>
    Latest Version for a Specific Module Provider
GET /v1/<namespace>/<name>/<provider>/download
    This endpoint downloads the latest version of a module for a single provider.    
GET /v1/<namespace>/<name>/<provider>/versions
    List versions of a module
GET /v1/<namespace>/<name>/<provider</<version>
    This endpoint returns the specified version of a module for a single provider.
GET /v1/<namespace>/<name>/<provider>/<version>/download
    Download module version

POST /v1/<namespace>/<name>/<provider</<version>/upload