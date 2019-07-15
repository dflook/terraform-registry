from typing import Dict, Iterable, Optional
import json
import logging
from semantic_version import Version
import base64
import os
import os.path
import boto3
from dataclasses import dataclass

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
registry = None


@dataclass
class Module:
    id: str
    owner: str
    namespace: str
    version: str
    provider: str
    description: str
    source: str
    published_at: str
    downloads: int
    verified: bool

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'owner': self.owner,
            'namespace': self.namespace,
            'version': self.version,
            'provider': self.provider,
            'description': self.description,
            'source': self.source,
            'published_at': str(self.published_at),
            'downloads': self.downloads,
            'verified': self.verified
        }

def archive_version(key) -> Optional[Version]:
    filename = os.path.basename(key)
    for ext in ['.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz', '.zip']:
        if filename.endswith(ext):
            return Version(filename[:-len(ext)])

class RegistryResponse:
    def __init__(self, content=None, *, status=None, headers=None):
        if status is None:
            if content is None:
                status = 204
            else:
                status = 200

        self.status = status
        self.content = content
        self.headers = headers

    def api_gateway_response(self):
        response = {
            'statusCode': self.status,
            'body': json.dumps(self.content)
        }

        if self.headers is not None:
            response['headers'] = self.headers

        logger.info(f'Response status {self.status}, headers: {self.headers}, body: {self.content}')

        return response


class RegistryError(RegistryResponse, Exception):

    def __init__(self, status=500, *errors):
        super().__init__(content=errors, status=status)

    def api_gateway_response(self):
        response = {
            'statusCode': self.status,
            'body': json.dumps({
                'errors': self.content
            })
        }

        if self.headers is not None:
            response['headers'] = self.headers

        logger.info(f'Response status {self.status}, headers: {self.headers}, body: {self.content}')

        return response


class Registry:
    def __init__(self, bucket_name: str, api_token_table_name: str):
        self.s3 = boto3.client('s3')
        self._bucket_name = bucket_name
        self._api_token_table_name = api_token_table_name

    def list_modules(self, namespace: Optional[str] = None) -> Iterable[Module]:
        pass

    def search(self) -> Iterable[Module]:
        pass

    def list_versions(self, namespace: str, name: str, provider: str) -> Iterable[str]:
        """List Available Versions for a Specific Module"""

        response = self.s3.list_objects_v2(
            Bucket=self._bucket_name,
            Prefix=f'{namespace}/{name}/{provider}/'
        )

        if 'Contents' not in response:
            return []

        keys = [obj['Key'] for obj in response.get('Contents', []) if obj['Size'] > 0]
        return [str(archive_version(key)) for key in keys]

    def download(self, namespace: str, name: str, provider: str, version: str) -> str:
        'Return a download link for this module'

        response = self.s3.list_objects_v2(
            Bucket=self._bucket_name,
            Prefix=f'{namespace}/{name}/{provider}/{version}'
        )

        if 'Contents' not in response:
            raise RegistryError(404, f'Module not found for {namespace}/{name}/{provider}/{version}')

        keys = [obj['Key'] for obj in response.get('Contents', []) if obj['Size'] > 0]

        url = self.s3.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': self._bucket_name,
                'Key': keys[0]
            },
            ExpiresIn=300
        )

        url = 'http://' + url[len('https://'):]

        return url

    def list_latest_versions(self, namespace: str, name: str) -> Iterable[Module]:
        'Return the latest version of a module for each provider'
        pass

    def get_module(self, namespace: str, name: str, provider: str, version: str) -> Module:
        """
        Return module metadata
        """

        response = self.s3.get_object(
            Bucket=self._bucket_name,
            Key=f'{namespace}/{name}/{provider}/{version}'
        )

        return Module(
            id=f'{namespace}/{name}/{provider}/{version}',
            owner='ovotech',
            namespace=namespace,
            version=version,
            provider=provider,
            description=response['Metadata'].get('description', ''),
            source=response['Metadata'].get('source', ''),
            published_at=response['LastModified'],
            downloads=0,
            verified=True,
        )

    def latest_version(self, namespace: str, name: str, provider: str) -> Optional[str]:
        """
        Return the highest version of a module
        """

        response = self.s3.list_objects_v2(
            Bucket=self._bucket_name,
            Prefix=f'{namespace}/{name}/{provider}/'
        )

        if 'Contents' not in response:
            return None

        keys = [obj['Key'] for obj in response.get('Contents', []) if obj['Size'] > 0]
        versions = [archive_version(key) for key in keys]
        return str(max(versions))


def registry_request(event: Dict, registry: Registry) -> RegistryResponse:
    # if 'Authorization' in event['headers']:
    #    raise RegistryError(403, 'Not Authorized')

    parameters = event.get('pathParameters', {})
    if parameters is None:
        parameters = {}

    if event['path'] == '/.well-known/terraform.json':
        return RegistryResponse({
            'modules.v1': '/'
        })

    if event['path'].startswith('/download'):
        # Terraform will add a 'terraform-get' query parameter to the request, which breaks request signing.
        # Terraform is the worst piece of software I have to use on a daily basis.
        # If they were competent they would use the user-agent header.

        return RegistryResponse(
            status=302,
            headers={
                'Location': base64.b64decode(event['queryStringParameters']['url']).decode(),
            }
        )

    logger.info('parameters is %r', parameters)

    if 'namespace' not in parameters:
        registry.list_modules()
        raise RegistryError(501, 'Not Implemented')

    if parameters['namespace'] == 'search':
        raise RegistryError(501, 'Not Implemented')

    if 'name' not in parameters:
        registry.list_modules(parameters['namespace'])
        raise RegistryError(501, 'Not Implemented')

    if 'provider' not in parameters:
        registry.list_latest_versions(parameters['namespace'], parameters['name'])
        raise RegistryError(501, 'Not Implemented')

    if 'version' not in parameters:
        registry.list_versions(parameters['namespace'], parameters['name'], parameters['provider'])
        raise RegistryError(501, 'Not Implemented')

    if parameters['version'] == 'download':
        latest_version = registry.latest_version(parameters['namespace'], parameters['name'], parameters['provider'])
        location = f'{parameters["namespace"]}/{parameters["name"]}/{parameters["providers"]}/{latest_version}/download'
        return RegistryResponse(
            f'<a href="{location}">Found</a>',
            status=302,
            headers={
                'Location': location,
                'Content-Type': 'text/html'
            }
        )

    if parameters['version'] == 'versions':
        versions = registry.list_versions(parameters['namespace'], parameters['name'], parameters['provider'])
        response = {
            'modules': [{
                'source': f'{parameters["namespace"]}/{parameters["name"]}/{parameters["provider"]}',
                'versions': [{'version': version} for version in versions]
            }]
        }
        return RegistryResponse(response)

    if event['path'].endswith('/download'):
        url = registry.download(parameters['namespace'], parameters['name'], parameters['provider'],
                                parameters['version'])

        return RegistryResponse(headers={
            'X-Terraform-Get': '/download.tar.gz?url=' + base64.b64encode(url.encode()).decode()
        })

    module = registry.get_module(parameters['namespace'], parameters['name'], parameters['provider'],
                                 parameters['version'])
    return RegistryResponse(module.to_dict())


def handler(event: Dict, context=None) -> Dict:
    logger.info('event: %r', event)

    global registry
    if registry is None:
        registry = Registry(os.environ['TerraformModules'], os.environ['ApiTokens'])

    try:
        response = registry_request(event, registry)
        return response.api_gateway_response()
    except RegistryError as registry_error:
        logger.exception('RegistryError')
        return registry_error.api_gateway_response()
    except Exception as exception:
        logger.exception('Exception is %r', type(exception))
        return RegistryError(500, 'Internal Error', str(exception)).api_gateway_response()


if __name__ == '__main__':
    handler({}, None)
