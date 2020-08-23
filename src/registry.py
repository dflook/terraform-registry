import re
from typing import Dict, Iterable, Optional, List
import json
import logging
from semantic_version import Version
import base64
import os
import os.path
import boto3
from dataclasses import dataclass

logger = logging.getLogger()
logger.setLevel(logging.INFO)

registry = None
registration_auth = None

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
        super().__init__(content=errors, status=status, headers={'content-type': 'application/json'})

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

class ModuleRegistry:
    def __init__(self, bucket_name: str):
        self.s3 = boto3.client('s3')
        self._bucket_name = bucket_name

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

        return url

    def upload(self, namespace: str, name: str, provider: str, version: str) -> str:
        'Return an upload link for this module'

        url = self.s3.generate_presigned_url(
            'put_object',
            Params={
                'Bucket': self._bucket_name,
                'Key': f'{namespace}/{name}/{provider}/{version}.tar.gz'
            },
            ExpiresIn=300
        )

        return url

class ProviderRegistry:
    def __init__(self, bucket_name: str):
        self.s3 = boto3.client('s3')
        self._bucket_name = bucket_name

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

        return url

    def upload(self, namespace: str, name: str, provider: str, version: str) -> str:
        'Return an upload link for this module'

        url = self.s3.generate_presigned_url(
            'put_object',
            Params={
                'Bucket': self._bucket_name,
                'Key': f'{namespace}/{name}/{provider}/{version}.tar.gz'
            },
            ExpiresIn=300
        )

        return url

class RegistryAuthorization:
    def __init__(self, table_name: str):
        self._table_name = table_name
        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(table_name)

    def read_namespaces(self, api_token: str) -> Iterable[str]:
        """
        Return the namespaces an api_token has read access to
        """

        response = self.table.get_item(Key={'token': api_token})

        if 'Item' not in response:
            raise RegistryError(401, 'Invalid token')

        return response['Item'].get('read', []) + response['Item'].get('write', [])

    def write_namespaces(self, api_token: str) -> Iterable[str]:
        """
        Return the namespaces an api_token has read access to
        """

        response = self.table.get_item(Key={'token': api_token})

        if 'Item' not in response:
            raise RegistryError(401, 'Invalid token')

        return response['Item'].get('write', [])

def get_api_token(event: Dict):
    if 'authorization' not in event['headers']:
        return 'Anonymous'

    header = event['headers']['authorization']
    if not header.startswith('Bearer '):
        raise RegistryError(401, 'Invalid token')

    return header[len('Bearer '):]

def service_discovery(event: Dict) -> RegistryResponse:
    return RegistryResponse({
        'modules.v1': '/modules/v1/',
        'providers.v1': '/providers/v1/'
    }, headers={
        'content-type': 'application/json'
    })

def module_request(path: str, event: Dict, registry: ModuleRegistry, registry_auth: RegistryAuthorization) -> RegistryResponse:

    list_versions = re.match(r'/(?P<namespace>.*?)/(?P<name>.*?)/(?P<provider>.*?)/versions', path)
    download_version = re.match(r'/(?P<namespace>.*?)/(?P<name>.*?)/(?P<provider>.*?)/(?P<version>.*?)/download', path)
    upload_version = re.match(r'/(?P<namespace>.*?)/(?P<name>.*?)/(?P<provider>.*?)/(?P<version>.*?)/upload', path)

    logger.info(path)

    if list_versions:
        logger.info(f'Attempting to list namespaces namespace {upload_version.group("namespace")} for token with write access to {registry_auth.write_namespaces(get_api_token(event))}')
        if list_versions.group('namespace') not in registry_auth.read_namespaces(get_api_token(event)):
            logger.info('Not allowed to read namespaces')
            raise RegistryError(403, 'Forbidden')

        versions = registry.list_versions(list_versions.group('namespace'), list_versions.group('name'), list_versions.group('provider'))
        response = {
            'modules': [{
                'source': f"{list_versions.group('namespace')}/{list_versions.group('name')}/{list_versions.group('provider')}",
                'versions': [{'version': version} for version in versions]
            }]
        }
        return RegistryResponse(response, headers={'content-type': 'application/json'})

    if download_version:
        logger.info(f'Attempting download from namespace {upload_version.group("namespace")} for token with write access to {registry_auth.write_namespaces(get_api_token(event))}')
        if download_version.group('namespace') not in registry_auth.read_namespaces(get_api_token(event)):
            logger.info('Not allowed to download version')
            raise RegistryError(403, 'Forbidden')

        url = registry.download(download_version.group('namespace'),
                                download_version.group('name'),
                                download_version.group('provider'),
                                download_version.group('version'))

        return RegistryResponse(headers={
            'X-Terraform-Get': '/download.tar.gz?url=' + base64.b64encode(url.encode()).decode()
        })

    if upload_version:
        logger.info(f'Attempting upload to namespace {upload_version.group("namespace")} for token with write access to {registry_auth.write_namespaces(get_api_token(event))}')
        if upload_version.group('namespace') not in registry_auth.write_namespaces(get_api_token(event)):
            logger.info('Get out of here')
            raise RegistryError(403, 'Forbidden')

        url = registry.upload(upload_version.group('namespace'),
                              upload_version.group('name'),
                              upload_version.group('provider'),
                              upload_version.group('version'))

        return RegistryResponse(status=307, headers={
            'Location': url
        })

    raise RegistryError(501, 'Not Implemented')

def provider_request(path: str, event: Dict, registry: ModuleRegistry, registry_auth: RegistryAuthorization) -> RegistryResponse:

    list_versions = re.match(r'/(?P<namespace>.*?)/(?P<type>.*?)/versions', path)
    download_version = re.match(r'/(?P<namespace>.*?)/(?P<type>.*?)/(?P<version>.*?)/download/(?P<os>.*?)/(?P<arch>.*)', path)
    upload_version = re.match(r'/(?P<namespace>.*?)/(?P<type>.*?)/(?P<version>.*?)/download/(?P<os>.*?)/(?P<arch>.*)', path)

    logger.info(path)

    if list_versions:
        versions = registry.list_versions(list_versions.group('namespace'), list_versions.group('name'), list_versions.group('provider'))
        response = {
            'modules': [{
                'source': f"{list_versions.group('namespace')}/{list_versions.group('name')}/{list_versions.group('provider')}",
                'versions': [{'version': version} for version in versions]
            }]
        }
        return RegistryResponse(response, headers={'content-type': 'application/json'})

    if download_version:
        url = registry.download(download_version.group('namespace'),
                                download_version.group('name'),
                                download_version.group('provider'),
                                download_version.group('version'))

        return RegistryResponse(headers={
            'X-Terraform-Get': '/download.tar.gz?url=' + base64.b64encode(url.encode()).decode()
        })

    if upload_version:
        if upload_version.group('namespace') not in registry_auth.write_namespaces(get_api_token(event)):
            raise RegistryError(403, 'Forbidden')

        url = registry.upload(download_version.group('namespace'),
                              download_version.group('name'),
                              download_version.group('provider'),
                              download_version.group('version'))

        return RegistryResponse(status=307, headers={
            'Location': url
        })

    raise RegistryError(501, 'Not Implemented')


def extract_sub_path(path: str, prefixes: List[str]) -> str:
    for p in prefixes:
        if path.startswith(p):
            return path[len(p):]
    return path

def registry_request(event: Dict, registry: ModuleRegistry, registry_auth: RegistryAuthorization) -> RegistryResponse:

    if event['rawPath'] == '/.well-known/terraform.json':
        return service_discovery(event)

    if event['rawPath'].startswith('/download'):
        return RegistryResponse(
            status=302,
            headers={
                'Location': base64.b64decode(event['queryStringParameters']['url']).decode(),
            }
        )

    if event['rawPath'].startswith('/v1/') or event['rawPath'].startswith('/modules/v1/'):
        sub_path = extract_sub_path(event['rawPath'], ['/v1', '/modules/v1'])
        return module_request(sub_path, event, registry, registry_auth)

    if event['rawPath'].startswith('/providers/v1/'):
        sub_path = extract_sub_path(event['rawPath'], ['/providers/v1'])
        return provider_request(sub_path, event, registry, registry_auth)

    raise RegistryError(501, 'Not Implemented')

def handler(event: Dict, context=None) -> Dict:
    logger.info('event: %r', event)

    global module_registry, provider_registry, registration_auth

    if registry is None:
        module_registry = ModuleRegistry(os.environ['TerraformModules'])
        provider_registry = ProviderRegistry(os.environ['TerraformModules'])

    if registration_auth is None:
        registration_auth = RegistryAuthorization(os.environ['ApiTokens'])

    try:
        response = registry_request(event, module_registry, registration_auth)

        return response.api_gateway_response()
    except RegistryError as registry_error:
        logger.exception('RegistryError')
        return registry_error.api_gateway_response()
    except Exception as exception:
        logger.exception('Exception is %r', type(exception))
        return RegistryError(500, 'Internal Error', str(exception)).api_gateway_response()


if __name__ == '__main__':
    handler({}, None)
