import base64
import logging
import os
import os.path
from typing import Iterable, Optional

import boto3
from semantic_version import Version

from auth import is_authorized_read, is_authorized_write
from aws.api_gateway_types import HttpEvent
from aws.response import Response, JsonResponse, create_router

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
bucket_name = os.environ['TerraformModulesBucket']


def archive_version(key: str) -> Optional[Version]:
    filename = os.path.basename(key)
    for ext in ['.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz', '.zip']:
        if filename.endswith(ext):
            return Version(filename[:-len(ext)])

    return None


def download_redirect(event: HttpEvent) -> Response:
    return Response(
        status=302,
        headers={
            'location': base64.b64decode(event['queryStringParameters']['url']).decode(),
        }
    )


def list_versions(event: HttpEvent, namespace: str, name: str, system: str) -> Response:
    logger.info(
        f'Attempting to list namespaces namespace {namespace}')

    if not is_authorized_read(event, namespace):
        logger.info('Not allowed to read namespaces')
        raise Response('Forbidden', status=403)

    def list_versions() -> Iterable[str]:
        response = s3_client.list_objects_v2(
            Bucket=bucket_name,
            Prefix=f'{namespace}/{name}/{system}/'
        )

        if 'Contents' not in response:
            return []

        keys = [obj['Key'] for obj in response.get('Contents', []) if obj['Size'] > 0]
        return [str(archive_version(key)) for key in keys]

    response = {
        'modules': [{
            'source': f"{namespace}/{name}/{system}",
            'versions': [{'version': version} for version in list_versions()]
        }]
    }
    return JsonResponse(response)


def download_version(event: HttpEvent, namespace: str, name: str, system: str, version: str) -> Response:
    logger.info(f'Attempting download from namespace {namespace}')

    if not is_authorized_read(event, namespace):
        logger.info('Not allowed to download version')
        raise Response('Forbidden', status=403)

    def download_url() -> str:
        response = s3_client.list_objects_v2(
            Bucket=bucket_name,
            Prefix=f'{namespace}/{name}/{system}/{version}'
        )

        if 'Contents' not in response:
            raise Response(f'Module not found for {namespace}/{name}/{system}/{version}', status=404)

        keys = [obj['Key'] for obj in response.get('Contents', []) if obj['Size'] > 0]

        url: str = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': bucket_name,
                'Key': keys[0]
            },
            ExpiresIn=300
        )

        return url

    url = download_url()

    return Response(headers={
        'X-Terraform-Get': '/modules_v1/download.tar.gz?url=' + base64.b64encode(url.encode()).decode()
    })


def upload_version(event: HttpEvent, namespace: str, name: str, system: str, version: str) -> Response:
    logger.info(f'Attempting upload to namespace {namespace}')

    if not is_authorized_write(event, namespace):
        logger.info('Get out of here')
        raise Response('Forbidden', status=403)

    def upload_url() -> str:
        url: str = s3_client.generate_presigned_url(
            'put_object',
            Params={
                'Bucket': bucket_name,
                'Key': f'{namespace}/{name}/{system}/{version}.tar.gz'
            },
            ExpiresIn=300
        )

        return url

    return Response(status=307, headers={
        'Location': upload_url()
    })

modules_v1_router = create_router([
    (r'^/modules_v1/download.tar.gz$', download_redirect),
    (r'^/modules_v1/(?P<namespace>.*?)/(?P<name>.*?)/(?P<system>.*?)/versions$', list_versions),
    (r'^/modules_v1/(?P<namespace>.*?)/(?P<name>.*?)/(?P<system>.*?)/(?P<version>.*?)/download$', download_version),
    (r'^/modules_v1/(?P<namespace>.*?)/(?P<name>.*?)/(?P<system>.*?)/(?P<version>.*?)/upload$', upload_version)
])

def modules_v1(event: HttpEvent) -> Response:
    return modules_v1_router(event)
