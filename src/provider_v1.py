import base64
import logging
import os
import os.path
from typing import Iterable, Optional, Tuple

import boto3
from semantic_version import Version

from api_gateway import Response, Error, route_request, HttpResponse, LambdaContext, HttpEvent
from auth import is_authorized_write, is_authorized_read

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
bucket_name = os.environ['providerBucket']


def archive_version(key: str) -> Optional[Version]:
    filename = os.path.basename(key)
    for ext in ['.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz', '.zip']:
        if filename.endswith(ext):
            return Version(filename[:-len(ext)])

    return None


def download_redirect(event: HttpEvent) -> Response:
    return Response(
        status_code=302,
        headers={
            'Location': base64.b64decode(event['queryStringParameters']['url']).decode(),
        }
    )


def list_versions(event: HttpEvent, namespace: str, type: str) -> Response:
    logger.info(
        f'Attempting to list package namespace {namespace}')

    if not is_authorized_read(event, namespace):
        logger.info('Not allowed to read namespace')
        raise Error(403, 'Forbidden')

    def list_versions() -> Iterable[str]:
        """List Available Versions for a Specific Module"""

        response = s3_client.list_objects_v2(
            Bucket=bucket_name,
            Prefix=f'{namespace}/{type}/'
        )

        if 'Contents' not in response:
            return []

        keys = [obj['Key'] for obj in response.get('Contents', []) if obj['Size'] > 0]
        return [str(archive_version(key)) for key in keys]

    versions = list_versions()
    response = {
        'versions': [{
            'version': version
        } for version in versions]
    }
    return Response(response, headers={'content-type': 'application/json'})


def download_package(event: HttpEvent, namespace: str, type: str, version: str, os: str, arch: str) -> Response:
    logger.info(f'Attempting download from namespace {namespace}')

    if not is_authorized_read(event, namespace):
        logger.info('Not allowed to download version')
        raise Error(403, 'Forbidden')

    def download_urls() -> Tuple[str, str, str]:
        'Return a download link for this provider'

        response = s3_client.list_objects_v2(
            Bucket=bucket_name,
            Prefix=f'{namespace}/{type}/{version}/{os}/{arch}'
        )

        if 'Contents' not in response:
            raise Error(404, f'Provider not found for {namespace}/{type}/{version}/{os}/{arch}')

        keys = [obj['Key'] for obj in response.get('Contents', []) if obj['Size'] > 0]

        url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': bucket_name,
                'Key': keys[0]
            },
            ExpiresIn=300
        )

        shasum_url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': bucket_name,
                'Key': keys[0] + '.sha256'
            },
            ExpiresIn=300
        )

        sig_url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': bucket_name,
                'Key': keys[0] + '.sha256.sig'
            },
            ExpiresIn=300
        )

        return url, shasum_url, sig_url

    download_url, shasum_url, sig_url = download_urls()

    return Response({
        "protocols": ["5.0"],
        "os": os,
        "arch": arch,
        "filename": f"terraform-provider-{type}_{version}_{os}_{arch}.zip",
        "download_url": download_url,
        "shasums_url": shasum_url,
        "shasums_signature_url": sig_url,
        "signing_keys": {
            "gpg_public_keys": [
                {
                    "key_id": "51852D87348FFC4C",
                    "ascii_armor": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1\n\nmQENBFMORM0BCADBRyKO1MhCirazOSVwcfTr1xUxjPvfxD3hjUwHtjsOy/bT6p9f\nW2mRPfwnq2JB5As+paL3UGDsSRDnK9KAxQb0NNF4+eVhr/EJ18s3wwXXDMjpIifq\nfIm2WyH3G+aRLTLPIpscUNKDyxFOUbsmgXAmJ46Re1fn8uKxKRHbfa39aeuEYWFA\n3drdL1WoUngvED7f+RnKBK2G6ZEpO+LDovQk19xGjiMTtPJrjMjZJ3QXqPvx5wca\nKSZLr4lMTuoTI/ZXyZy5bD4tShiZz6KcyX27cD70q2iRcEZ0poLKHyEIDAi3TM5k\nSwbbWBFd5RNPOR0qzrb/0p9ksKK48IIfH2FvABEBAAG0K0hhc2hpQ29ycCBTZWN1\ncml0eSA8c2VjdXJpdHlAaGFzaGljb3JwLmNvbT6JATgEEwECACIFAlMORM0CGwMG\nCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEFGFLYc0j/xMyWIIAIPhcVqiQ59n\nJc07gjUX0SWBJAxEG1lKxfzS4Xp+57h2xxTpdotGQ1fZwsihaIqow337YHQI3q0i\nSqV534Ms+j/tU7X8sq11xFJIeEVG8PASRCwmryUwghFKPlHETQ8jJ+Y8+1asRydi\npsP3B/5Mjhqv/uOK+Vy3zAyIpyDOMtIpOVfjSpCplVRdtSTFWBu9Em7j5I2HMn1w\nsJZnJgXKpybpibGiiTtmnFLOwibmprSu04rsnP4ncdC2XRD4wIjoyA+4PKgX3sCO\nklEzKryWYBmLkJOMDdo52LttP3279s7XrkLEE7ia0fXa2c12EQ0f0DQ1tGUvyVEW\nWmJVccm5bq25AQ0EUw5EzQEIANaPUY04/g7AmYkOMjaCZ6iTp9hB5Rsj/4ee/ln9\nwArzRO9+3eejLWh53FoN1rO+su7tiXJA5YAzVy6tuolrqjM8DBztPxdLBbEi4V+j\n2tK0dATdBQBHEh3OJApO2UBtcjaZBT31zrG9K55D+CrcgIVEHAKY8Cb4kLBkb5wM\nskn+DrASKU0BNIV1qRsxfiUdQHZfSqtp004nrql1lbFMLFEuiY8FZrkkQ9qduixo\nmTT6f34/oiY+Jam3zCK7RDN/OjuWheIPGj/Qbx9JuNiwgX6yRj7OE1tjUx6d8g9y\n0H1fmLJbb3WZZbuuGFnK6qrE3bGeY8+AWaJAZ37wpWh1p0cAEQEAAYkBHwQYAQIA\nCQUCUw5EzQIbDAAKCRBRhS2HNI/8TJntCAClU7TOO/X053eKF1jqNW4A1qpxctVc\nz8eTcY8Om5O4f6a/rfxfNFKn9Qyja/OG1xWNobETy7MiMXYjaa8uUx5iFy6kMVaP\n0BXJ59NLZjMARGw6lVTYDTIvzqqqwLxgliSDfSnqUhubGwvykANPO+93BBx89MRG\nunNoYGXtPlhNFrAsB1VR8+EyKLv2HQtGCPSFBhrjuzH3gxGibNDDdFQLxxuJWepJ\nEK1UbTS4ms0NgZ2Uknqn1WRU1Ki7rE4sTy68iZtWpKQXZEJa0IGnuI2sSINGcXCJ\noEIgXTMyCILo34Fa/C6VCm2WBgz9zZO8/rHIiQm1J5zqz0DrDwKBUM9C\n=LYpS\n-----END PGP PUBLIC KEY BLOCK-----",
                }
            ]
        }
    })


def upload_version(event: HttpEvent, namespace: str, name: str, provider: str, version: str) -> Response:
    logger.info(f'Attempting upload to namespace {namespace}')

    if not is_authorized_write(event, namespace):
        logger.info('Get out of here')
        raise Error(403, 'Forbidden')

    def upload_url() -> str:
        'Return an upload link for this provider'

        url: str = s3_client.generate_presigned_url(
            'put_object',
            Params={
                'Bucket': bucket_name,
                'Key': f'{namespace}/{name}/{provider}/{version}.tar.gz'
            },
            ExpiresIn=300
        )

        return url

    return Response(status_code=307, headers={
        'Location': upload_url()
    })


def provider_registry(event: HttpEvent) -> Response:
    return route_request(event, [
        (r'^/download.tar.gz$', download_redirect),
        (r'^/(?P<namespace>.*?)/(?P<type>.*?)/(?P<version>.*?)/download/(?P<os>.*?)/(?P<arch>.*?)$', download_package),
        (r'^/(?P<namespace>.*?)/(?P<type>.*?)/versions$', list_versions),
    ])


def handler(event: HttpEvent, _: LambdaContext = None) -> HttpResponse:
    logger.info(f'event: {event}')

    try:
        response = provider_registry(event)

        return response.api_gateway_response()
    except Error as registry_error:
        logger.exception('Error')
        return registry_error.api_gateway_response()
    except Exception as exception:
        logger.exception('Exception is %r', type(exception))
        return Error(500, 'Internal Error', str(exception)).api_gateway_response()
