"""
Terraform Provider Network Mirror

"""

import json
import logging
import os.path

import boto3
from typing import Dict

from api_gateway import Response, Error, route_request, HttpEvent, LambdaContext, HttpResponse

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
bucket_name = os.environ['MirrorBucket']

def provider_index(event: HttpEvent, hostname: str, namespace: str, type: str) -> Response:
    object = s3_client.get_object(Bucket=bucket_name, Key=f'{hostname}/{namespace}/{type}/index.json')
    return Response(json.load(object['Body']))

def provider_packages(event: HttpEvent, hostname: str, namespace: str, type: str, version: str) -> Response:
    object = s3_client.get_object(Bucket=bucket_name, Key=f'{hostname}/{namespace}/{type}/{version}.json')
    packages = json.load(object['Body'])

    def sign_url(package: Dict) -> Dict:
        package['url'] = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': bucket_name,
                'Key': f'{hostname}/{namespace}/{type}/{package["url"]}'
            },
            ExpiresIn=300
        )

        return package

    packages['archives'] = { platform: sign_url(package) for platform, package in packages['archives'] }
    return Response(packages)
