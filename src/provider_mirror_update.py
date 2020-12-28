import logging
import os.path
import shutil
import boto3
import tempfile
from typing import Dict, Any
import subprocess

from api_gateway import LambdaContext

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
bucket_name = os.environ['MirrorBucket']

import requests
from typing import Dict
import urllib
from typing import Optional, List, TypedDict

class Platform(TypedDict):
    os: str
    arch: str

class Version(TypedDict):
    version: str
    protocols: Optional[List[str]]
    platforms: Optional[List[Platform]]

class ProviderRegistry:
    def __init__(self, hostname: str):
        self._session = requests.Session()

        response = self._session.get(f'{hostname}/.well-known/terraform.json')
        response.raise_for_status()

        service_discovery = response.json()
        if 'providers.v1' not in service_discovery:
            raise Exception(f'No provider registry at {hostname}')

        self._provider_registry_url = urllib.parse.urljoin(hostname, service_discovery['providers.v1'])

    def get_available_versions(self, namespace: str, type: str) -> List[Version]:
        response = self._session.get(f'{self._provider_registry_url}/{namespace}/{type}/versions')
        response.raise_for_status()
        return response.json()['versions']

class TempDir:
    def __enter__(self):
        self.dir = tempfile.mkdtemp()
        return self.dir

    def __exit__(self, exc_type, exc_val, exc_tb):
        shutil.rmtree(self.dir, ignore_errors=True)

def mirror_package(hostname: str, namespace: str, type: str, version: str, operating_sys: str, arch: str) -> None:

    with TempDir() as d:
        with open(os.path.join(d, 'provider.tf'), 'w') as f:
            f.write('''
    terraform {
      required_providers {
        %s = {
          source  = "%s"
          version = "%s"
        }
      }
    }
            ''' % (type, f'{hostname}/{namespace}/{type}', version))

        mirror = subprocess.call('terraform providers mirror packages', shell=True, cwd=d)

def handler(event: Dict[str, Any], context: LambdaContext = None) -> None:
    logger.info('event: %r', event)

if __name__ == '__main__':
    mirror_package('registry.terraform.io', 'hashicorp', 'aws', '3.22.0', 'darwin', 'amd64')
