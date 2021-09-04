import logging

from aws.api_gateway_types import HttpEvent
from aws.response import JsonResponse

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def service_discovery(_: HttpEvent) -> JsonResponse:
    payload = {
        'modules.v1': '/modules_v1/',
        'providers.v1': '/providers_v1/',
        'login.v1': {
            'client': 'terraform-cli',
            'grant_types': ['authz_code'],
            'authz': '/login_v1/oauth/authorization',
            'token': '/login_v1/oauth/token',
        },
    }

    return JsonResponse(payload, headers={'cache-control': 'public, max-age=300'})
