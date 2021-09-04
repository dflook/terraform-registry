import logging

from aws.api_gateway_types import HttpEvent, HttpResponse
from aws.awslambda import LambdaContext
from aws.response import Response, create_router
from handlers.login_v1 import cli_login
from handlers.index import index
from handlers.service_discovery import service_discovery
from handlers.user import user

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

ui_router = create_router([
    (r'^/\.well-known/terraform\.json$', service_discovery),
    (r'^/$', index),
    (r'^/user/.+$', ['GET', 'POST'], user),

    # (r'^/modules_v1/.+$', modules_v1),
    # (r'^/providers_v1/.+$', providers_v1),
    (r'^/login_v1/.+$', cli_login),

    # (r'^/namespace/.+$', namespace),
    # ('^/module/.+$', modules),
    # ('^/provider/.+$', providers),

    # (r'^/(?P<hostname>[^/]+)/(?P<namespace>[^/]+)/(?P<type>[^/]+)/index\.json$', provider_mirror_index),
    # (r'^/(?P<hostname>[^/]+)/(?P<namespace>[^/]+)/(?P<type>[^/]+)/\d+\.\d+\.\d+\.json$', provider_mirror_packages),

    # ('^/(?P<namespace>[^/]+?)/(?P<name>[^/]+?)/(?P<system>[^/]+?)$', redirect_to_module),
    # ('^/(?P<namespace>[^/]+?)/(?P<type>[^/]+?)$', redirect_to_provider),

    # (r'^/(?P<path>.+)$', static_asset),
])

def handle(event:HttpEvent) -> HttpResponse:
    try:
        response = ui_router(event)

        return response.api_gateway_response()
    except Response as response:
        logger.exception('Error')
        return response.api_gateway_response()
    except Exception as exception:
        logger.exception('Exception is %r', type(exception))
        return Response('Internal Error', status=500).api_gateway_response()


def handler(event: HttpEvent, _: LambdaContext = None) -> HttpResponse:
    logger.info('event: %r', event)
    response = handle(event)
    logger.info('response: %r', response)
    return response
