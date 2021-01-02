import logging

from aws.api_gateway_types import HttpEvent, HttpResponse
from aws.awslambda import LambdaContext
from aws.response import Response, create_router
from handlers.assets import static_asset
from handlers.index import index
from handlers.modules_v1 import modules_v1
from handlers.service_discovery import service_discovery

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

ui_router = create_router([
    (r'^/.well-known/terraform.json$', service_discovery),
    (r'^/$', index),
    (r'^/modules_v1/.+$', modules_v1),
    (r'^/(?P<path>.+)$', static_asset),
])


def handler(event: HttpEvent, _: LambdaContext = None) -> HttpResponse:
    logger.info('event: %r', event)

    try:
        response = ui_router(event)

        return response.api_gateway_response()
    except Response as response:
        logger.exception('Error')
        return response.api_gateway_response()
    except Exception as exception:
        logger.exception('Exception is %r', type(exception))
        return Response('Internal Error', status=500).api_gateway_response()
