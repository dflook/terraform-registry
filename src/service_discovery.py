import logging
import os
import typing

from api_gateway import Response, Error, HttpEvent, HttpResponse, LambdaContext

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


def service_discovery(services: typing.Mapping[str, str]) -> Response:
    payload = {}

    if 'modules_v1' in services:
        payload['modules.v1'] = services['modules_v1'] + '/'

    if 'providers_v1' in services:
        payload['providers.v1'] = services['providers_v1'] + '/'

    if 'login_v1' in services:
        payload['login.v1'] = {
            'client': 'terraform-cli',
            'grant_types': ['authz_code'],
            'authz': services['login_v1'] + '/oauth/authorization',
            'token': services['login_v1'] + '/oauth/token'
          }

    return Response(payload, headers={'cache-control': 'public, max-age=300'})


def handler(event: HttpEvent, _: LambdaContext = None) -> HttpResponse:
    logger.info(f'event: {event}')

    try:
        response = service_discovery(os.environ)

        return response.api_gateway_response()
    except Error as registry_error:
        logger.exception('Error')
        return registry_error.api_gateway_response()
    except Exception as exception:
        logger.exception(type(exception))
        return Error(500, 'Internal Error', str(exception)).api_gateway_response()
