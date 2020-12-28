import logging
import os
import typing

from api_gateway import Response, Error, HttpEvent, HttpResponse, LambdaContext

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

def handler(event: HttpEvent, _: LambdaContext = None) -> HttpResponse:
    logger.info(f'event: {event}')

    try:
        response = Response({'message':'hello'})

        return response.api_gateway_response()
    except Error as registry_error:
        logger.exception('Error')
        return registry_error.api_gateway_response()
    except Exception as exception:
        logger.exception(type(exception))
        return Error(500, 'Internal Error', str(exception)).api_gateway_response()
