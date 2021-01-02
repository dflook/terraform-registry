from aws.api_gateway_types import HttpEvent
from aws.response import Response, TemplateResponse


def index(_: HttpEvent) -> Response:
    return TemplateResponse('index.html', headers={'cache-control': 'no-cache'})
