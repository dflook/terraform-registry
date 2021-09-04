import base64
import json
import logging
import mimetypes
import re
import hashlib
import uuid
from typing import Dict, List, Tuple, Callable, cast

import jinja2

from aws.api_gateway_types import HttpResponse, HttpEvent

logger = logging.getLogger('response')
logger.setLevel(logging.INFO)


class Response(Exception):
    def __init__(self,
                 response: str = None,
                 *,
                 status: int = None,
                 headers: Dict[str, str] = None,
                 content_type: str = None,
                 cookies: Dict[str, str] = None):

        self.response = response
        self.status = status or (200 if response else 204)
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.base64encode = False

        if content_type:
            self.headers['content-type'] = content_type

    def __repr__(self):
        return f'Response(status={self.status}, headers={self.headers}, cookies={self.cookies})'

    def __str__(self):
        return f'HTTP {self.status} Response'

    def api_gateway_response(self) -> HttpResponse:

        self.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        http_response = HttpResponse(
            statusCode=self.status,
            body=self.response if not self.base64encode else base64.b64encode(self.response),
            headers=self.headers,
            isBase64Encoded=self.base64encode,
            cookies=[f'{k}={v}' for k, v in self.cookies.items()]
        )

        logger.info(f'Sending {self}')

        return http_response


class JsonResponse(Response):
    def __init__(self,
                 response: Dict = None,
                 *,
                 status: int = None,
                 headers: Dict[str, str] = None,
                 cookies: Dict[str, str] = None):
        super().__init__(json.dumps(response), status=status, headers=headers, content_type='application/json',
                         cookies=cookies)

jinja_env = jinja2.Environment(
    auto_reload=False,
    loader=jinja2.ModuleLoader('./templates.zip'),
    autoescape=jinja2.select_autoescape(['html', 'xml'])
)

def generate_nonce() -> str:
    return base64.b64encode(hashlib.sha256(str(uuid.uuid4()).encode()).digest()).decode()

class TemplateResponse(Response):
    def __init__(self,
                 template_path: str,
                 context: Dict = None,
                 *,
                 status: int = None,
                 headers: Dict[str, str] = None,
                 cookies: Dict[str, str] = None):

        if headers is None:
            headers = {}

        script_nonce = generate_nonce()
        style_nonce = generate_nonce()
        context['csp'] = {
            'script_nonce': script_nonce,
            'style_nonce': style_nonce
        }

        template = jinja_env.get_template(template_path)
        response = template.render(context) if context is not None else template.render()
        headers['etag'] = f'"{hashlib.blake2b(response.encode()).hexdigest()}"'

        nonce = {'script': script_nonce}

        headers['content-security-policy'] = ';'.join(f'{k} {v}' for k, v in {
            'default-src': "'none'",
            'form-action': "'none'",
            'base-uri': "'none'",
            'connect-src': "'self'",
            'frame-ancestors': "'none'",
            'img-src': f"'self' https://avatars.githubusercontent.com",
            'script-src': f"'self' 'nonce-{script_nonce}'",
            'style-src': f"'self' 'nonce-{style_nonce}'"
        }.items())

        if 'content-type' in headers:
            content_type = None
        else:
            content_type, _ = mimetypes.guess_type(template_path)

        super().__init__(response, status=status, headers=headers, content_type=content_type, cookies=cookies, )

def compile_routes(routes):
    for route in routes:
        if len(route) == 3:
            pattern, methods, handler = route
            if isinstance(methods, str):
                methods = [methods]
        else:
            pattern, handler = route
            methods = ['GET']

        for method in methods:
            yield re.compile(pattern), method, handler


def create_router(routes: List[Tuple[str, Callable]]) -> Callable[[HttpEvent], Response]:

    compiled_routes = list(compile_routes(routes))

    def route_request(event: HttpEvent) -> Response:
        for route in compiled_routes:
            pattern, method, handler = route

            match = pattern.match(event['rawPath'])

            if match and event['requestContext']['http']['method'] == method:
                logger.info('Matched ' + method + ' ' + str(pattern) + ' - calling' + str(handler))
                r = cast(Response, handler(event, **match.groupdict()))
                return r

        r = Response(status=404)
        return r

    return route_request
