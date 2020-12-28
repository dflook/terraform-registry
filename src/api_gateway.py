import json
import logging
import re
from typing import Dict, List, Tuple, Callable, TypedDict, Literal, Optional, Any, cast

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


class Validity(TypedDict):
    notBefore: str
    notAfter: str


class ClientCert(TypedDict):
    clientCertPem: str
    subjectDN: str
    issuerDN: str
    serialNumber: str
    validity: Validity


class Authentication(TypedDict):
    clientCert: Optional[ClientCert]


class JWT(TypedDict):
    claims: Dict[str, str]
    scopes: Dict[str, str]


class Authorizer(TypedDict):
    jwt: Optional[JWT]


class Http(TypedDict):
    method: str
    path: str
    protocol: str
    sourceIp: str
    userAgent: str


class RequestContext(TypedDict):
    accountId: str
    apiId: str
    authentication: Authentication
    authorizer: Authorizer
    domainName: str
    domainPrefix: str
    http: Http
    requestId: str
    routeKey: str
    stage: str
    time: str
    timeEpoch: int


class HttpEvent(TypedDict):
    version: Literal["2.0"]
    routeKey: str
    rawPath: str
    rawQueryString: str
    cookies: List[str]
    headers: Dict[str, str]
    queryStringParameters: Dict[str, str]
    requestContext: RequestContext
    body: str
    pathParameters: Dict[str, str]
    isBase64Encoded: bool
    stageVariables: Dict[str, str]


class HttpResponse(TypedDict):
    cookies: List[str]
    isBase64Encoded: bool
    statusCode: int
    headers: Dict[str, str]
    body: str


class LambdaContext(object):
    function_name: str
    function_version: int
    invoked_function_arn: str
    memory_limit_in_mb: int
    aws_reqeuest_id: str
    log_group_name: str
    log_stream_name: str

    @staticmethod
    def get_remaining_time_in_millis() -> int:
        pass


class Response:
    def __init__(self, payload: Dict[str, Any] = None, *, status_code: int = None, headers: Dict = None):
        if status_code is None:
            status_code = 200 if payload is not None else 204

        self.content = json.dumps(payload) if payload is not None else ''
        self.status_code = status_code
        self.headers = headers if headers is not None else {}

        if payload is not None:
            self.headers['content-type'] = 'application/json'

    def api_gateway_response(self) -> HttpResponse:
        response = HttpResponse(statusCode=self.status_code, body=self.content, headers=self.headers,
                                isBase64Encoded=False, cookies=[])

        logger.info(f'Response status {self.status_code}, headers: {self.headers}, body: {self.content}')

        return response


def route_request(event: HttpEvent, routes: List[Tuple[str, Callable]]) -> Response:
    for pattern, handler in routes:
        match = re.match(pattern, event['rawPath'])

        if match:
            return cast(Response, handler(event, **match.groupdict()))

    return Response(status_code=404)


class Error(Response, Exception):
    def __init__(self, status_code: int = 500, *errors: str):
        super().__init__(payload={
            'errors': errors
        }, status_code=status_code)
