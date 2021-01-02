from typing import Dict, List, TypedDict, Literal, Optional


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
