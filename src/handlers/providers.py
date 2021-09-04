from aws.api_gateway_types import HttpEvent
from aws.response import Response, create_router
from session.session import Session, with_session


def redirect_to_provider(event: HttpEvent) -> Response:
    return Response(status=301, headers={
        'location': f'/provider{event["rawPath"]}'
    })

@with_session
def show_provider(event: HttpEvent, session: Session) -> Response:
    pass

providers_router = create_router([
    (r'^/provider/(?P<namespace>[^/]+?)/(?P<type>[^/]+?)$', show_provider),
])

def modules(event: HttpEvent) -> Response:
    return providers_router(event)
