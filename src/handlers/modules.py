from aws.api_gateway_types import HttpEvent
from aws.response import Response, create_router
from session.session import Session, with_session


def redirect_to_module(event: HttpEvent) -> Response:
    return Response(status=301, headers={
        'location': f'/module{event["rawPath"]}'
    })

@with_session
def show_module(event: HttpEvent, session: Session) -> Response:
    pass

modules_router = create_router([
    (r'^/module/(?P<namespace>[^/]+?)/(?P<name>[^/]+?)/(?P<system>[^/]+?)', show_module),
])

def modules(event: HttpEvent) -> Response:
    return modules_router(event)
