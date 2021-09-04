import os

from aws.api_gateway_types import HttpEvent
from aws.response import Response, TemplateResponse
from session.session import with_session, Session


@with_session
def index(_: HttpEvent, session: Session) -> Response:
    return TemplateResponse('index.html',
                            context={
                                'user': session.user,
                                'csrf_token': session.csrf_token
                            },
                            headers={'cache-control': 'no-cache'})
