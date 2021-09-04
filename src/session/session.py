import uuid
from typing import List, Dict, Optional
import wrapt

import logging
import boto3
import os

from aws.api_gateway_types import HttpEvent
from aws.response import Response

logger = logging.getLogger(__name__)
session_table = boto3.resource('dynamodb').Table(os.environ['SessionsTable'])


def method_is_safe(event: HttpEvent) -> bool:
    return event['requestContext']['http']['method'] in ['GET', 'HEAD', 'OPTIONS']

def existing_session_item(cookies: Dict[str, str]) -> Optional[Dict]:
    if (
        '__Host-session-strict' in cookies and '__Host-session-lax' in cookies
        and cookies['__Host-session-strict'] != cookies['__Host-session-lax']
    ):
        logger.warning('Possible attack: cookie mismatch')
        return None

    if '__Host-session-strict' in cookies and '__Host-session-lax' not in cookies:
        logger.warning('Possible attack: missing lax cookie')
        return None

    if '__Host-session-lax' not in cookies:
        return None

    session_id = cookies.get('__Host-session-strict') or cookies['__Host-session-lax']

    response = session_table.get_item(Key={'session_id': session_id}, ConsistentRead=True)
    if 'Item' in response:
        return response['Item']

    logger.warning('Possible attack: Client sent unknown session id')
    return None

class Session:
    CSRF_HEADER='csrf-token'

    def __init__(self, event: HttpEvent):
        cookies = {k: v for k, v in (cookie.split('=', maxsplit=1) for cookie in event.get('cookies', []))}

        self._session = existing_session_item(cookies)
        self._same_site = self._session and '__Host-session-strict' in cookies

        if self._session is None:
            self._session = {
                'session_id': str(uuid.uuid4()),
                'csrf_token': str(uuid.uuid4())
            }
            logger.info('Creating session')
            session_table.put_item(Item=self._session)

        if not method_is_safe(event):
            if self.CSRF_HEADER not in event['headers']:
                logger.warning('Possible attack: Missing csrf_token')
                raise Response('A problem occurred', status=400)

            elif event['headers'][self.CSRF_HEADER] != self._session['csrf_token']:
                logger.warning('Possible attack: Incorrect csrf_token')
                raise Response('A problem occurred', status=400)

            if self._same_site is False:
                logger.warning('Possible attack: Unsafe request using lax session id')
                raise Response('A problem occurred', status=400)

            if event['headers'].get('sec-fetch-site') in ['cross-site', 'same-site']:
                logger.warning('Possible attack: Unsafe cross-site request')
                raise Response('A problem occurred', status=400)

            if 'origin' in event['headers'] and event['headers']['origin'] != f'https://{event["headers"]["host"]}':
                logger.warning('Possible attack: Unsafe request has origin header mismatch')
                raise Response('A problem occurred', status=400)

            if 'referer' in event['headers'] and not event['headers']['referer'].startswith(f'https://{event["headers"]["host"]}/'):
                logger.warning('Possible attack: Unsafe request has referer header mismatch')
                raise Response('A problem occurred', status=400)

    def renew(self) -> None:
        logger.info('Refreshing existing session with a new id')
        old_session_id = self._session['session_id']
        self._session['session_id'] = str(uuid.uuid4())
        session_table.put_item(Item=self._session)
        session_table.delete_item(Key={'session_id': old_session_id})

    def logout(self) -> None:
        logger.info('Replacing session with a new unauthorised session')
        old_session_id = self._session['session_id']
        self._session = {
            'session_id': str(uuid.uuid4()),
            'csrf_token': str(uuid.uuid4())
        }
        session_table.put_item(Item=self._session)
        session_table.delete_item(Key={'session_id': old_session_id})

    def authorise(self, **kwargs):
        logger.info('Replacing session with a new authorised session')
        old_session_id = self._session['session_id']
        self._session = {
            'session_id': str(uuid.uuid4()),
            'csrf_token': str(uuid.uuid4()),
            **kwargs
        }
        session_table.put_item(Item=self._session)
        session_table.delete_item(Key={'session_id': old_session_id})

    @property
    def same_site(self) -> bool:
        """
        Is the request origin from 'same-site'

        Unsafe actions must require same-site. The is automatically asserted for unsafe methods

        """
        return self._same_site

    @property
    def id(self) -> str:
        """
        The Session ID
        """
        return self._session['session_id']

    @property
    def csrf_token(self) -> str:
        """
        The CSRF token to be included in the 'csrf-token' header for unsafe requests.
        """
        return self._session['csrf_token']

    @property
    def user(self) -> Optional[Dict]:
        """
        Information about the authenticated user

        If the user is not authenticated, this will be None
        """

        return self._session.get('github_user')

    @property
    def session_cookies(self) -> Dict[str, str]:
        """
        Cookies that should be included in the response
        """

        return {
            f'__Host-session-strict': f'{self.id}; Path=/; Secure; HttpOnly; SameSite=Strict',
            f'__Host-session-lax': f'{self.id}; Path=/; Secure; HttpOnly; SameSite=Lax'
        }

    @property
    def expires(self) -> int:
        """
        When this session should be refreshed
        """
        return 0

@wrapt.decorator
def with_session(wrapped, instance, args, kwargs):
    def _execute(event, *_args, **_kwargs):
        session = Session(event)
        response = wrapped(event, session, *_args, **_kwargs)
        response.cookies.update(session.session_cookies)
        return response

    return _execute(*args, **kwargs)
