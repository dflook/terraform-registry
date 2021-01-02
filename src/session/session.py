import uuid
from typing import List, Dict, Optional
import wrapt

from api_gateway import HttpEvent
import boto3
import os

session_table = boto3.resource('dynamodb').Table(os.environ['SessionTable'])

class Session:
    """
    A user session

    A session is

    Every request is part of a session.
    Each request extends the life of the session.

    Unsafe requests require a custom header

    """

    CSRF_HEADER='csrf-token'

    def __init__(self, event: HttpEvent):
        cookies = {k: v for k, v in (cookie.split('=') for cookie in event['cookies'])}

        self._strict = cookies.get('__Host-session-strict')
        self._lax = cookies.get('__Host-session-lax')

        if self._strict is not None and self._lax is not None and self._strict != self._lax:
            # Clear session
            raise Exception('400 Mixed session cookies')

        self._session_id = self._strict or self._lax or uuid.uuid4()

        if not self._session_id:
            return

        response = session_table.get_item(Key={'session_id': self._session_id})
        if 'Item' in response:
            self._session = response['Item']

        if event['requestContext']['http']['method'] not in ['GET', 'HEAD', 'OPTIONS']:
            # unsafe method
            if event['headers'][self.CSRF_HEADER] != self._session['csrf_token']:
                # Shenanigans
                raise Exception()

    @property
    def user(self) -> Optional[Dict]:
        """
        Information about the authenticated user

        If the user is not authenticated, this will be None
        """

        return None

    @property
    def headers(self) -> Dict[str, str]:
        """
        Custom headers that should be included in any requests using unsafe methods
        """

        return {
            self.CSRF_HEADER: self._session['csrf_token']
        }

    @property
    def session_cookies(self) -> List[str]:
        """
        Cookies that should be included in the response
        """

        return [
            f'__Host-session-strict={self._session_id}; Path=/; Secure; HttpOnly; SameSite=Strict',
            f'__Host-session-lax={self._session_id}; Path=/; Secure; HttpOnly; SameSite=Lax',
        ]
