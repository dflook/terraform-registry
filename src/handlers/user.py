import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from typing import Dict
from urllib.parse import urlencode

import logging

import boto3
import requests

from aws.api_gateway_types import HttpEvent
from aws.response import create_router, Response, TemplateResponse, JsonResponse
from session.session import Session, with_session

logger = logging.getLogger(__name__)

http_session = requests.Session()

STATE_SECRET = hashlib.sha512('terraform'.encode()).digest()

api_tokens_table = boto3.resource('dynamodb').Table(os.environ['ApiTokensTable'])

API_TOKEN_TTL = 600

# The state token is like a JWT, but without the bullshit.
# The header is unnecessary, it's always hmac sha512.
# urlencoding is also not necessary.

def encode_state(state: Dict[str, str]) -> str:
    payload = json.dumps(state, separators=(',', ':')).encode()
    signature = hmac.digest(STATE_SECRET, payload, 'sha512')
    return (base64.b64encode(payload) + b'.' + base64.b64encode(signature)).decode()


def decode_state(token: str) -> Dict[str, str]:
    payload_enc, signature_enc = token.encode().split(b'.', maxsplit=1)
    payload, signature = base64.b64decode(payload_enc), base64.b64decode(signature_enc)
    if hmac.digest(STATE_SECRET, payload, 'sha512') != signature:
        raise Response(status=403)

    return json.loads(payload)

@with_session
def login_with_github(event: HttpEvent, session: Session) -> Response:
    if session.user:
        return Response(status=302, headers={
            'location': event.get('queryStringParameters', {}).get('redirect_to', '/')
        })

    state_token = encode_state({
        'csrf_token': session.csrf_token,
        'redirect_to': event.get('queryStringParameters', {}).get('redirect_to', '/')
    })

    github_url = 'https://github.com/login/oauth/authorize?'
    github_url += urlencode({
        'state': state_token,
        'client_id': os.environ['GITHUB_CLIENT_ID'],
        'redirect_uri': 'https://terraform-dev.flook.org/user/login/github/authorize'
    })
    logger.info('Redirecting user to github to login')
    return Response(status=302, headers={'location': github_url})

@with_session
def access_token(event: HttpEvent, session: Session) -> Response:

    state = decode_state(event['queryStringParameters'].get('state'))
    if state['csrf_token'] != session.csrf_token:
        logger.warning('Invalid state in OAuth flow')
        return Response(status=403)

    token_response = http_session.post(
        'https://github.com/login/oauth/access_token',
        data={
            'client_id': os.environ['GITHUB_CLIENT_ID'],
            'client_secret': os.environ['GITHUB_CLIENT_SECRET'],
            'code': event['queryStringParameters']['code'],
            'state': event['queryStringParameters']['state'],
            'redirect_uri': 'https://terraform-dev.flook.org/user/login/github/authorize'
        },
        headers={
            'accept': 'application/json'
        }
    )

    token_response.raise_for_status()
    github_token = token_response.json()['access_token']

    github_user_response = http_session.get(
        'https://api.github.com/user',
        headers={
            'accept': 'application/vnd.github.v3+json',
            'Authorization': f'token {github_token}'
        }
    )
    github_user_response.raise_for_status()

    session.authorise(
        github_access_token=github_token,
        github_user=github_user_response.json()
    )

    logger.warning('Successfully got a github token using OAuth')
    return Response(status=302, headers={
        'location': state['redirect_to']
    })

@with_session
def logout(event: HttpEvent, session: Session) -> Response:
    session.logout()
    return Response(status=302, headers={
        'location': '/'
    })


@with_session
def security(_: HttpEvent, session: Session) -> Response:
    if session.user is None:
        return Response(status=302, headers={
            'location': '/user/login?redirect_to=/user/security'
        })

    return TemplateResponse('account_security.html',
                            context={
                                'client_id': os.environ['GITHUB_CLIENT_ID'],
                                'user': session.user,
                                'csrf_token': session.csrf_token
                            },
                            headers={'cache-control': 'no-cache'})

@with_session
def create_api_token(event: HttpEvent, session: Session) -> JsonResponse:
    if event['requestContext']['http']['method'] != 'POST':
        return JsonResponse(status=501)

    if session.user is None:
        return JsonResponse(status=403)

    token = str(uuid.uuid4())

    api_tokens_table.put_item(Item={
        'token': token,
        'user': session.user['login'],
        'client_id': 'Web Session',
        'exp': int(time.time()) + API_TOKEN_TTL,
        'created_at': int(time.time())
    })

    return JsonResponse(
        {
            'access_token': token,
            'token_type': '',
            'expires_in': API_TOKEN_TTL,
        },
        headers={
            'cache-control': 'no-store'
        }
    )


user_router = create_router([
    (r'^/user/login$', login_with_github),
    (r'^/user/login/github$', login_with_github),
    (r'^/user/login/github/authorize$', access_token),
    (r'^/user/api_tokens$', 'POST', create_api_token),
    (r'^/user/logout$', 'POST', logout),
    (r'^/user/security$', security),
])

def user(event: HttpEvent) -> Response:
    return user_router(event)
