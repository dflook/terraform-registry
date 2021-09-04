import os
import logging
import time

import boto3
from urllib.parse import urlencode, parse_qsl
import base64
import uuid

from aws.api_gateway_types import HttpEvent
from aws.response import JsonResponse, Response, create_router
from handlers.user import encode_state, decode_state
from session.session import with_session, Session

logger = logging.getLogger()
logger.setLevel(logging.INFO)

#users_table = boto3.resource('dynamodb').Table(os.environ['Users'])
api_tokens_table = boto3.resource('dynamodb').Table(os.environ['ApiTokensTable'])
auth_code_table = boto3.resource('dynamodb').Table(os.environ['AuthCodesTable'])

AUTH_CODE_TTL = 30
API_TOKEN_TTL = 600

@with_session
def authorization(event: HttpEvent, session: Session) -> Response:
    """
    There may or may not be a user session
    """

    if session.user is None:
        return Response(
            status=303,
            headers={
                'location': '/user/login?redirect_to=/login_v1/oauth/authorize'
            },
            cookies={ # TODO: secure
                'oauth_login': encode_state(event['queryStringParameters'])
            }
        )

    return Response(
        status=303,
        headers={
            'location': '/login_v1/oauth/authorize'
        },
        cookies={
            'oauth_login': encode_state(event['queryStringParameters'])
        }
    )


@with_session
def do_authorize(event: HttpEvent, session: Session) -> Response:
    """
    There may or may not be a user session
    """

    if session.user is None:
        return JsonResponse(
            status=403,
        )

    cookies = {k: v for k, v in (cookie.split('=', maxsplit=1) for cookie in event.get('cookies', []))}
    auth_info = decode_state(cookies['oauth_login'])

    if auth_info.get('client_id') != 'terraform-cli':
        return JsonResponse({'error': 'invalid_client'}, status=400)
    if auth_info.get('response_type') != 'code':
        return JsonResponse(status=400)

    code = str(uuid.uuid4())

    auth_code_table.put_item(Item={
        'code': code,
        'user': session.user['login'],
        'redirect_uri': auth_info['redirect_uri'],
        'code_challenge': auth_info.get('code_challenge', ''),
        'code_challenge_method': auth_info.get('code_challenge_method', ''),
        'exp': int(time.time()) + AUTH_CODE_TTL,
        'response_type': auth_info.get('response_type', ''),
        'client_id': auth_info['client_id'],
    })

    redirect = auth_info['redirect_uri'] + '?'
    redirect += urlencode({
        'state': auth_info['state'],
        'code': code
    })

    return JsonResponse(
        status=303,
        headers={
            'location': redirect
        },
        cookies={
            'oauth_login': ''
        }
    )

def token(event: HttpEvent) -> JsonResponse:
    """
    :param event:
    :return:
    """

    body = base64.b64decode(event['body']) if event['isBase64Encoded'] else event['body']
    logger.info('Body is %r', body)

    request = { k.decode(): v.decode() for k, v in parse_qsl(body) }
    logger.info('token_request is %r', request)

    response = auth_code_table.get_item(Key={'code': request['code']})

    if 'Item' not in response:
        return JsonResponse(status=400)

    auth_code = response['Item']

    if (auth_code['redirect_uri'] != request['redirect_uri'] or
        auth_code['exp'] < int(time.time())):

        return JsonResponse(status=400)

    # Code is valid

    token = str(uuid.uuid4())

    api_tokens_table.put_item(Item={
        'token': token,
        'user': auth_code['user'],
        'client_id': auth_code['client_id'],
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

login_router = create_router([
    (r'^/login_v1/oauth/authorization$', authorization),
    (r'^/login_v1/oauth/authorize$', do_authorize),
    (r'^/login_v1/oauth/token$', token)
])

def cli_login(event: HttpEvent) -> Response:
    return login_router(event)
