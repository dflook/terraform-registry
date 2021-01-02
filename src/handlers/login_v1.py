import os
import logging
import time

import boto3
from urllib.parse import urlencode, parse_qsl
import base64
import uuid
from api_gateway import Response, Error, route_request, HttpResponse, HttpEvent, LambdaContext
from oauth import OAuthError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

users_table = boto3.resource('dynamodb').Table(os.environ['Users'])
api_tokens_table = boto3.resource('dynamodb').Table(os.environ['ApiTokens'])
auth_code_table = boto3.resource('dynamodb').Table(os.environ['AuthCodes'])

AUTH_CODE_TTL = 30
AUTH_TOKEN_TTL = 600

def authorization(event: HttpEvent) -> Response:

    auth_failed = Response(status_code=401, headers={'www-authenticate': 'Basic realm="Terraform Registry", charset="UTF-8"'})

    if event['queryStringParameters'].get('client_id') != 'terraform-cli':
        return Response({'error': 'invalid_client'}, status_code=400)
    if event['queryStringParameters'].get('response_type') != 'code':
        return Response(status_code=400)

    if 'authorization' not in event['headers']:
        return auth_failed

    header = event['headers']['authorization']
    if not header.startswith('Basic '):
        return auth_failed

    email, password = base64.b64decode(event['headers']['authorization'][len('Basic '):]).decode().split(':', maxsplit=1)

    response = users_table.get_item(Key={'email': email})

    if 'Item' not in response:
        return auth_failed

    if response['Item'].get('password') != password:
        return auth_failed

    # User is now authenticated

    code = str(uuid.uuid4())

    auth_code_table.put_item(Item={
        'code': code,
        'email': email,
        'redirect_uri': event['queryStringParameters']['redirect_uri'],
        'code_challenge': event['queryStringParameters'].get('code_challenge', ''),
        'code_challenge_method': event['queryStringParameters'].get('code_challenge_method', ''),
        'exp': int(time.time()) + AUTH_CODE_TTL,
        'client_id': event['queryStringParameters']['client_id'],
    })

    redirect = event['queryStringParameters']['redirect_uri'] + '?'
    redirect += urlencode({
        'state': event['queryStringParameters']['state'],
        'code': code
    })

    return Response(
        status_code=303,
        headers={
            'location': redirect
        }
    )

def token(event: HttpEvent) -> Response:

    body = base64.b64decode(event['body']) if event['isBase64Encoded'] else event['body']
    logger.info('Body is %r', body)

    request = { k.decode(): v.decode() for k, v in parse_qsl(body) }
    logger.info('token_request is %r', request)

    response = auth_code_table.get_item(Key={'code': request['code']})

    if 'Item' not in response:
        return Response(status_code=400)

    auth_code = response['Item']

    if (auth_code['redirect_uri'] != request['redirect_uri'] or
        auth_code['exp'] < int(time.time())):

        return Response(status_code=400)

    # Code is valid

    token = str(uuid.uuid4())

    api_tokens_table.put_item(Item={
        'token': token,
        'email': auth_code['email'],
        'client_id': auth_code['client_id'],
        'exp': int(time.time()) + AUTH_TOKEN_TTL
    })

    return Response({
        'access_token': token,
        'token_type': '',
        'expires_in': AUTH_TOKEN_TTL,
    },
    headers={
        'cache-control': 'no-store'
    })


def cli_login(event: HttpEvent) -> Response:
    return route_request(event, [
        (r'^/oauth/authorization$', authorization),
        (r'^/oauth/token$', token)
    ])
