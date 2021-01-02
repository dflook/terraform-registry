from datetime import datetime
import hashlib
import mimetypes
from typing import Tuple, Optional

from functools import lru_cache
from aws.api_gateway_types import HttpEvent
from aws.response import Response

import os.path

@lru_cache()
def get_asset_response(path: str) -> Response:

    if path not in ['hello.txt']:
        raise Response(status=404)

    if not os.path.isfile(path):
        raise Response(status=404)

    with open(path) as f:
        body = f.read()

    stat = os.stat(path)
    hash = f'"{hashlib.blake2b(body.encode()).hexdigest()}"'
    content_type, _ = mimetypes.guess_type(path)

    headers = {
        'cache-control': 'no-cache',
        'last-modified': datetime.utcfromtimestamp(int(stat.st_mtime)).strftime('%a, %d %b %Y %H:%M:%S GMT'),
        'etag': f'"{hash}"'
    }

    return Response(body, status=200, headers=headers, content_type=content_type)

def static_asset(event: HttpEvent, path: str) -> Response:
    response = get_asset_response(path)

    if event['headers'].get('if-none-match') == response.headers['etag']:
        response.response = None
        response.status = 304
        return response

    return response
