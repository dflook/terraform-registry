from typing import TypedDict, Literal


class OAuthError:
    error: Literal['invalid_request', 'invalid_client', 'invalid_grant', 'unauthorized_client', 'unsupported_grant_type', 'invalid_scope']
    error_description: str
    error_uri: str
