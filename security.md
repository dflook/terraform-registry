All requests are made in the context of a session. A session is created for a request if it doesn't exist.
If a session is not found, a new session is created

Brand new Sessions are created unauthenticated. Once a user is authenticated, a new authenticated session is created and the old one destroyed.

Requests may require an authenticated session, and will return an error if not.

Both lax and strict cookies are refreshed with the session identifier in every response.

Requests that require authentication and use a safe request method only require a lax session cookie, and will return an error if not.
Requests that require authentication and use an unsafe request method require a strict cookie, and return an error if not.
When both lax and strict cookies are present both must match, or a new session is created.

Unsafe requests require a CSRF token in a request header.

If an Origin header is present, it must match the Host header.
If a referer header is present, it must match the host header.

Unauthenticated requests


# Cookies

These session cookies contain a random session id that identifies the current session on the server. They have the same value.
- __Host-session-strict
- __Host-session-lax

strict is only sent with same-site requests and is required for unsafe methods.
lax is sent with all requests and is ok for safe (i.e. GET) methods

# Timeouts


## Absolute session ttl
Each session_id is created with an absolute ttl.
- Unauthenticated sessions have absolute ttl of 1 hour
- Unauthenticated sessions have absolute ttl of 8 days

Javascript on each page should refresh if the ttl is exceeded.

## Idle timeout
Each session_id has an
