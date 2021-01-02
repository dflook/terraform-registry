def login(event: HttpEvent, session: Session) -> Response:
    pass

def login_with_github(event: HttpEvent) -> Response:
    github_url = 'https://github.com/login/oauth/authorize?'
    github_url += urlencode({
        'state': uuid.uuid4(),
        'client_id': os.environ['GITHUB_CLIENT_ID'],
        'redirect_uri': 'https://terraform-dev.flook.org/login/github/authorize'
    })
    return Response(status_code=302, headers={'location': github_url})

def access_token(event: HttpEvent) -> Response:

    token_response = requests.post(
        'https://github.com/login/oauth/access_token',
        data={
            'client_id': os.environ['GITHUB_CLIENT_ID'],
            'client_secret': os.environ['GITHUB_CLIENT_SECRET'],
            'code': event['queryStringParameters']['code'],
            'state': event['queryStringParameters']['state'],
            'redirect_uri': 'https://terraform-dev.flook.org/login/github/authorize'
        },
        headers={
            'accept': 'application/json'
        }
    )

    token_response.raise_for_status()
    github_token = token_response.json()['access_token']

    github_user_response = requests.get(
        'https://api.github.com/user',
        headers={
            'accept': 'application/vnd.github.v3+json',
            'Authorization': f'token {github_token}'
        }
    )
    github_user_response.raise_for_status()

    session_id = uuid.uuid4()
    csrf = uuid.uuid4()
    session_table.put_item(Item={
        'session_id': session_id,
        'github_access_token': github_token,
        'github_user': github_user_response.json(),
        'csrf': csrf
    })

    cookies = [
        f'__Host-session-strict={session_id}; Path=/; Secure; HttpOnly; SameSite=Strict',
        f'__Host-session-lax={session_id}; Path=/; Secure; HttpOnly; SameSite=Lax',
    ]

    return Response(status_code=302, headers={
        'set-cookie': ','.join(cookies),
        'location': '/'
    })
