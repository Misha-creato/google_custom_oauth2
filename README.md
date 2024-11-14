# Google Custom OAuth2 Library

A library for integrating Google OAuth 2.0 authentication into Django projects. This library enables users to authenticate via their Google accounts, simplifying the login process and enhancing security.

## Features

- Easy integration of Google OAuth 2.0 for Django projects.
- Simple setup with configuration options.
- Retrieves basic user information from Google after successful authentication.

## Requirements

- Python 3.6+
- Django 3.2+
- `requests` library
- `PyJWT` library
- `cryptography` library

## Installation

1. Install the package:

   `pip install git+https://github.com/Misha-creato/google_custom_oauth2.git`

2. Add Google API credentials to your Django settings:
```py

 GOOGLE_OAUTH_CLIENT_ID = "your-google-client-id"   
 GOOGLE_OAUTH_CLIENT_SECRET = "your-google-client-secret"  
 GOOGLE_OAUTH_REDIRECT_URI = "https://yourdomain.com/oauth/callback"

```
3. Set up URL routes:
```py
from django.urls import path

urlpatterns = [
    # Other URL patterns
    path('oauth/login/google/', your_google_login_view, name='google_oauth_login'),
    path('oauth/callback/', your_google_callback_view, name='google_oauth_callback'),
]
```

## Usage

1. Import GoogleOAuth:
```py

from google_custom_oauth2.google_oauth import GoogleOAuth
from config.settings import (
    GOOGLE_OAUTH_CLIENT_ID,
    GOOGLE_OAUTH_CLIENT_SECRET,
    GOOGLE_OAUTH_REDIRECT_URI,
)

oauth = GoogleOAuth(
    client_id=GOOGLE_OAUTH_CLIENT_ID,
    client_secret=GOOGLE_OAUTH_CLIENT_SECRET,
    redirect_uri=GOOGLE_OAUTH_REDIRECT_URI,
    scope=['openid', 'email'],
)
```
2. Get Google Auth link with provided state:
```py

auth_url = oauth.get_auth_url(
      state=state,
)

```
3. Exchange authorization code for tokens(access_token or id_token):
```py
status, response = oauth.exchange_code_for_tokens(
    code=code,
)

access_token = response['access_token']
id_token = response['id_token']
```
4. Verify id token and get user info(must be in scope):
```py
status, response = oauth.verify_id_token(
    id_token=id_token,
)

email = response['email']
```
5. Or you can get user info by access token:
```py
status, response = oauth.get_user_info(
    access_token=access_token,
)

email = response['email']
```

## Example Workflow

1. The user clicks “Login with Google.”
2. They are redirected to the Google OAuth consent page to approve access.
3. After they consent, Google redirects them back to your callback endpoint.
4. The callback view verifies the response, retrieves the user’s information, and logs them in.

## Configuration
You can configure different aspects of the Google OAuth process in your Django settings.py:

- `GOOGLE_OAUTH_CLIENT_ID`: Your Google API client ID.
- `GOOGLE_OAUTH_CLIENT_SECRET`: Your Google API client secret.
- `GOOGLE_OAUTH_REDIRECT_URI`: URL where Google redirects users after they authenticate.
