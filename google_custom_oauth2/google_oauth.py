import urllib.parse

import requests

from google.oauth2.id_token import verify_oauth2_token
from google.auth.transport.requests import Request

import logging


logger = logging.getLogger(__name__)


class GoogleOAuth:

    token_url = 'https://oauth2.googleapis.com/token'
    auth_url = 'https://accounts.google.com/o/oauth2/v2/auth'
    user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo'

    def __init__(self,
                 client_id: str,
                 client_secret: str,
                 redirect_uri: str,
                 scope: list[str],
                 ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scope = scope

    def _make_request(self,
                       method: str,
                       url: str,
                       headers: dict | None = None,
                       data: dict | None = None
                       ) -> (int, dict):
        logger.debug(
            msg=f'Sending a {method} request to {url} with {data} data',
        )

        if data is None:
            data = {}
        if headers is None:
            headers = {}
        try:
            response = getattr(requests, method)(
                url=url,
                headers=headers,
                data=data,
            )
        except Exception as exc:
            logger.error(
                msg=f'An error occurred while sending {method} request to '
                    f'{url} with {data}: {exc}',
            )
            return 500, {}

        status = response.status_code
        if status == 200:
            response_data = response.json()
        else:
            response_data = response.content

        logger.debug(
            msg=f'Sent {method} request to address {url} with data {data}',
        )
        return status, response_data

    def get_auth_url(self, state: str) -> str:
        logger.debug(
            msg='Receiving a link for authorization via Google',
        )

        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': ' '.join(self.scope),
            'state': state,
            'response_type': 'code',
            'access_type': 'offline',
            'include_granted_scopes': 'true',
        }

        encoded_params = urllib.parse.urlencode(query=params)
        auth_url = f'{self.auth_url}?{encoded_params}'

        logger.debug(
            msg='Received a link for authorization via Google',
        )
        return auth_url

    def exchange_code_for_tokens(self, code: str) -> (int, dict):
        logger.debug(
            msg=f'Exchange authorization code {code} for access token',
        )

        data = {
            'code': code,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'redirect_uri': self.redirect_uri,
            'grant_type': 'authorization_code',
        }
        status, response_data = self._make_request(
            method='post',
            url=self.token_url,
            data=data,
        )
        return status, response_data

    def get_user_info(self, access_token: str) -> (int, dict):
        logger.debug(
            msg='Retrieving user data from Google',
        )

        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        status, response_data = self._make_request(
            method='get',
            url=self.user_info_url,
            headers=headers,
        )
        return status, response_data

    def verify_id_token(self, id_token: str) -> (int, dict):
        logger.debug(
            msg='ID token verification',
        )
        try:
            token_info = verify_oauth2_token(
                id_token=id_token,
                request=Request(),
            )
        except Exception as exc:
            logger.error(
                msg=f'An error occurred while verifying the ID token: {exc}',
            )
            return 400, {}

        logger.debug(
            msg='ID token verified',
        )
        return 200, token_info
