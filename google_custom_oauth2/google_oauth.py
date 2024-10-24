import urllib.parse
import requests
import logging
import jwt

from jwt.algorithms import RSAAlgorithm


logger = logging.getLogger(__name__)


class GoogleOAuth:

    token_url = 'https://oauth2.googleapis.com/token'
    auth_url = 'https://accounts.google.com/o/oauth2/v2/auth'
    user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo'
    certs_url = 'https://www.googleapis.com/oauth2/v3/certs'
    issuers = [
        'accounts.google.com',
        'https://accounts.google.com',
    ]

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
        status, response = self._make_request(
            method='get',
            url=self.certs_url,
        )
        if status != 200:
            logger.error(
                msg=f'Failed to get Google public keys',
            )
            return status, response

        try:
            unverified_header = jwt.get_unverified_header(id_token)
        except Exception as exc:
            logger.error(
                msg=f'An error occurred while verifying the ID token: {exc}',
            )
            return 400, {}

        public_keys = response
        kid = unverified_header['kid']
        public_key = None
        for key in public_keys['keys']:
            if key['kid'] == kid:
                public_key = RSAAlgorithm.from_jwk(key)
                break

        if public_key is None:
            logger.error(
                msg=f'The public key for token sign was not found',
            )
            return 400, {}

        try:
            token_info = jwt.decode(
                jwt=id_token,
                key=public_key,
                algorithms=['RS256'],
                audience=self.client_id,
                issuer=self.issuers,
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
