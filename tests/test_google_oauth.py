from datetime import (
    datetime,
    timezone,
)

import json

import os.path

import unittest

from unittest.mock import (
    Mock,
    patch,
)

import jwt

from google_custom_oauth2.google_oauth import GoogleOAuth


CUR_DIR = os.path.dirname(__file__)


class TestGoogleOAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = f'{CUR_DIR}/fixtures'
        cls.oauth = GoogleOAuth(
            client_id='some_client_id',
            client_secret='some_client_secret',
            redirect_uri='some_redirect_uri',
            scope=['email'],
        )

    @patch('requests.get')
    def test_make_request(self, mock_requests_get):
        path = f'{self.path}/make_request'

        fixtures = (
            (200, 'valid'),
            (500, 'invalid'),
        )

        for code, name in fixtures:
            fixture = f'{code}_{name}'

            with open(f'{path}/{fixture}.json', 'r') as file:
                data = json.load(file)

            if code == 500:
                mock_requests_get.side_effect = Exception('Test')
            else:
                mock_value = Mock(
                    status_code=code,
                    json=lambda: data['mock_json'],
                )
                mock_requests_get.return_value = mock_value

            status, response = self.oauth._make_request(
                method=data['method'],
                url=data['url'],
                headers=data['headers'],
                data=data['data'],
            )
            self.assertEqual(status, code, msg=fixture)

    @patch('google_custom_oauth2.google_oauth.GoogleOAuth._make_request')
    def test_exchange_code_for_tokens(self, mock_make_request):
        path = f'{self.path}/exchange_code_for_tokens'

        fixtures = (
            (200, 'valid'),
            (400, 'invalid'),
        )

        for code, name in fixtures:
            fixture = f'{code}_{name}'

            with open(f'{path}/{fixture}.json', 'r') as file:
                data = json.load(file)

            mock_make_request.return_value = (code, {})

            status, response = self.oauth.exchange_code_for_tokens(
                code=data['code'],
            )
            self.assertEqual(status, code, msg=fixture)

    @patch('google_custom_oauth2.google_oauth.GoogleOAuth._make_request')
    def test_get_user_info(self, mock_make_request):
        path = f'{self.path}/get_user_info'

        fixtures = (
            (200, 'valid'),
            (400, 'invalid'),
        )

        for code, name in fixtures:
            fixture = f'{code}_{name}'

            with open(f'{path}/{fixture}.json', 'r') as file:
                data = json.load(file)

            mock_make_request.return_value = (code, {})

            status, response = self.oauth.get_user_info(
                access_token=data['access_token'],
            )
            self.assertEqual(status, code, msg=fixture)

    @patch('datetime.datetime')
    @patch('google_custom_oauth2.google_oauth.jwt.algorithms.RSAAlgorithm.from_jwk')
    @patch('google_custom_oauth2.google_oauth.GoogleOAuth._make_request')
    def test_verify_id_token(self,
                             mock_make_request,
                             mock_from_jwk,
                             mock_datetime,
                             ):
        path = f'{self.path}/verify_id_token'

        with open(f'{path}/google_certs.json', 'r') as file:
            data = json.load(file)

        mock_make_request.return_value = (200, data)

        with open(f'{path}/private_key.pem', 'r') as file:
            private_key = file.read()

        with open(f'{path}/public_key.pem', 'r') as file:
            public_key = file.read()

        mock_from_jwk.return_value = public_key
        mock_datetime.now.return_value = datetime(2024, 10, 20, 10, 0, tzinfo=timezone.utc)
        print(datetime.now())
        fixtures = (
            (200, 'valid'),
            (400, 'invalid_unverified_header_kid'),
        )

        for code, name in fixtures:
            fixture = f'{code}_{name}'

            with open(f'{path}/{fixture}.json', 'r') as file:
                data = json.load(file)

            headers = data['headers']
            payload = data['payload']
            exp = payload['exp']
            iat = payload['iat']
            payload['exp'] = datetime.strptime(exp, '%Y-%m-%d %H:%M')
            payload['iat'] = datetime.strptime(iat, '%Y-%m-%d %H:%M')
            print(payload)
            id_token = jwt.encode(
                payload=payload,
                headers=headers,
                algorithm='RS256',
                key=private_key,
            )

            status, response = self.oauth.verify_id_token(
                id_token=id_token,
            )
            self.assertEqual(status, code, msg=fixture)
