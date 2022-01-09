import json
from datetime import datetime, timedelta
from typing import Dict
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwk

from auth.adapters.cognito import CognitoAuthenticator

AWS_COGNITO_REGION = "eu-central-1"
AWS_USER_POOL_ID = "eu-central-1_123abc"
AWS_USER_POOL_CLIENT_ID = "456def"


@pytest.fixture(scope="function")
def test_cognito_authenticator(mocker, jwks_fixture) -> CognitoAuthenticator:
    """Returns Cognito test authenticator"""

    # mock urllib request
    mock = MagicMock()
    mock.read.return_value = json.dumps(jwks_fixture).encode("utf-8")
    mocker.patch(
        "urllib.request.urlopen",
        return_value=mock,
    )

    return CognitoAuthenticator(
        pool_region=AWS_COGNITO_REGION,
        pool_id=AWS_USER_POOL_ID,
        client_id=AWS_USER_POOL_CLIENT_ID,
    )


@pytest.fixture(scope="function")
def jwks_fixture(key, headers_fixture) -> Dict:
    """Returns a JSON Web Key Set (JWKS)"""

    key_dict = key.to_dict()
    return {
        "keys": [
            {
                # the JWK used in the tests
                "alg": key_dict["alg"],
                "e": key_dict["e"],
                "kid": headers_fixture["kid"],
                "kty": key_dict["kty"],
                "n": key_dict["n"],
                "use": "sig",
            },
            {
                # additional dummy JWK
                "alg": "RS256",
                "e": "AQAB",
                "kid": "abcdefghijklmnopqrsexample=",
                "kty": "RSA",
                "n": "lsjhglskjhgslkjgh43lj5h34lkjh34lkjht3example",
                "use": "sig",
            },
        ]
    }


@pytest.fixture(scope="function")
def claims_fixture() -> Dict:
    """Returns a claim set for a JSON Web Token (JWT)"""

    return {
        "sub": "216f6e34-049a-4339-b025-a8b827dfbc39",
        "token_use": "access",
        "iss": f"https://cognito-idp.{AWS_COGNITO_REGION}.amazonaws.com/{AWS_USER_POOL_ID}",
        "exp": datetime.utcnow() + timedelta(minutes=15),
        "client_id": AWS_USER_POOL_CLIENT_ID,
    }


@pytest.fixture(scope="function")
def headers_fixture() -> Dict:
    """Returns headers for a JSON Web Token (JWT)"""

    return {
        "kid": "5438ade6-064f-4851-9da8-df37a69d1b84",
        "alg": "RS256",
    }


@pytest.fixture(scope="function")
def key() -> jwk.RSAKey:
    """Returns a key object"""

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return jwk.RSAKey(
        key=pem,
        algorithm=jwk.ALGORITHMS.RS256,
    )


@pytest.fixture(scope="function")
def invalid_key() -> jwk.RSAKey:
    """Returns a key object"""

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return jwk.RSAKey(
        key=pem,
        algorithm=jwk.ALGORITHMS.RS256,
    )
