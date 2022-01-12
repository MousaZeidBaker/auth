from datetime import datetime, timedelta
from typing import Dict

import pytest
from jose import jwk, jwt

from auth.adapters import cognito


def test_valid_token_should_pass_verification(
    test_cognito_authenticator: cognito.CognitoAuthenticator,
    claims_fixture: Dict,
    headers_fixture: Dict,
    key: jwk.RSAKey,
):
    token = jwt.encode(
        claims=claims_fixture,
        key=key.to_pem(),
        algorithm=key._algorithm,
        headers=headers_fixture,
    )
    assert test_cognito_authenticator.verify_token(token) is True


def test_invalid_jwt_should_not_pass_verification(
    test_cognito_authenticator: cognito.CognitoAuthenticator,
):
    token = "invalid_jwt"
    assert test_cognito_authenticator.verify_token(token) is False
    pytest.raises(
        cognito.InvalidJWTError,
        test_cognito_authenticator._is_jwt,
        token,
    )


def test_invalid_kid_should_not_pass_verification(
    test_cognito_authenticator: cognito.CognitoAuthenticator,
    claims_fixture: Dict,
    headers_fixture: Dict,
    key: jwk.RSAKey,
):
    headers_fixture["kid"] = "invalid_kid"
    token = jwt.encode(
        claims=claims_fixture,
        key=key.to_pem(),
        algorithm=key._algorithm,
        headers=headers_fixture,
    )
    assert test_cognito_authenticator.verify_token(token) is False
    pytest.raises(
        cognito.InvalidKidError,
        test_cognito_authenticator._get_verified_header,
        token,
    )


def test_invalid_signature_should_not_pass_verification(
    test_cognito_authenticator: cognito.CognitoAuthenticator,
    claims_fixture: Dict,
    headers_fixture: Dict,
    invalid_key: jwk.RSAKey,
):
    token = jwt.encode(
        claims=claims_fixture,
        key=invalid_key.to_pem(),
        algorithm=invalid_key._algorithm,
        headers=headers_fixture,
    )
    assert test_cognito_authenticator.verify_token(token) is False
    pytest.raises(
        cognito.SignatureError,
        test_cognito_authenticator._get_verified_header,
        token,
    )


def test_expired_token_should_not_pass_verification(
    test_cognito_authenticator: cognito.CognitoAuthenticator,
    claims_fixture: Dict,
    headers_fixture: Dict,
    key: jwk.RSAKey,
):
    claims_fixture["exp"] = datetime.utcnow() + timedelta(minutes=-15)
    token = jwt.encode(
        claims=claims_fixture,
        key=key.to_pem(),
        algorithm=key._algorithm,
        headers=headers_fixture,
    )
    assert test_cognito_authenticator.verify_token(token) is False
    pytest.raises(
        cognito.TokenExpiredError,
        test_cognito_authenticator._get_verified_claims,
        token,
    )


def test_invalid_issuer_should_not_pass_verification(
    test_cognito_authenticator: cognito.CognitoAuthenticator,
    claims_fixture: Dict,
    headers_fixture: Dict,
    key: jwk.RSAKey,
):
    claims_fixture["iss"] = "invalid_issuer"
    token = jwt.encode(
        claims=claims_fixture,
        key=key.to_pem(),
        algorithm=key._algorithm,
        headers=headers_fixture,
    )
    assert test_cognito_authenticator.verify_token(token) is False
    pytest.raises(
        cognito.InvalidIssuerError,
        test_cognito_authenticator._get_verified_claims,
        token,
    )


def test_invalid_audience_should_not_pass_verification(
    test_cognito_authenticator: cognito.CognitoAuthenticator,
    claims_fixture: Dict,
    headers_fixture: Dict,
    key: jwk.RSAKey,
):
    claims_fixture["client_id"] = "invalid_client_id"
    token = jwt.encode(
        claims=claims_fixture,
        key=key.to_pem(),
        algorithm=key._algorithm,
        headers=headers_fixture,
    )
    assert test_cognito_authenticator.verify_token(token) is False
    pytest.raises(
        cognito.InvalidAudienceError,
        test_cognito_authenticator._get_verified_claims,
        token,
    )


def test_invalid_token_use_should_not_pass_verification(
    test_cognito_authenticator: cognito.CognitoAuthenticator,
    claims_fixture: Dict,
    headers_fixture: Dict,
    key: jwk.RSAKey,
):
    claims_fixture["token_use"] = "invalid_token_use"
    token = jwt.encode(
        claims=claims_fixture,
        key=key.to_pem(),
        algorithm=key._algorithm,
        headers=headers_fixture,
    )
    assert test_cognito_authenticator.verify_token(token) is False
    pytest.raises(
        cognito.InvalidTokenUseError,
        test_cognito_authenticator._get_verified_claims,
        token,
    )
