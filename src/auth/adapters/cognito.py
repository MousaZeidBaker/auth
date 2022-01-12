import json
import logging
import time
import urllib.error
import urllib.request
from typing import Dict, List

import boto3
from jose import jwk, jwt
from jose.utils import base64url_decode
from pydantic import BaseModel
from warrant.aws_srp import AWSSRP

from auth.domain import models
from auth.ports import ports


class JWK(BaseModel):
    """A JSON Web Key (JWK) model that represents a cryptographic key.

    The JWK specification:
    https://datatracker.ietf.org/doc/html/rfc7517
    """

    alg: str
    e: str
    kid: str
    kty: str
    n: str
    use: str


class CognitoAuthenticator(ports.Authenticator):
    def __init__(self, pool_region: str, pool_id: str, client_id: str) -> None:
        self.pool_region = pool_region
        self.pool_id = pool_id
        self.client_id = client_id
        self.issuer = f"https://cognito-idp.{self.pool_region}.amazonaws.com/{self.pool_id}"  # noqa: E501
        self.jwks = self.__get_jwks()

    def __get_jwks(self) -> List[JWK]:
        """Returns a list of JSON Web Keys (JWKs) from the issuer. A JWK is a
        public key used to verify a JSON Web Token (JWT).

        Returns:
            List of keys

        Raises:
            Exception when JWKS endpoint does not contain any keys
        """

        file = urllib.request.urlopen(f"{self.issuer}/.well-known/jwks.json")
        res = json.loads(file.read().decode("utf-8"))
        if not res.get("keys"):
            raise Exception("The JWKS endpoint does not contain any keys")
        jwks = [JWK(**key) for key in res["keys"]]
        return jwks

    def verify_token(
        self,
        token: str,
    ) -> bool:
        """Verify a JSON Web Token (JWT).

        For more details refer to:
        https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html

        Args:
            token: The token to verify

        Returns:
            True if valid, False otherwise
        """

        try:
            self._is_jwt(token)
            self._get_verified_header(token)
            self._get_verified_claims(token)
        except CognitoError:
            return False
        return True

    def _is_jwt(self, token: str) -> bool:
        """Validate a JSON Web Token (JWT).

        A JSON Web Token (JWT) includes three sections: Header, Payload and
        Signature. They are base64url encoded and are separated by dot (.)
        characters. If JWT token does not conform to this structure, it is
        considered invalid.

        Args:
            token: The token to validate

        Returns:
            True if valid

        Raises:
            CognitoError when invalid token
        """

        try:
            jwt.get_unverified_header(token)
            jwt.get_unverified_claims(token)
        except jwt.JWTError:
            logging.info("Invalid JWT")
            raise InvalidJWTError
        return True

    def _get_verified_header(self, token: str) -> Dict:
        """Verifies the signature of a a JSON Web Token (JWT) and returns its
        decoded header.

        Args:
            token: The token to decode header from

        Returns:
            A dict representation of the token header

        Raises:
            CognitoError when unable to verify signature
        """

        # extract key ID (kid) from token
        headers = jwt.get_unverified_header(token)
        kid = headers["kid"]

        # find JSON Web Key (JWK) that matches kid from token
        key = None
        for k in self.jwks:
            if k.kid == kid:
                # construct a key object from found key data
                key = jwk.construct(k.dict())
                break
        if not key:
            logging.info(f"Unable to find a signing key that matches '{kid}'")
            raise InvalidKidError

        # get message and signature (base64 encoded)
        message, encoded_signature = str(token).rsplit(".", 1)
        signature = base64url_decode(encoded_signature.encode("utf-8"))

        if not key.verify(message.encode("utf8"), signature):
            logging.info("Signature verification failed")
            raise SignatureError

        # signature successfully verified
        return headers

    def _get_verified_claims(self, token: str) -> Dict:
        """Verifies the claims of a JSON Web Token (JWT) and returns its claims.

        Args:
            token: The token to decode claims from

        Returns:
            A dict representation of the token claims

        Raises:
            CognitoError when unable to verify claims
        """

        claims = jwt.get_unverified_claims(token)

        # verify expiration time
        if claims["exp"] < time.time():
            logging.info("Expired token")
            raise TokenExpiredError

        # verify issuer
        if claims["iss"] != self.issuer:
            logging.info("Invalid issuer claim")
            raise InvalidIssuerError

        # verify audience
        # note: claims["client_id"] for access token, claims["aud"] otherwise
        if claims["client_id"] != self.client_id:
            logging.info("Invalid audience claim")
            raise InvalidAudienceError

        # verify token use
        if claims["token_use"] != "access":
            logging.info("Invalid token use claim")
            raise InvalidTokenUseError

        # claims successfully verified
        return claims

    def get_current_user(
        self,
        token: str,
    ) -> models.Token:
        """Return current authenticated user.

        Args:
            token: The token of the user

        Returns:
            The user data

        Raises:
            Exception when unauthorized
        """

        if not self.verify_token(token):
            raise Exception("Unauthorized")

        # prepare cognito request
        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.GetUser",
        }
        data = json.dumps({"AccessToken": token}).encode("utf-8")
        req = urllib.request.Request(
            method="POST",
            url=f"{self.issuer}",
            headers=headers,
            data=data,
        )

        try:
            logging.info("Cognito get current user")
            res = json.loads(urllib.request.urlopen(req).read().decode("utf-8"))
            logging.info("Cognito successfully got user")
        except urllib.error.HTTPError:
            raise Exception("Unauthorized")

        attributes = {attr["Name"]: attr for attr in res["UserAttributes"]}

        return models.User(
            username=res["Username"],
            email=attributes["email"]["Value"],
            first_name=attributes["given_name"]["Value"],
            last_name=attributes["family_name"]["Value"],
        )

    def authenticate(
        self,
        username: str,
        password: str,
    ) -> models.Token:
        """Authenticate a user.

        Args:
            username: The username of the user to authenticate
            password: The password of the user to authenticate

        Returns: A token for the user
        """

        # prepare cognito request
        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
        }
        data = json.dumps(
            {
                "AuthParameters": {
                    "USERNAME": username,
                    "PASSWORD": password,
                },
                "AuthFlow": "USER_PASSWORD_AUTH",
                "ClientId": self.client_id,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            method="POST",
            url=f"{self.issuer}",
            headers=headers,
            data=data,
        )

        try:
            logging.info(f"Cognito login user '{username}'")
            res = json.loads(urllib.request.urlopen(req).read().decode("utf-8"))
            logging.info("Cognito successfully logged in user")
        except urllib.error.HTTPError:
            raise Exception("Unauthorized")

        return models.Token(
            access_token=res["AuthenticationResult"]["AccessToken"],
            token_type=res["AuthenticationResult"]["TokenType"],
            expires_in=res["AuthenticationResult"]["ExpiresIn"],
            refresh_token=res["AuthenticationResult"]["RefreshToken"],
            id_token=res["AuthenticationResult"]["IdToken"],
        )

    def authenticate_srp(
        self,
        username: str,
        password: str,
    ) -> models.Token:
        """Authenticate a user using Secure Remote Password (SRP) Authentication.

        Args: username: The username of the user to authenticate
        password: The password of the user to authenticate

        Returns: A token for the user
        """

        client = boto3.client("cognito-idp", region_name=self.pool_region)
        aws = AWSSRP(
            username=username,
            password=password,
            pool_id=self.pool_id,
            client_id=self.client_id,
            client=client,
        )

        try:
            logging.info(f"Cognito login user '{username}'")
            res = aws.authenticate_user()
            logging.info("Cognito successfully logged in user")
        # For a list of possible errors refer to:
        # https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html?shortFooter=true#API_InitiateAuth_Errors
        except (
            client.exceptions.UserNotFoundException,
            client.exceptions.NotAuthorizedException,
        ):
            raise Exception("Unauthorized")

        return models.Token(
            access_token=res["AuthenticationResult"]["AccessToken"],
            token_type=res["AuthenticationResult"]["TokenType"],
            expires_in=res["AuthenticationResult"]["ExpiresIn"],
            refresh_token=res["AuthenticationResult"]["RefreshToken"],
            id_token=res["AuthenticationResult"]["IdToken"],
        )


class CognitoError(Exception):
    pass


class InvalidJWTError(CognitoError):
    pass


class InvalidKidError(CognitoError):
    pass


class SignatureError(CognitoError):
    pass


class TokenExpiredError(CognitoError):
    pass


class InvalidIssuerError(CognitoError):
    pass


class InvalidAudienceError(CognitoError):
    pass


class InvalidTokenUseError(CognitoError):
    pass
