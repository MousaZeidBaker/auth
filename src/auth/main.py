import logging
import os

from dotenv import load_dotenv

from auth.adapters.cognito import CognitoAuthenticator
from auth.domain import models
from auth.ports import ports

config = load_dotenv()
logging.basicConfig(level=os.environ.get("LOGLEVEL", "WARNING").upper())

auth: ports.Authenticator = CognitoAuthenticator(
    pool_region=os.environ["AWS_COGNITO_REGION"],
    pool_id=os.environ["AWS_USER_POOL_ID"],
    client_id=os.environ["AWS_USER_POOL_CLIENT_ID"],
)


if __name__ == "__main__":
    token: models.Token = auth.authenticate(
        username=os.environ["TEST_USERNAME"],
        password=os.environ["TEST_PASSWORD"],
    )
    logging.info(f"{token.dict()}\n")
    logging.info(f"Token verified: {auth.verify_token(token.access_token)}\n")

    user: models.User = auth.get_current_user(token.access_token)
    logging.info(f"User: {user.dict()}\n")
