from abc import ABC, abstractmethod

from auth.domain import models


class Authenticator(ABC):
    @abstractmethod
    def verify_token(
        self,
        token: str,
    ) -> bool:
        """Verify a token.

        Args:
            token: The token to verify

        Returns:
            True if valid, False otherwise
        """

        pass

    @abstractmethod
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

        pass
