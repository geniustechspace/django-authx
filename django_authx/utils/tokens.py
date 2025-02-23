import binascii
import logging
from os import urandom
from typing import Union
from jwt import decode, InvalidTokenError

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from django_authx.settings import authx_settings

logger = logging.getLogger(__name__)


def generate_token(size=None) -> str:
    return binascii.hexlify(
        urandom(int(size or authx_settings.TOKEN_CHARACTER_LENGTH / 2))
    ).decode()


def generate_jwt(token: Union[str, dict], secret: str) -> bool:
    """Validate JWT token."""
    try:
        if isinstance(token, str):
            payload = decode(token, secret, algorithms=["HS256"])
        else:
            payload = token

        # Verify token claims
        if not all(k in payload for k in ["exp", "iat", "sub"]):
            raise ValidationError(_("Missing required claims"))

        return True

    except InvalidTokenError as e:
        logger.error(f"JWT validation error: {str(e)}")
        return False


def validate_jwt(token: Union[str, dict], secret: str) -> bool:
    """Validate JWT token."""
    try:
        if isinstance(token, str):
            payload = decode(token, secret, algorithms=["HS256"])
        else:
            payload = token

        # Verify token claims
        if not all(k in payload for k in ["exp", "iat", "sub"]):
            raise ValidationError(_("Missing required claims"))

        return True

    except InvalidTokenError as e:
        logger.error(f"JWT validation error: {str(e)}")
        return False
