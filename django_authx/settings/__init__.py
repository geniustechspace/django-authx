from datetime import timedelta
from typing import Optional

from django.core.signals import setting_changed

from .base import BaseSettings


IMPORT_STRINGS = {}


class AuthXSettings(BaseSettings):
    """
    Class for managing AuthX settings with defaults and dynamic reloading.
    Prevents runtime mutation of settings.
    """

    SECURE_HASH_ALGORITHM: str = "hashlib.sha512"

    AUTH_HEADER_PREFIX: str = "Token"
    DATETIME_FORMAT: str = "iso-8601"
    DEFAULT_TOKEN_TTL: timedelta = timedelta(days=1)
    TOKEN_CHARACTER_LENGTH: int = 64
    TOKEN_CACHE_TIMEOUT: timedelta = timedelta(seconds=60)
    REFRESH_TOKEN_ON_LOGIN: bool = False

    PRIMARY_EMAIL_FIELD: Optional[str] = "email"
    PRIMARY_PHONE_FIELD: Optional[str] = "phone"


# Singleton instance of AuthXSettings
authx_settings = AuthXSettings(settings_key="AUTHX_", import_strings=IMPORT_STRINGS)


def reload_settings(*args, **kwargs):
    """
    Reload the AuthX settings when Django's `setting_changed` signal is triggered.
    """
    # if kwargs["setting"] == "AUTHX_SETTINGS":
    authx_settings.reload()


# Connect to Django's `setting_changed` signal
setting_changed.connect(reload_settings)


__all__ = ["BaseSettings", "authx_settings", "reload_settings"]
