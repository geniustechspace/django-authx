from django.db import models
from django.utils.translation import gettext_lazy as _

from . import modelfields
from .base import AbstractBaseAuthModel, AbstractAuthModel, AbstractMFAMethod
from .mfactor import TOTPAuth, TrustedDevice
from .oauth2 import OAuth2Auth

from .session import Session


class EmailAuth(AbstractAuthModel):
    email = models.EmailField(
        _("email"),
        unique=True,
        db_index=True,
        error_messages={
            "unique": _("An account with this email already exists."),
        },
    )

    class Meta:
        db_table = "authx_emails"
        verbose_name = _("Email Address")
        verbose_name_plural = _("Email Addresses")
        indexes = [
            models.Index(fields=["email", "is_active", "is_verified"]),
        ]


class PhoneAuth(AbstractAuthModel):
    phone = modelfields.PhoneNumberField(
        _("phone"),
        max_length=32,
        unique=True,
        help_text=_("E.164 format: +[country code][number]"),
    )

    class Meta:
        db_table = "authx_phones"
        verbose_name = _("Phone Number")
        verbose_name_plural = _("Phone Numbers")
        indexes = [
            models.Index(fields=["phone", "is_active", "is_verified"]),
        ]


__all__ = [
    "AbstractBaseAuthModel",
    "AbstractAuthModel",
    "AbstractMFAMethod",
    "EmailAuth",
    "PhoneAuth",
    "OAuth2Auth",
    "TOTPAuth",
    "TrustedDevice",
    "MagicLinkAuth",
    "Session",
]
