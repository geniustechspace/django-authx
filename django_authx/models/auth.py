import binascii
from os import urandom

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from django_authx.settings import authx_settings

from . import base, modelfields


def generate_token() -> str:
    return binascii.hexlify(
        urandom(int(authx_settings.TOKEN_CHARACTER_LENGTH / 2))
    ).decode()


def get_default_expiry():
    """Return default expiry time (30 minutes from now)"""
    return timezone.now() + timezone.timedelta(minutes=30)


class EmailAuth(base.BaseAuthModel):
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


class PhoneAuth(base.BaseAuthModel):
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


class OAuth2Auth(base.BaseAuthModel):
    provider = models.CharField(_("provider"), max_length=50, db_index=True)
    provider_id = models.CharField(_("provider ID"), max_length=255, db_index=True)
    access_token = models.CharField(_("access token"), max_length=1024, db_index=True)
    refresh_token = models.CharField(
        _("refresh token"), max_length=1024, null=True, blank=True
    )
    expires_at = models.DateTimeField(_("expires at"))
    scope = models.CharField(_("scopes"), max_length=1024, null=True, blank=True)

    class Meta:
        db_table = "authx_oauth2"
        verbose_name = _("OAuth Account")
        verbose_name_plural = _("OAuth Accounts")
        unique_together = ("provider", "provider_id")
        indexes = [
            models.Index(fields=["user", "provider"]),
            models.Index(fields=["user", "provider", "is_active"]),
        ]

    def is_expired(self):
        return timezone.now() > self.expires_at


class MagicLinkAuth(base.BaseAuthModel):
    token = models.CharField(
        _("token"), default=generate_token, unique=True, db_index=True, max_length=255
    )
    session = models.ForeignKey("Session", on_delete=models.CASCADE)
    expires_at = models.DateTimeField(default=get_default_expiry)

    class Meta:
        db_table = "authx_magic_links"
        verbose_name = _("Magic Link")
        verbose_name_plural = _("Magic Links")
        indexes = [
            models.Index(fields=["user", "created_at"]),
            models.Index(fields=["token", "is_active"]),
        ]

    def is_expired(self):
        return timezone.now() > self.expires_at


class TOTPAuth(base.BaseAuthModel):
    secret_key = models.CharField(_("secret key"), max_length=32)
    backup_codes = models.JSONField(_("backup codes"), default=list)
    last_used_at = models.DateTimeField(_("last used at"), null=True, db_index=True)
    device_name = models.CharField(
        _("device name"), max_length=255, null=True, db_index=True
    )
    recovery_codes = models.JSONField(_("recovery codes"), default=list)

    class Meta:
        db_table = "authx_totps"
        verbose_name = _("TOTP Device")
        verbose_name_plural = _("TOTP Devices")
        indexes = [
            models.Index(fields=["user", "device_name"]),
            models.Index(fields=["user", "device_name", "is_active"]),
            models.Index(fields=["last_used", "is_active"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "device_name"], name="unique_user_device"
            )
        ]
