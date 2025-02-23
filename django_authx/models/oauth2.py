from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .base import AbstractMFAMethod


class OAuth2Auth(AbstractMFAMethod):
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
