import uuid

try:
    import humanize
except Exception as e:
    print(e)
    humanize = None

from django.db import models
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from django_authx.settings import authx_settings

from . import base


class Session(base.BaseAuthModel):
    session_id = models.UUIDField(
        _("session ID"),
        primary_key=True,
        unique=True,
        default=uuid.uuid4,
        editable=False,
        db_index=True,
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="sessions",
    )

    #: Token string
    token = models.CharField(
        max_length=authx_settings.TOKEN_CHARACTER_LENGTH,
        null=False,
        blank=False,
        db_index=True,
        unique=True,
        help_text=_("Token is auto-generated on save."),
    )

    #: Token Time To Live (TTL) in timedelta. Format: ``DAYS HH:MM:SS``.
    token_ttl = models.DurationField(
        null=False,
        default=authx_settings.DEFAULT_TOKEN_TTL,
        verbose_name=_("Token Time To Live (TTL)"),
        help_text=_(
            """
            Token Time To Live (TTL) in timedelta. Format: <code>DAYS HH:MM:SS</code>.
            """
        ),
    )

    #: Throttle rate for requests authed with this client.
    #:
    #: **Format**: ``number_of_requests/period``
    #: where period should be one of: *('s', 'm', 'h', 'd')*.
    #: (same format as DRF's throttle rates)
    #:
    #: **Example**: ``100/h`` implies 100 requests each hour.
    #:
    #: .. versionadded:: 0.2
    throttle_rate = models.CharField(
        max_length=64,
        default="",
        blank=True,
        verbose_name=_("Throttle rate for requests authed with this client"),
        help_text=_(
            """Follows the same format as DRF's throttle rates.
            Format: <em>'number_of_requests/period'</em>
            where period should be one of: ('s', 'm', 'h', 'd').
            Example: '100/h' implies 100 requests each hour.
            """
        ),
        # validators=[validate_client_throttle_rate],
    )

    auth_backend = models.CharField(_("auth backend"), max_length=126, db_index=True)

    client_name = models.CharField(_("client name"), max_length=255, db_index=True)

    ip_address = models.GenericIPAddressField(_("IP address"), db_index=True)

    location = models.CharField(_("location"), max_length=255, db_index=True)

    last_activity = models.DateTimeField(
        _("last activity"), default=timezone.now, db_index=True
    )

    expires_at = models.DateTimeField(_("expires at"))

    remember_session = models.BooleanField(default=False, db_index=True)

    class Meta:
        db_table = "sessions_model"
        verbose_name = _("Session")
        verbose_name_plural = _("Sessions")
        indexes = [
            models.Index(fields=["user", "auth_backend"]),
            models.Index(fields=["user", "auth_backend", "is_active"]),
            models.Index(fields=["client_name", "ip_address"]),
        ]
        constraints = [
            models.CheckConstraint(
                check=models.Q(expires_at__gt=models.F("created_at")),
                name="session_expiry_after_creation",
            )
        ]

    @property
    def expires_in(self) -> str:
        """
        Dynamic property that gives the :py:attr:`~expiry`
        attribute in human readable string format.

        Uses `humanize package <https://github.com/jmoiron/humanize>`__.
        """
        if self.expiry:
            td = self.expiry - self.created
            return humanize.naturaldelta(td) if humanize else td
        return "N/A"

    @property
    def has_expired(self) -> bool:
        """
        Dynamic property that returns ``True`` if token has expired,
        otherwise ``False``.
        """
        return timezone.now() > self.expires_at

    def __str__(self):
        td = humanize.naturaldelta(self.token_ttl) if humanize else self.token_ttl
        rate = self.throttle_rate or "0/s"
        return "({0}: {1}, {2})".format(self.client_name, td, rate)

    def __repr__(self) -> str:
        return "({0}, {1}/{2})".format(
            self.token, self.user.get_username(), self.client_name
        )

    def renew_token(self, request=None) -> "timezone.datetime":
        """
        Utility function to renew the token.

        Updates the :py:attr:`~expiry` attribute by ``Client.token_ttl``.
        """
        new_expiry = timezone.now() + self.token_ttl
        self.expires_at = new_expiry
        self.save(update_fields=("expires_at",))
        return new_expiry
