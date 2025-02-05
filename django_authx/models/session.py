from __future__ import annotations
from typing import Optional
from datetime import timedelta

from django.db import models
from django.conf import settings
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.utils.functional import cached_property
from django.utils.translation import gettext_lazy as _

from django_authx.dependencies import humanize
from django_authx.utils import generate_token
from . import base


class SessionQuerySet(models.QuerySet):
    @property
    def active(self):
        """Get all active and non-expired sessions."""
        return self.filter(is_active=True, expires_at__gt=timezone.now())

    @property
    def expired(self):
        """Get all expired sessions."""
        return self.filter(expires_at__lte=timezone.now())

    def for_user(self, user):
        """Get all sessions for a specific user."""
        return self.filter(user=user)


class SessionManager(models.Manager):
    use_in_migrations = True

    def get_queryset(self):
        return SessionQuerySet(self.model, using=self._db)

    def create_session(
        self,
        user: Optional[settings.AUTH_USER_MODEL] = None,
        expires_in: int = 86400,
        **kwargs,
    ) -> Session:
        """Create a new session."""
        expires_at = timezone.now() + timedelta(seconds=expires_in)
        session = self.model(user=user, expires_at=expires_at, **kwargs)
        session.full_clean()
        session.save()
        return session


class AbstractBaseSession(base.BaseAuthModel):
    session_key = models.CharField(
        _("session key"),
        max_length=64,
        primary_key=True,
        default=generate_token,
    )
    refresh_token = models.CharField(
        _("refresh token"),
        max_length=64,
        unique=True,
        db_index=True,
        default=generate_token,
    )
    expires_at = models.DateTimeField(_("expires at"), db_index=True)
    remember_session = models.BooleanField(
        _("remember session"),
        default=False,
        db_index=True,
        help_text=_("If enabled, extends session lifetime"),
    )

    class Meta:
        abstract = True
        verbose_name = _("session")
        verbose_name_plural = _("sessions")

    def clean(self):
        """Validate session data."""
        if self.expires_at <= timezone.now():
            raise ValidationError(_("Expiry time must be in the future"))
        super().clean()

    @property
    def expires_in(self) -> str:
        if self.expires_at:
            td = self.expires_at - timezone.now()
            return humanize.naturaldelta(td)
        return "N/A"

    @property
    def has_expired(self) -> bool:
        return timezone.now() > self.expires_at

    def refresh(self, duration: int = 86400) -> None:
        """Refresh session expiry time."""
        self.expires_at = timezone.now() + timedelta(seconds=duration)
        self.save(update_fields=["expires_at"])


class Session(AbstractBaseSession):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="sessions_set",
    )
    throttle_rate = models.CharField(
        max_length=64,
        default="",
        blank=True,
        verbose_name=_("Throttle rate"),
    )
    auth_backend = models.CharField(_("auth backend"), max_length=126, db_index=True)
    user_agent = models.TextField(_("user agent"), blank=True, default="")
    ip_address = models.GenericIPAddressField(_("IP address"), db_index=True)
    location = models.CharField(_("location"), max_length=255, db_index=True)
    last_activity = models.DateTimeField(
        _("last activity"), default=timezone.now, db_index=True
    )

    objects = SessionManager()

    class Meta:
        db_table = "authx_sessions"
        indexes = [
            models.Index(fields=["user", "auth_backend"]),
            models.Index(fields=["user", "auth_backend", "is_active"]),
            models.Index(fields=["user_agent", "ip_address"]),
            models.Index(fields=["last_activity"]),
        ]
        constraints = [
            models.CheckConstraint(
                check=models.Q(expires_at__gt=models.F("created_at")),
                name="session_expiry_after_creation",
            )
        ]

    def update_activity(self):
        """Update last activity timestamp."""
        self.last_activity = timezone.now()
        self.save(update_fields=["last_activity"])

    @cached_property
    def client(self):
        """Return the client associated with this session.

        Returns:
            UserAgent: python UserAgent object
        """
        return self.user_agent

    def __str__(self):
        # td = humanize.naturaldate(self.expires_at)
        rate = self.throttle_rate or "0/s"
        return "({0}: {1}".format(self.client.device, rate)

    def __repr__(self) -> str:
        return "({0}, {1}/{2})".format(
            self.session_key, self.user.get_username(), self.client
        )

    @classmethod
    def get_session_store_class(cls):
        from django_authx.session_store import SessionStore

        return SessionStore
