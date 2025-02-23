from __future__ import annotations
from datetime import timedelta

from django.db import models
from django.conf import settings
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.utils.functional import cached_property
from django.utils.translation import gettext_lazy as _

from django_authx.dependencies import humanize
from django_authx.utils.tokens import generate_token
from .base import AbstractBaseAuthModel


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
        user=None,
        expires_in: int = 86400,
        **kwargs,
    ) -> Session:
        """Create a new session."""
        expires_at = timezone.now() + timedelta(seconds=expires_in)
        session = self.model(user=user, expires_at=expires_at, **kwargs)
        session.full_clean()
        session.save()
        return session


class AbstractBaseSession(AbstractBaseAuthModel):
    session_key = models.CharField(
        _("session key"),
        max_length=64,
        primary_key=True,
        default=generate_token,
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="sessions_set",
        verbose_name=_("user"),
    )
    auth_backend = models.CharField(
        _("auth backend"),
        max_length=126,
        default="django.contrib.auth.backends.ModelBackend",
        db_index=True,
    )
    access_token = models.CharField(
        _("access token"),
        max_length=64,
        unique=True,
        db_index=True,
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
    user_agent = models.TextField(_("user agent"), blank=True, default="")
    ip_address = models.GenericIPAddressField(
        _("IP address"), null=True, blank=True, db_index=True
    )
    location = models.CharField(_("location"), max_length=255, db_index=True)
    throttle_rate = models.CharField(
        _("throttle rate"), max_length=64, blank=True, default=""
    )

    objects = SessionManager()

    class Meta:
        db_table = "authx_sessions"
        indexes = [
            models.Index(fields=["user", "auth_backend"]),
            models.Index(fields=["user", "auth_backend", "is_active"]),
            models.Index(fields=["last_used_at"]),
            models.Index(fields=["user_agent", "ip_address"]),
        ]
        constraints = [
            models.CheckConstraint(
                check=models.Q(expires_at__gt=models.F("created_at")),
                name="session_expiry_after_creation",
            )
        ]

    def update_last_used_at(self):
        self.last_used_at = timezone.now()
        self.save(update_fields=["last_used_at"])

    @cached_property
    def last_activity(self):
        """Return the client associated with this session.

        Returns:
            UserAgent: python UserAgent object
        """
        return self.last_used_at

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
        return "({0}: {1}".format(self.client, rate)

    def __repr__(self) -> str:
        return "({0}, {1}/{2})".format(
            self.session_key, self.user.get_username(), self.client
        )
