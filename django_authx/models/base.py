from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class AbstractBaseAuthModel(models.Model):
    """Abstract base auth model providing common authentication fields."""

    AUTH_STATUS = (
        ("pending", "Pending Verification"),
        ("active", "Active"),
        ("used_up", "Used Up"),
        ("expired", "Expired"),
        ("disabled", "Disabled"),
        ("suspended", "Suspended"),
        ("locked", "Temporarily Locked"),
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        help_text=_("User this record belongs to"),
        db_index=True,
    )

    status = models.CharField(
        max_length=20,
        choices=AUTH_STATUS,
        default="pending",
        db_index=True,
        help_text=_("Current status of this auth method"),
    )
    is_active = models.BooleanField(_("active"), default=True, db_index=True)
    is_verified = models.BooleanField(_("verified"), default=False, db_index=True)
    # Timestamps
    created_at = models.DateTimeField(
        auto_now_add=True, db_index=True, help_text=_("When this record was created")
    )
    updated_at = models.DateTimeField(
        auto_now=True, help_text=_("When this record was last updated")
    )

    # Validation tracking
    last_used_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When this method was last successfully used"),
    )
    failed_attempts = models.PositiveIntegerField(
        default=0, help_text=_("Number of consecutive failed attempts")
    )
    locked_until = models.DateTimeField(
        null=True, blank=True, help_text=_("Locked until this timestamp")
    )

    class Meta:
        abstract = True

    @property
    def is_locked(self) -> bool:
        """Check if method is temporarily locked."""
        if self.status == "locked" or (
            self.locked_until and timezone.now() < self.locked_until
        ):
            return True
        return False

    def validate(self, claim) -> None:
        """Validate this claim."""
        raise NotImplementedError("Subclasses must implement the validate method")

    def handle_failed_attempt(self) -> None:
        """Handle a failed validation attempt."""
        self.failed_attempts += 1
        if self.failed_attempts >= 3:  # Max attempts
            self.status = "locked"
            self.locked_until = timezone.now() + timezone.timedelta(minutes=15)
        self.save()

    def handle_successful_attempt(self) -> None:
        """Handle a successful validation."""
        self.failed_attempts = 0
        self.locked_until = None
        self.last_used_at = timezone.now()
        self.save()

    def change_status(self, new_status: str, reason: str = None) -> None:
        """Change method status with audit logging."""
        # old_status = self.status
        self.status = new_status
        self.save()

        # # Log status change
        # from django_authx.models import MFAMethodLog

        # MFAMethodLog.objects.create(
        #     method_type=self.__class__.__name__,
        #     method_id=self.id,
        #     # action=f"status_change",
        #     old_value=old_status,
        #     new_value=new_status,
        #     reason=reason,
        # )

    def enable(self) -> None:
        """Enable this auth method."""
        self.change_status("active", "Manually enabled")

    def disable(self) -> None:
        """Disable this auth method."""
        self.change_status("disabled", "Manually disabled")


class AbstractAuthModel(AbstractBaseAuthModel):
    is_primary = models.BooleanField(default=False)

    class Meta:
        abstract = True


class AbstractMFAMethod(AbstractBaseAuthModel):
    """Base model for MFA methods with additional tracking."""

    class Meta:
        abstract = True
