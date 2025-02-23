"""Multi-factor authentication method implementations.

This module provides Django models for various MFA methods including:
- TOTP (Time-based One-Time Password)
- WebAuthn/FIDO2
- Push notifications
- Backup codes
- Trusted devices

Each method inherits from BaseMFAMethod and implements the required validation logic.
"""

from typing import List, Dict, Any, Optional, Union
import logging
import pyotp
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError

from django_authx.utils.tokens import generate_token, validate_jwt

from .base import AbstractMFAMethod
from .modelfields import encrypted_fields

logger = logging.getLogger(__name__)


class TOTPAuth(AbstractMFAMethod):
    """Time-based One-Time Password authentication method.

    Implements TOTP verification using PyOTP library with configurable
    parameters for digits and interval.
    """

    token = encrypted_fields.EncryptedCharField(
        max_length=255, help_text=_("Encrypted TOTP secret key")
    )
    otp = encrypted_fields.EncryptedCharField(
        max_length=255, help_text=_("Current OTP value")
    )
    digits = models.IntegerField(default=6, help_text=_("Number of digits in OTP"))
    interval = models.IntegerField(default=30, help_text=_("TOTP interval in seconds"))

    @classmethod
    def validate(cls, claims: Union[str, dict], secret: Optional[str] = None) -> bool:
        """Validate TOTP code or JWT token.

        Args:
            claims: Either TOTP code or JWT token
            secret: Optional JWT secret key

        Returns:
            bool: True if validation succeeds

        Raises:
            ValidationError: If validation fails
        """
        # Detect claim type
        if isinstance(claims, str) and claims.isdigit():
            return cls._validate_totp(claims)
        elif isinstance(claims, (str, dict)):
            return cls._validate_jwt(claims, secret)
        else:
            raise ValidationError(_("Invalid claim format"))

    @classmethod
    def _validate_totp(cls, code: str) -> bool:
        """Validate TOTP code."""
        if not code or not code.isdigit():
            raise ValidationError(_("Invalid TOTP format"))

        try:
            totp = pyotp.TOTP(cls.token, digits=cls.digits, interval=cls.interval)
            is_valid = totp.verify(code)

            if is_valid:
                cls.handle_successful_attempt()
            else:
                cls.handle_failed_attempt()

            return is_valid

        except Exception as e:
            logger.error(f"TOTP validation error: {str(e)}")
            return False

    @classmethod
    def _validate_jwt(cls, token: Union[str, dict], secret: str) -> bool:
        """Validate JWT token."""
        return validate_jwt(token=token, secret=secret)

    def send_code(self) -> bool:
        """Send TOTP code via configured delivery method.

        Returns:
            bool: True if code was sent successfully
        """
        # TODO: Implement code delivery logic
        raise NotImplementedError


class WebAuthn(AbstractMFAMethod):
    """WebAuthn/FIDO2 authentication method.

    Implements WebAuthn authentication using FIDO2 protocol with
    encrypted storage of credentials.
    """

    credential_id = encrypted_fields.EncryptedTextField(
        help_text=_("Encrypted WebAuthn credential ID")
    )
    public_key = encrypted_fields.EncryptedTextField(
        help_text=_("Encrypted public key")
    )
    sign_count = models.IntegerField(
        default=0, help_text=_("Number of successful authentications")
    )

    def validate(self, assertion: Dict[str, Any]) -> bool:
        """Validate WebAuthn assertion.

        Args:
            assertion: WebAuthn assertion data

        Returns:
            bool: True if assertion is valid
        """
        # TODO: Implement WebAuthn validation
        raise NotImplementedError


class PushAuth(AbstractMFAMethod):
    """Push notification-based authentication method."""

    device_token = encrypted_fields.EncryptedTextField()
    device_name = models.CharField(max_length=255)
    platform = models.CharField(max_length=50)  # ios, android, etc.

    def validate(self, response: dict) -> bool:
        # Implement push validation logic
        pass

    def send_push(self) -> bool:
        # Implement push notification sending logic
        pass


class BackupCode(AbstractMFAMethod):
    """Backup codes for account recovery.

    Implements single-use backup codes with automatic generation
    and usage tracking.
    """

    code = encrypted_fields.EncryptedCharField(
        max_length=20, help_text=_("Encrypted backup code")
    )
    is_used = models.BooleanField(
        default=False, help_text=_("Whether code has been used")
    )
    used_at = models.DateTimeField(
        null=True, blank=True, help_text=_("When code was used")
    )

    class Meta:
        unique_together = ["user", "code"]

    @classmethod
    def generate_codes(cls, user, count: int = 8) -> List[str]:
        """Generate new set of backup codes.

        Args:
            user: User to generate codes for
            count: Number of codes to generate

        Returns:
            List of generated codes
        """
        user.backup_code_set.filter(is_used=False).delete()

        codes = []
        for __ in range(count):
            code = generate_token(16).upper()
            cls.objects.create(user=user, code=code)
            codes.append(code)

        logger.info(f"Generated {count} backup codes for user {user.id}")
        return codes

    def use_code(self) -> None:
        """Mark backup code as used."""
        self.is_used = True
        self.used_at = timezone.now()
        self.save()
        logger.info(f"Backup code used for user {self.user}")


class TrustedDevice(AbstractMFAMethod):
    """Remembered and trusted devices.

    Tracks trusted devices with device fingerprinting and automatic expiry.
    """

    device_id = models.UUIDField(
        default=generate_token, unique=True, help_text=_("Unique device identifier")
    )
    device_name = models.CharField(
        max_length=255, help_text=_("User-friendly device name")
    )
    device_type = models.CharField(max_length=50, help_text=_("Type of device"))
    user_agent = models.TextField(help_text=_("Browser/device user agent"))
    ip_address = models.GenericIPAddressField(help_text=_("Device IP address"))
    fingerprint = encrypted_fields.EncryptedTextField(
        help_text=_("Encrypted device fingerprint")
    )
    is_trusted = models.BooleanField(
        default=True, help_text=_("Whether device is currently trusted")
    )
    expires_at = models.DateTimeField(help_text=_("Device trust expiry"))

    def is_valid(self) -> bool:
        """Check if device trust is valid."""
        return self.is_trusted and timezone.now() < self.expires_at

    def revoke(self) -> None:
        """Revoke device trust."""
        self.is_trusted = False
        self.save()
        logger.info(f"Revoked trust for device {self.device_id}")
