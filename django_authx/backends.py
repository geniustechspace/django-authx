"""
Django authentication backends providing multiple authentication methods.
Supports username, email, phone, OAuth2, magic links and TOTP-based authentication.
"""

import logging
from typing import Optional

# import pyotp

from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractBaseUser
from django.http import HttpRequest
from django.utils import timezone

from .models import EmailAuth, PhoneAuth, OAuth2Auth, Session

logger = logging.getLogger(__name__)
UserModel = get_user_model()

# Auth backend identifiers
AUTH_BACKEND_USERNAME = "username:password"
AUTH_BACKEND_EMAIL = "email:password"
AUTH_BACKEND_PHONE = "phone:password"
AUTH_BACKEND_PHONE_CODE = "phone:code"
AUTH_BACKEND_OAUTH2 = "oauth2"
AUTH_BACKEND_MAGIC_LINK = "magic_link"
AUTH_BACKEND_TOTP = "totp"


class BaseAuthxBackend(ModelBackend):
    """Base authentication backend providing common session management functionality.

    Handles session creation, updates and validation for all authentication methods.
    Extends Django's ModelBackend.
    """

    def authenticate(self, request: HttpRequest, **kwargs):
        """Authenticate a user request and manage the associated session.

        Args:
            request (HttpRequest): The incoming request object
            **kwargs: Authentication credentials

        Returns:
            User: Authenticated user object if successful, None otherwise
        """
        # self.session = request.authx_session
        if request.session.session_key is None:
            return None
        user = self.validate_auth(request, **kwargs)
        print(self.session)
        print(user)
        if user:
            request.authx_session.user = user
            request.authx_session.user.save(update_fields=["user",])
        print(user, self.session, self.session.user, sep="\n")
        return user or self.session.user if self.session else None

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        pass

    def validate_auth(
        self, request: HttpRequest, **kwargs
    ) -> Optional[AbstractBaseUser]:
        """Validate authentication credentials. To be implemented by subclasses.

        Args:
            request (HttpRequest): The incoming request object
            **kwargs: Authentication credentials

        Returns:
            Optional[AbstractBaseUser]: User object if valid, None otherwise
        """
        return None

    def _update_session(
        self, user: AbstractBaseUser, auth_backend: str = None, **kwargs
    ) -> None:
        """Update existing session"""
        if not self.session:
            return None

        if self.session.user and self.session.user != user:
            raise ValueError("Session user mismatch")

        try:
            for key, value in kwargs.items():
                setattr(self.session, key, value)
            self.session.user = user
            self.session.auth_backend = (
                auth_backend if auth_backend else self.session.auth_backend
            )
            self.session.save()

        except Session.DoesNotExist:
            return None
        except Exception as e:
            logger.error(f"Session update failed: {str(e)}")
            return None

    def get_session(self, request: HttpRequest) -> Optional[Session]:
        """Get and update active session"""
        if not request.authx_session:
            return None

        try:
            session = Session.objects.select_related("user").get(
                session_key=request.session.session_key,
                is_active=True,
                expires_at__gt=timezone.now(),
            )
            session.last_used_at = timezone.now()
            session.save(update_fields=["last_used_at"])
            return session
        except Session.DoesNotExist:
            return None
        except Exception as e:
            logger.error(f"Session retrieval failed: {str(e)}")
            return None


class UsernameAuthBackend(BaseAuthxBackend):

    def validate_auth(
        self,
        request: HttpRequest,
        username=None,
        password=None,
        **kwargs,
    ):
        username = username or kwargs.get(UserModel.USERNAME_FIELD)
        user = super(ModelBackend, self).authenticate(
            request, username=username, password=password
        )

        return user


class EmailPasswordAuthBackend(BaseAuthxBackend):
    """Email and password based authentication backend.

    Validates email/password combinations against EmailAuth records.
    Requires verified email addresses.
    """

    def validate_auth(
        self, request: HttpRequest, email: str = None, password: str = None, **kwargs
    ) -> Optional[AbstractBaseUser]:
        """Validate email and password authentication.

        Args:
            request (HttpRequest): The incoming request object
            email (str, optional): Email address
            password (str, optional): User password
            **kwargs: Additional arguments

        Returns:
            Optional[AbstractBaseUser]: User object if valid credentials, None otherwise
        """
        if not email or not password:
            return None

        try:
            auth = EmailAuth.objects.select_related("user").get(
                email=email, is_active=True, is_verified=True
            )
            if auth.user.check_password(password):
                self._update_session(auth.user, AUTH_BACKEND_EMAIL)
                return auth.user
        except EmailAuth.DoesNotExist:
            return None


class PhonePasswordAuthBackend(BaseAuthxBackend):
    """Phone number and password based authentication backend.

    Validates phone/password combinations against PhoneAuth records.
    Requires verified phone numbers.
    """

    def validate_auth(
        self, request: HttpRequest, phone=None, password=None, **kwargs
    ) -> Optional[AbstractBaseUser]:
        """Validate phone number and password authentication.

        Args:
            request (HttpRequest): The incoming request object
            phone (str, optional): Phone number
            password (str, optional): User password
            **kwargs: Additional arguments

        Returns:
            Optional[AbstractBaseUser]: User object if valid credentials, None otherwise
        """
        if not phone or not password:
            return None
        try:
            auth = PhoneAuth.objects.select_related("user").get(
                phone=phone, is_active=True, is_verified=True
            )
            if auth.user.check_password(password):
                self._update_session(auth.user, AUTH_BACKEND_PHONE)
                return auth.user
        except PhoneAuth.DoesNotExist:
            return None


class OAuth2Backend(BaseAuthxBackend):
    """OAuth2 based authentication backend.

    Handles authentication via third-party OAuth2 providers.
    Validates provider tokens and IDs.
    """

    def validate_auth(
        self,
        request: HttpRequest,
        provider=None,
        provider_id=None,
        access_token=None,
        **kwargs,
    ) -> Optional[AbstractBaseUser]:
        """Validate OAuth2 authentication credentials.

        Args:
            request (HttpRequest): The incoming request object
            provider (str, optional): OAuth2 provider name
            provider_id (str, optional): Provider-specific user ID
            access_token (str, optional): OAuth2 access token
            **kwargs: Additional arguments

        Returns:
            Optional[AbstractBaseUser]: User object if valid credentials, None otherwise
        """
        if not provider or not provider_id or not access_token:
            return None

        try:
            auth = OAuth2Auth.objects.get(
                provider=provider,
                provider_id=provider_id,
                access_token=access_token,
                is_active=True,
                is_verified=True,
            )
            self._update_session(auth.user, f"{AUTH_BACKEND_OAUTH2}_{provider}")
            return auth.user
        except OAuth2Auth.DoesNotExist:
            return None


class TOTPBackend(BaseAuthxBackend):
    """Time-based One-Time Password (TOTP) authentication backend.

    Implements two-factor authentication using TOTP.
    Validates time-based codes against user secrets.
    """

    def validate_auth(
        self, request: HttpRequest, user=None, code=None, **kwargs
    ) -> Optional[AbstractBaseUser]:
        """Validate TOTP code authentication.

        Args:
            request (HttpRequest): The incoming request object
            user (User, optional): User attempting authentication
            code (str, optional): TOTP code to validate
            **kwargs: Additional arguments

        Returns:
            Optional[AbstractBaseUser]: User object if valid code, None otherwise
        """

        if not user or not code:
            return None

        # try:
        #     auth = TOTPAuth.objects.get(user=user, is_active=True, is_verified=True)
        #     totp = pyotp.TOTP(auth.secret_key)
        #     if totp.verify(code):
        #         self._update_session(auth.user, AUTH_BACKEND_TOTP)
        #         return auth.user
        # except TOTPAuth.DoesNotExist:
        #     return None


__all__ = [
    "BaseAuthxBackend",
    "EmailPasswordAuthBackend",
    "PhonePasswordAuthBackend",
    "OAuth2Backend",
    "TOTPBackend",
]
