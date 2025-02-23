import logging
from typing import Optional

from django.http import HttpRequest
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
# from django.core.exceptions import ValidationError

from django_authx import HTTP_HEADER_ENCODING

# from django_authx.utils.tokens import validate_jwt

from .models import Session
from .settings import authx_settings

logger = logging.getLogger(__name__)

# User = get_user_model()


def get_authorization_header(request: HttpRequest) -> bytes:
    """
    Return request's 'Authorization:' header, as a bytestring.

    Args:
        request (HttpRequest): The incoming request

    Returns:
        bytes: The authorization header value
    """
    auth = request.META.get("HTTP_AUTHORIZATION", b"")
    if isinstance(auth, str):
        auth = auth.encode(HTTP_HEADER_ENCODING)
    print("\nHTTP_AUTHORIZATION:", auth, end="\n\n")
    return auth


class AuthXMiddleware(MiddlewareMixin):
    def process_request(self, request: HttpRequest):
        # Try to get session ID from multiple sources
        session = self._get_auth_session_obj(request)
        if not session and request.session.session_key:
            session = self._create_new_session(request)

        # Attach session to request
        request.authx_session = session

    def _get_auth_session_obj(self, request: HttpRequest) -> Optional[Session]:
        """
        Handle existing session validation and updates.

        Args:
            request (HttpRequest): The incoming request
            session_key (str): Session key to validate

        Returns:
            Optional[Session]: Valid session object or None
        """
        try:
            session = Session.objects.select_related("user").get(
                session_key=request.session.session_key,
                is_active=True,
                expires_at__gt=timezone.now(),
            )
            session.update_last_used_at()
            return session

        except Session.DoesNotExist:
            logger.info(
                f"No valid session found for key: {request.session.session_key}"
            )
            return None
        except Exception as e:
            logger.error(f"Session retrieval error: {str(e)}", exc_info=True)
            return None

    def _create_new_session(self, request: HttpRequest) -> Session:
        """
        Create new session for first-time requests.

        Args:
            request (HttpRequest): The incoming request

        Returns:
            Optional[Session]: Newly created session or None
        """
        session = Session.objects.create(
            session_key=request.session.session_key,
            user_agent=request.META.get("HTTP_USER_AGENT", "Unknown Client"),
            ip_address=request.META.get("HTTP_X_FORWARDED_FOR", "Unknown"),
            location=request.META.get("HTTP_X_FORWARDED_FOR", "Unknown"),
            auth_backend="django.contrib.auth.backends.ModelBackend",
            expires_at=timezone.now() + authx_settings.DEFAULT_TOKEN_TTL,
            is_active=True,
            is_verified=True,
        )

        return session
