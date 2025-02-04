import time
# from importlib import import_module

from django.conf import settings
from django.contrib.sessions.backends.base import UpdateError
from django.contrib.sessions.exceptions import SessionInterrupted
from django.http import HttpRequest, HttpResponse
from django.utils import timezone
from django.utils.cache import patch_vary_headers
from django.utils.deprecation import MiddlewareMixin
from django.utils.http import http_date

from django_authx import HTTP_HEADER_ENCODING
from django_authx.models.session import SessionStore

from .models import Session
from .models.auth import generate_token
from .settings import authx_settings

# User = get_user_model()


def get_authorization_header(request: HttpRequest):
    """
    Return request's 'Authorization:' header, as a bytestring.

    Hide some test client ickyness where the header can be unicode.
    """
    auth = request.META.get("HTTP_AUTHORIZATION", b"")
    if isinstance(auth, str):
        # Work around django test client oddness
        auth = auth.encode(HTTP_HEADER_ENCODING)
    return auth


class AuthXMiddleware(MiddlewareMixin):
    def process_request(self, request: HttpRequest):
        # Try to get session ID from multiple sources
        session_id = self._get_session_id(request)

        if session_id:
            # Handle existing session
            session = self._get_existing_session(request, session_id)
        else:
            # Create new session
            session = self._create_new_session(request)

        print(session.session_id)

        # Attach session to request
        if session:
            request.authx_session = session
            if session.user:
                request.user = session.user

    def _get_session_id(self, request: HttpRequest) -> str:
        """Get session ID from multiple sources"""
        # First try session storage
        session_id = request.session.get("authx_session_id")
        if session_id:
            return session_id

        # Then try Authorization header for DRF
        auth = get_authorization_header(request).split()
        if len(auth) == 2 and auth[0].lower() == b"token":
            return auth[1].decode()

        # Finally try query parameters
        return request.GET.get("token")

    def _get_existing_session(self, request: HttpRequest, session_id: str) -> Session:
        """Handle existing session validation and updates"""
        try:
            session = Session.objects.select_related("user").get(
                session_id=session_id, is_active=True, expires_at__gt=timezone.now()
            )

            # Update last activity
            session.last_activity = timezone.now()
            session.save(update_fields=["last_activity"])

            # Store session ID in Django session if using session auth
            if not request.headers.get("Authorization"):
                request.session["authx_session_id"] = str(session.session_id)

            return session

        except Session.DoesNotExist:
            # Clear invalid session
            request.session.pop("authx_session_id", None)
            return None
        except Exception as e:
            # Log error but don't raise
            print(f"Session retrieval error: {e}")
            return None

    def _create_new_session(self, request: HttpRequest) -> Session:
        """Create new session for first-time requests"""
        try:
            session = Session.objects.create(
                client_name=request.META.get("HTTP_USER_AGENT", "Unknown Client"),
                ip_address=self._get_client_ip(request),
                location=request.META.get("HTTP_X_FORWARDED_FOR", "Unknown"),
                token=generate_token(),
                token_ttl=authx_settings.DEFAULT_TOKEN_TTL,
                expires_at=timezone.now() + authx_settings.DEFAULT_TOKEN_TTL,
                is_active=True,
                is_verified=True,
            )

            # Store in Django session if not using token auth
            if not request.headers.get("Authorization"):
                request.session["authx_session_id"] = str(session.session_id)

            return session

        except Exception as e:
            print(f"Session creation error: {e}")
            return None

    def _get_client_ip(self, request: HttpRequest) -> str:
        """Get client IP from request"""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0]
        return request.META.get("REMOTE_ADDR", "0.0.0.0")


class SessionMiddleware(MiddlewareMixin):
    def __init__(self, get_response):
        super().__init__(get_response)
        self.SessionStore = SessionStore

    def process_request(self, request: HttpRequest):
        session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME)
        request.session = self.SessionStore(session_key)
        print(request.session)
        print(request.session.session_key)
        print(request.session.values())

    def process_response(self, request: HttpRequest, response: HttpResponse):
        """
        If request.session was modified, or if the configuration is to save the
        session every time, save the changes and set a session cookie or delete
        the session cookie if the session has been emptied.
        """
        try:
            accessed = request.session.accessed
            modified = request.session.modified
            empty = request.session.is_empty()
        except AttributeError:
            return response
        # First check if we need to delete this cookie.
        # The session should be deleted only if the session is entirely empty.
        if settings.SESSION_COOKIE_NAME in request.COOKIES and empty:
            response.delete_cookie(
                settings.SESSION_COOKIE_NAME,
                path=settings.SESSION_COOKIE_PATH,
                domain=settings.SESSION_COOKIE_DOMAIN,
                samesite=settings.SESSION_COOKIE_SAMESITE,
            )
            patch_vary_headers(response, ("Cookie",))
        else:
            if accessed:
                patch_vary_headers(response, ("Cookie",))
            if (modified or settings.SESSION_SAVE_EVERY_REQUEST) and not empty:
                if request.session.get_expire_at_browser_close():
                    max_age = None
                    expires = None
                else:
                    max_age = request.session.get_expiry_age()
                    expires_time = time.time() + max_age
                    expires = http_date(expires_time)
                # Save the session data and refresh the client cookie.
                # Skip session save for 5xx responses.
                if response.status_code < 500:
                    try:
                        request.session.save()
                    except UpdateError:
                        raise SessionInterrupted(
                            "The request's session was deleted before the "
                            "request completed. The user may have logged "
                            "out in a concurrent request, for example."
                        )
                    response.set_cookie(
                        settings.SESSION_COOKIE_NAME,
                        request.session.session_key,
                        max_age=max_age,
                        expires=expires,
                        domain=settings.SESSION_COOKIE_DOMAIN,
                        path=settings.SESSION_COOKIE_PATH,
                        secure=settings.SESSION_COOKIE_SECURE or None,
                        httponly=settings.SESSION_COOKIE_HTTPONLY or None,
                        samesite=settings.SESSION_COOKIE_SAMESITE,
                    )
        return response
