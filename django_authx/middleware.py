from django.http import HttpRequest
from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone

from .models import Session
from .models.auth import generate_token
from .settings import authx_settings


class AuthXMiddleware(MiddlewareMixin):
    def process_request(self, request: HttpRequest):
        session_id = request.session.get(
            "authx_session_id", request.headers.get("Authorization", "")
        )
        print(request.headers)
        print(request.session.items())

        if session_id:
            try:
                session = Session.objects.get(
                    session_id=session_id, is_active=True, expires_at__gt=timezone.now()
                )
                session.last_activity = timezone.now()
                session.save(update_fields=["last_activity"])
                request.authx_session = session
            except Session.DoesNotExist:
                request.authx_session = None
                request.session.pop("authx_session_id", None)

        else:
            try:
                session = Session.objects.create(
                    client_name=request.META.get("HTTP_USER_AGENT", "Unknown Client"),
                    ip_address=request.META.get("REMOTE_ADDR", "0.0.0.0"),
                    location=request.META.get("HTTP_X_FORWARDED_FOR", "Unknown"),
                    token=generate_token(),
                    token_ttl=authx_settings.DEFAULT_TOKEN_TTL,
                    expires_at=timezone.now() + authx_settings.DEFAULT_TOKEN_TTL,
                    # remember_session=remember
                    is_active=True,
                    is_verified=True,
                )
                request.session["authx_session_id"] = str(session.session_id)
                request.authx_session = session
            except Exception as e:
                print(e)
