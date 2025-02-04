from rest_framework.routers import DefaultRouter

from .views import (
    EmailAuthViewSet,
    PhoneAuthViewSet,
    OAuth2AuthViewSet,
    TOTPAuthViewSet,
    MagicLinkAuthViewSet,
    SessionViewSet,
    UserViewSet,
)


class AuthRouter(DefaultRouter):
    """
    Router for authentication related endpoints
    """

    def __init__(self, *args, **kwargs):
        self.trailing_slash = True
        super().__init__(*args, **kwargs)

        self.register("user", UserViewSet, basename="user")
        # Register authentication viewsets
        self.register("email", EmailAuthViewSet, basename="email-auth")
        self.register("phone", PhoneAuthViewSet, basename="phone-auth")
        self.register("oauth2", OAuth2AuthViewSet, basename="oauth2-auth")
        self.register("totp", TOTPAuthViewSet, basename="totp-auth")
        self.register("magic-link", MagicLinkAuthViewSet, basename="magic-link-auth")
        self.register("sessions", SessionViewSet, basename="session")


def get_authx_api_routes():
    """
    Helper function to get all auth related URL patterns
    """
    router = AuthRouter()
    return router.urls
