from django_filters import rest_framework as filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import status

from django_authx.models import EmailAuth, PhoneAuth, OAuth2Auth, TOTPAuth, MagicLinkAuth
from django_authx.serializers import (
    EmailAuthSerializer,
    PhoneAuthSerializer,
    OAuth2AuthSerializer,
    TOTPAuthSerializer,
    MagicLinkAuthSerializer,
)

from .base import BaseAuthViewSet


class EmailAuthFilter(filters.FilterSet):
    class Meta:
        model = EmailAuth
        fields = {
            "email": ["exact", "contains"],
            "is_active": ["exact"],
            "is_verified": ["exact"],
            "created_at": ["gte", "lte"],
        }


class EmailAuthViewSet(BaseAuthViewSet):
    queryset = EmailAuth.objects.all()
    serializer_class = EmailAuthSerializer
    filterset_class = EmailAuthFilter
    search_fields = ["email"]
    ordering_fields = ["email", "created_at", "last_used"]

    @action(detail=True, methods=["post"])
    def verify_email(self, request, pk=None):
        instance = self.get_object()
        instance.is_verified = True
        instance.save()
        return Response({"status": "email verified"})


class PhoneAuthFilter(filters.FilterSet):
    class Meta:
        model = PhoneAuth
        fields = {
            "phone": ["exact"],
            "is_active": ["exact"],
            "is_verified": ["exact"],
            "created_at": ["gte", "lte"],
        }


class PhoneAuthViewSet(BaseAuthViewSet):
    queryset = PhoneAuth.objects.all()
    serializer_class = PhoneAuthSerializer
    filterset_class = PhoneAuthFilter
    search_fields = ["phone"]
    ordering_fields = ["phone", "created_at", "last_used"]

    @action(detail=True, methods=["post"])
    def verify_phone(self, request, pk=None):
        instance = self.get_object()
        instance.is_verified = True
        instance.save()
        return Response({"status": "phone verified"})


class OAuth2AuthFilter(filters.FilterSet):
    class Meta:
        model = OAuth2Auth
        fields = {
            "provider": ["exact"],
            "provider_id": ["exact"],
            "is_active": ["exact"],
            "expires_at": ["gte", "lte"],
        }


class OAuth2AuthViewSet(BaseAuthViewSet):
    queryset = OAuth2Auth.objects.all()
    serializer_class = OAuth2AuthSerializer
    filterset_class = OAuth2AuthFilter
    search_fields = ["provider", "provider_id"]
    ordering_fields = ["provider", "created_at", "expires_at"]

    @action(detail=True, methods=["post"])
    def refresh_token(self, request, pk=None):
        # instance = self.get_object()
        # Add your token refresh logic here
        return Response({"status": "token refreshed"})


class TOTPAuthFilter(filters.FilterSet):
    class Meta:
        model = TOTPAuth
        fields = {
            "device_name": ["exact", "contains"],
            "is_active": ["exact"],
            "last_used_at": ["gte", "lte"],
        }


class TOTPAuthViewSet(BaseAuthViewSet):
    queryset = TOTPAuth.objects.all()
    serializer_class = TOTPAuthSerializer
    filterset_class = TOTPAuthFilter
    search_fields = ["device_name"]
    ordering_fields = ["device_name", "created_at", "last_used_at"]

    @action(detail=True, methods=["post"])
    def verify_totp(self, request, pk=None):
        # Add your TOTP verification logic here
        return Response({"status": "TOTP verified"})


class MagicLinkAuthFilter(filters.FilterSet):
    class Meta:
        model = MagicLinkAuth
        fields = {
            "is_active": ["exact"],
            "expires_at": ["gte", "lte"],
        }


class MagicLinkAuthViewSet(BaseAuthViewSet):
    queryset = MagicLinkAuth.objects.all()
    serializer_class = MagicLinkAuthSerializer
    filterset_class = MagicLinkAuthFilter
    ordering_fields = ["created_at", "expires_at"]

    @action(detail=True, methods=["post"])
    def verify_link(self, request, pk=None):
        instance = self.get_object()
        if instance.is_expired():
            return Response(
                {"error": "Link has expired"}, status=status.HTTP_400_BAD_REQUEST
            )
        instance.is_verified = True
        instance.save()
        return Response({"status": "link verified"})
