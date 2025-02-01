# from rest_framework import serializers

from django_authx.models import EmailAuth, PhoneAuth, OAuth2Auth, TOTPAuth, MagicLinkAuth
from django_authx.fields import serializerfields

from .base import BaseAuthSerializer


class EmailAuthSerializer(BaseAuthSerializer):
    class Meta(BaseAuthSerializer.Meta):
        model = EmailAuth
        fields = BaseAuthSerializer.Meta.fields + ("email",)


class PhoneAuthSerializer(BaseAuthSerializer):
    phone = serializerfields.PhoneNumberField()

    class Meta(BaseAuthSerializer.Meta):
        model = PhoneAuth
        fields = BaseAuthSerializer.Meta.fields + ("phone",)


class OAuth2AuthSerializer(BaseAuthSerializer):
    class Meta(BaseAuthSerializer.Meta):
        model = OAuth2Auth
        fields = BaseAuthSerializer.Meta.fields + (
            "provider",
            "provider_id",
            "access_token",
            "refresh_token",
            "expires_at",
            "scope",
        )
        extra_kwargs = {
            "access_token": {"write_only": True},
            "refresh_token": {"write_only": True},
        }


class TOTPAuthSerializer(BaseAuthSerializer):
    class Meta(BaseAuthSerializer.Meta):
        model = TOTPAuth
        fields = BaseAuthSerializer.Meta.fields + (
            "secret_key",
            "backup_codes",
            "last_used_at",
            "device_name",
            "recovery_codes",
        )
        extra_kwargs = {
            "secret_key": {"write_only": True},
            "backup_codes": {"write_only": True},
            "recovery_codes": {"write_only": True},
        }


class MagicLinkAuthSerializer(BaseAuthSerializer):
    class Meta(BaseAuthSerializer.Meta):
        model = MagicLinkAuth
        fields = BaseAuthSerializer.Meta.fields + ("token", "session", "expires_at")
        extra_kwargs = {"token": {"read_only": True}}
