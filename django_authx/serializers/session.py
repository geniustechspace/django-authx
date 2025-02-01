from rest_framework import serializers

from django_authx.models import Session


class SessionSerializer(serializers.ModelSerializer):
    expires_in = serializers.CharField(read_only=True)
    has_expired = serializers.BooleanField(read_only=True)

    class Meta:
        model = Session
        fields = (
            "session_id",
            "user",
            "token",
            "token_ttl",
            "throttle_rate",
            "auth_backend",
            "client_name",
            "ip_address",
            "location",
            "last_activity",
            "expires_at",
            "expires_in",
            "has_expired",
            "remember_session",
            "created_at",
            "updated_at",
        )
        read_only_fields = (
            "session_id",
            "token",
            "created_at",
            "updated_at",
            "last_activity",
        )
