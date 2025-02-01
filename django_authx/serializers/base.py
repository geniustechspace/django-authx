from rest_framework import serializers


class BaseAuthSerializer(serializers.ModelSerializer):
    class Meta:
        abstract = True
        fields = (
            "id",
            "user",
            "is_active",
            "is_verified",
            "last_used",
            "metadata",
            "created_at",
            "updated_at",
        )
        read_only_fields = (
            "id",
            "user",
            "created_at",
            "is_active",
            "is_verified",
            "updated_at",
            "last_used",
        )
