from django.contrib.auth import get_user_model

# from django.contrib.auth.models import AbstractBaseUser
from django.db import transaction
from rest_framework import serializers

from django_authx.models import EmailAuth, PhoneAuth
from django_authx.settings import authx_settings

from . import serializerfields

UserModel = get_user_model()


class AuthXUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=False)
    phone = serializerfields.PhoneNumberField(required=False)
    password = serializers.CharField(
        write_only=True, required=True, style={"input_type": "password"}
    )

    class Meta:
        model = UserModel
        fields = ("email", "phone", "password") + tuple(
            (field.name for field in UserModel._meta.local_fields)
        )
        read_only_fields = tuple(
            (
                field.name
                for field in UserModel._meta.local_fields
                if field.auto_created or not field.editable
            )
        ) + (
            "id",
            "password",
            "is_active",
            "is_staff",
            "is_superuser",
            "last_login",
            "date_joined",
        )

    def create(self, validated_data: dict):
        email = (
            validated_data.get(authx_settings.PRIMARY_EMAIL_FIELD, None)
            if authx_settings.PRIMARY_EMAIL_FIELD
            and getattr(UserModel, authx_settings.PRIMARY_EMAIL_FIELD, None)
            else validated_data.pop(authx_settings.PRIMARY_EMAIL_FIELD, None)
        )
        phone = (
            validated_data.get(authx_settings.PRIMARY_PHONE_FIELD, None)
            if authx_settings.PRIMARY_PHONE_FIELD
            and getattr(UserModel, authx_settings.PRIMARY_PHONE_FIELD, None)
            else validated_data.pop(authx_settings.PRIMARY_PHONE_FIELD, None)
        )
        password = validated_data.pop("password")

        print("validated_data:", validated_data)
        print("email:", email)
        print("phone:", phone)
        with transaction.atomic():
            # Create user
            user = super().create(validated_data)
            user.set_password(password)
            user.save()

            # Create email auth if provided
            if email:
                EmailAuth.objects.create(user=user, email=email)

            # Create phone auth if provided
            if phone:
                PhoneAuth.objects.create(user=user, phone=phone)

        return user
