from django_filters import rest_framework as filters
from rest_framework.decorators import action
from rest_framework.response import Response

from django_authx.models import Session
from django_authx.serializers import SessionSerializer
from .base import BaseAuthViewSet


class SessionFilter(filters.FilterSet):
    class Meta:
        model = Session
        fields = {
            "client_name": ["exact", "contains"],
            "auth_backend": ["exact"],
            "ip_address": ["exact"],
            "location": ["exact", "contains"],
            "is_active": ["exact"],
            "created_at": ["gte", "lte"],
            "last_activity": ["gte", "lte"],
        }


class SessionViewSet(BaseAuthViewSet):
    queryset = Session.objects.all()
    serializer_class = SessionSerializer
    filterset_class = SessionFilter
    search_fields = ["client_name", "location", "auth_backend"]
    ordering_fields = ["created_at", "last_activity", "expires_at"]

    @action(detail=True, methods=["post"])
    def revoke(self, request, pk=None):
        instance = self.get_object()
        instance.is_active = False
        instance.save()
        return Response({"status": "session revoked"})

    @action(detail=True, methods=["post"])
    def renew(self, request, pk=None):
        instance = self.get_object()
        new_expiry = instance.renew_token(request)
        return Response({"status": "session renewed", "expires_at": new_expiry})
