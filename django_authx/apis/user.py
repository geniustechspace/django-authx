from django.contrib.auth import get_user_model
# from django.contrib.auth.models import update_last_login
from django_filters import rest_framework as filters
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response

from django_authx.serializers.user import AuthXUserSerializer

User = get_user_model()


class UserFilter(filters.FilterSet):
    class Meta:
        model = User
        fields = {
            "username": ["exact", "contains"],
            "email": ["exact", "contains"],
            "first_name": ["exact", "contains"],
            "last_name": ["exact", "contains"],
            "is_active": ["exact"],
            "is_staff": ["exact"],
            "date_joined": ["gte", "lte"],
            "last_login": ["gte", "lte"],
        }


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = AuthXUserSerializer
    filterset_class = UserFilter
    permission_classes = [IsAdminUser]
    search_fields = ["username", "email", "first_name", "last_name"]
    ordering_fields = ["username", "email", "date_joined", "last_login"]

    @action(detail=True, methods=["post"], permission_classes=[IsAdminUser])
    def activate(self, request, pk=None):
        user = self.get_object()
        user.is_active = True
        user.save()
        return Response({"status": "user activated"})

    @action(detail=True, methods=["post"], permission_classes=[IsAdminUser])
    def deactivate(self, request, pk=None):
        user = self.get_object()
        user.is_active = False
        user.save()
        return Response({"status": "user deactivated"})

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def change_password(self, request, pk=None):
        user = self.get_object()
        if user != request.user and not request.user.is_staff:
            return Response(
                {"error": "Not permitted"}, status=status.HTTP_403_FORBIDDEN
            )

        # serializer = ChangePasswordSerializer(data=request.data)
        # if serializer.is_valid():
        #     user.set_password(serializer.validated_data["new_password"])
        #     user.save()
        #     update_last_login(None, user)
        #     return Response({"status": "password changed"})
        # return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({}, status=status.HTTP_400_BAD_REQUEST)
