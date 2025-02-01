from django.conf import settings
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class ModelTimeStamped(models.Model):
    created_at = models.DateTimeField(_("created at"), auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(_("updated at"), auto_now=True)
    deleted_at = models.DateTimeField(_("deleted at"), null=True, blank=True)

    class Meta:
        abstract = True

    def soft_delete(self):
        self.deleted_at = timezone.now()
        self.save()

    @property
    def is_deleted(self):
        return self.deleted_at is not None


class BaseAuthModel(ModelTimeStamped):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="%(class)s_auth",
        on_delete=models.CASCADE,
    )
    is_active = models.BooleanField(default=False, db_index=True)
    is_verified = models.BooleanField(default=False, db_index=True)
    last_used = models.DateTimeField(auto_now=True, db_index=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        abstract = True
