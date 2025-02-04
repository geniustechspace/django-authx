from django.contrib import admin
from django.contrib.admin import widgets
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from django.utils import timezone

from . import models


class BaseAuthAdmin(admin.ModelAdmin):
    readonly_fields = ("created_at", "updated_at", "deleted_at")
    ordering = ("-created_at",)

    def get_status_display(self, obj, check_method):
        if getattr(obj, check_method)():
            return format_html('<span class="badge badge-danger">Expired</span>')
        return format_html('<span class="badge badge-success">Active</span>')

    class Media:
        css = {"all": ("admin/css/authx_admin.css",)}


@admin.register(models.Session)
class SessionAdmin(BaseAuthAdmin):
    list_display = (
        "session_key",
        "user",
        "client_info",
        "status_display",
        "expires_in_display",
        "last_activity",
    )
    list_filter = (
        ("is_active", admin.BooleanFieldListFilter),
        ("auth_backend", admin.ChoicesFieldListFilter),
        ("created_at", admin.DateFieldListFilter),
    )
    search_fields = ("session_key", "user__email", "client_name", "ip_address")

    fieldsets = (
        (
            _("Session Details"),
            {
                "fields": (
                    ("session_key", "user"),
                    ("client_name", "ip_address"),
                    ("is_active", "remember_session"),
                )
            },
        ),
        (
            _("Security"),
            {
                "fields": (
                    "auth_backend",
                    ("refresh_token"),
                    "token_ttl",
                    "throttle_rate",
                ),
                "classes": ("collapse",),
            },
        ),
        (
            _("Timestamps"),
            {
                "fields": (
                    ("created_at", "last_activity"),
                    ("expires_at", "deleted_at"),
                ),
                "classes": ("collapse",),
            },
        ),
    )

    def client_info(self, obj):
        return format_html(
            '<div class="client-info">'
            "<strong>{}</strong><br>"
            "<small>{}</small>"
            "</div>",
            obj.client_name,
            obj.ip_address,
        )

    client_info.short_description = _("Client Details")

    def status_display(self, obj):
        return self.get_status_display(obj, "has_expired")

    status_display.short_description = _("Status")

    actions = ["renew_sessions", "terminate_sessions", "clear_expired_sessions"]

    @admin.action(description=_("Clear expired sessions"))
    def clear_expired_sessions(self, request, queryset):
        expired = queryset.filter(expires_at__lt=timezone.now())
        count = expired.count()
        expired.delete()
        self.message_user(request, f"Cleared {count} expired sessions")

    def renew_sessions(self, request, queryset):
        for session in queryset:
            session.renew_token()
        self.message_user(request, f"Successfully renewed {queryset.count()} sessions.")

    renew_sessions.short_description = _("Renew selected sessions")

    def terminate_sessions(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(
            request, f"Successfully terminated {queryset.count()} sessions."
        )

    terminate_sessions.short_description = _("Terminate selected sessions")

    def expires_in_display(self, obj):
        if obj.has_expired:
            return format_html('<span style="color: red;">Expired</span>')
        return obj.expires_in

    expires_in_display.short_description = _("Expires in")


@admin.register(models.EmailAuth)
class EmailAuthAdmin(BaseAuthAdmin):
    list_display = ("email", "user", "verification_status", "created_at")
    list_filter = (
        "is_verified",
        "is_active",
        ("created_at", admin.DateFieldListFilter),
    )
    search_fields = ("email", "user__email")

    def verification_status(self, obj):
        return format_html(
            '<span class="badge badge-{}">{}</span>',
            "success" if obj.is_verified else "warning",
            _("Verified") if obj.is_verified else _("Pending"),
        )

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        form.base_fields["metadata"].widget = widgets.AdminTextareaWidget(
            attrs={"rows": 3, "cols": 40}
        )
        return form


@admin.register(models.PhoneAuth)
class PhoneAuthAdmin(BaseAuthAdmin):
    list_display = ("phone", "user", "is_active", "is_verified", "created_at")
    list_filter = ("is_active", "is_verified")
    search_fields = ("phone", "user__email")
    raw_id_fields = ("user",)
    readonly_fields = ("created_at", "updated_at", "deleted_at")
    date_hierarchy = "created_at"

    fieldsets = (
        (
            None,
            {
                "fields": ("phone", "user"),
            },
        ),
        (
            _("Status"),
            {"fields": (("is_active", "is_verified"),), "classes": ("wide",)},
        ),
        (_("Metadata"), {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            _("Timestamps"),
            {
                "fields": (("created_at", "updated_at", "deleted_at"),),
                "classes": ("collapse",),
            },
        ),
    )


@admin.register(models.OAuth2Auth)
class OAuth2AuthAdmin(BaseAuthAdmin):
    list_display = (
        "user",
        "provider",
        "provider_id",
        "is_active",
        "expires_at",
        "token_status",
    )
    list_filter = ("provider", "is_active")
    search_fields = ("user__email", "provider_id")
    raw_id_fields = ("user",)
    readonly_fields = ("created_at", "updated_at", "deleted_at")
    date_hierarchy = "created_at"

    fieldsets = (
        (
            _("Provider Info"),
            {
                "fields": (
                    "provider",
                    "provider_id",
                    "user",
                    ("is_active", "is_verified"),
                ),
            },
        ),
        (
            _("OAuth Tokens"),
            {
                "fields": ("access_token", "refresh_token", "expires_at", "scope"),
                "classes": ("collapse",),
            },
        ),
        (_("Metadata"), {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            _("Timestamps"),
            {
                "fields": (
                    ("created_at", "updated_at", "deleted_at"),
                    # ("last_used", "deleted_at"),
                ),
                "classes": ("collapse",),
            },
        ),
    )

    def token_status(self, obj):
        if obj.is_expired():
            return format_html('<span style="color: red;">Expired</span>')
        return format_html('<span style="color: green;">Valid</span>')

    token_status.short_description = _("Token Status")

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        form.base_fields["scope"].widget = widgets.AdminTextareaWidget(
            attrs={"rows": 2}
        )
        return form


@admin.register(models.MagicLinkAuth)
class MagicLinkAuthAdmin(BaseAuthAdmin):
    list_display = ("user", "token", "is_active", "expires_at", "link_status")
    list_filter = ("is_active",)
    search_fields = ("user__email", "token")
    raw_id_fields = ("user", "session")
    readonly_fields = ("created_at", "updated_at", "deleted_at", "token")
    date_hierarchy = "created_at"

    fieldsets = (
        (
            _("Link Info"),
            {
                "fields": ("user", "session", ("is_active", "is_verified")),
            },
        ),
        (_("Token"), {"fields": ("token", "expires_at"), "classes": ("wide",)}),
        (_("Metadata"), {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            _("Timestamps"),
            {
                "fields": (
                    ("created_at", "updated_at", "deleted_at"),
                    # ("last_used", "deleted_at"),
                ),
                "classes": ("collapse",),
            },
        ),
    )

    actions = ["invalidate_links"]

    def invalidate_links(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(
            request, f"Successfully invalidated {queryset.count()} magic links."
        )

    invalidate_links.short_description = _("Invalidate selected magic links")

    def link_status(self, obj):
        if obj.is_expired():
            return format_html('<span style="color: red;">Expired</span>')
        return format_html('<span style="color: green;">Valid</span>')

    link_status.short_description = _("Link Status")


@admin.register(models.TOTPAuth)
class TOTPAuthAdmin(BaseAuthAdmin):
    list_display = (
        "user",
        "device_name",
        "is_active",
        "is_verified",
        "last_used_at",
    )
    list_filter = ("is_active", "is_verified")
    search_fields = ("user__email", "device_name")
    raw_id_fields = ("user",)
    readonly_fields = (
        "created_at",
        "updated_at",
        "deleted_at",
        "secret_key",
        "backup_codes",
        "recovery_codes",
    )
    date_hierarchy = "created_at"

    fieldsets = (
        (
            _("Device Info"),
            {
                "fields": ("user", "device_name", ("is_active", "is_verified")),
            },
        ),
        (
            _("TOTP Settings"),
            {
                "fields": ("secret_key",),
                "classes": ("collapse",),
                "description": _("Warning: Secret key should never be shared."),
            },
        ),
        (
            _("Backup & Recovery"),
            {"fields": ("backup_codes", "recovery_codes"), "classes": ("collapse",)},
        ),
        (_("Metadata"), {"fields": ("metadata",), "classes": ("collapse",)}),
        (
            _("Timestamps"),
            {
                "fields": (
                    ("created_at", "updated_at"),
                    # ("last_used", "last_used_at"),
                    "deleted_at",
                ),
                "classes": ("collapse",),
            },
        ),
    )

    actions = ["disable_devices"]

    def disable_devices(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(
            request, f"Successfully disabled {queryset.count()} TOTP devices."
        )

    disable_devices.short_description = _("Disable selected TOTP devices")

    def get_fields(self, request, obj=None):
        fields = super().get_fields(request, obj)
        if obj is None:  # Adding new object
            fields = [f for f in fields if f not in self.readonly_fields]
        return fields

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        if obj:  # Only for existing objects
            form.base_fields["backup_codes"].widget = widgets.AdminTextareaWidget(
                attrs={"rows": 3, "readonly": "readonly"}
            )
            form.base_fields["recovery_codes"].widget = widgets.AdminTextareaWidget(
                attrs={"rows": 3, "readonly": "readonly"}
            )
        return form
