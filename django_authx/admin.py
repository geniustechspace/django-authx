from django.contrib import admin
from django.contrib.admin import widgets
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from . import models


@admin.register(models.Session)
class SessionAdmin(admin.ModelAdmin):
    list_display = (
        "session_id",
        "user",
        "client_name",
        "ip_address",
        "last_activity",
        "is_active",
        "expires_in_display",
    )
    list_filter = ("is_active", "auth_backend", "client_name", "remember_session")
    search_fields = (
        "session_id",
        "user__email",
        "client_name",
        "ip_address",
        "location",
    )
    readonly_fields = ("session_id", "created_at", "updated_at", "deleted_at")
    raw_id_fields = ("user",)
    date_hierarchy = "created_at"
    ordering = ("-last_activity",)

    fieldsets = (
        (
            _("Session Info"),
            {
                "fields": (
                    "session_id",
                    "user",
                    "client_name",
                    ("is_active", "remember_session"),
                ),
                "classes": ("wide",),
            },
        ),
        (
            _("Location Data"),
            {
                "fields": ("ip_address", "location"),
            },
        ),
        (
            _("Authentication"),
            {
                "fields": ("auth_backend", "token", "token_ttl", "throttle_rate"),
                "classes": ("collapse",),
            },
        ),
        (
            _("Timestamps"),
            {
                "fields": (
                    ("created_at", "updated_at"),
                    ("last_activity", "expires_at"),
                    "deleted_at",
                ),
                "classes": ("collapse",),
            },
        ),
    )

    actions = ["renew_sessions", "terminate_sessions"]

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
class EmailAuthAdmin(admin.ModelAdmin):
    list_display = ("email", "user", "is_active", "is_verified", "created_at")
    list_filter = ("is_active", "is_verified")
    search_fields = ("email", "user__email")
    raw_id_fields = ("user",)
    readonly_fields = ("created_at", "updated_at", "deleted_at")
    date_hierarchy = "created_at"

    fieldsets = (
        (
            None,
            {
                "fields": ("email", "user"),
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
                "fields": (
                    ("created_at", "updated_at", "deleted_at"),
                    # ("last_used", "deleted_at"),
                ),
                "classes": ("collapse",),
            },
        ),
    )

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        form.base_fields["metadata"].widget = widgets.AdminTextareaWidget(
            attrs={"rows": 3, "cols": 40}
        )
        return form


@admin.register(models.PhoneAuth)
class PhoneAuthAdmin(admin.ModelAdmin):
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
                "fields": (
                    ("created_at", "updated_at", "deleted_at"),
                ),
                "classes": ("collapse",),
            },
        ),
    )


@admin.register(models.OAuth2Auth)
class OAuth2AuthAdmin(admin.ModelAdmin):
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
class MagicLinkAuthAdmin(admin.ModelAdmin):
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
class TOTPAuthAdmin(admin.ModelAdmin):
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
