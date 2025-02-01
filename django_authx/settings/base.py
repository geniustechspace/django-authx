from typing import Any, Union, get_args, get_origin
from django.conf import settings as django_settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string


class BaseSettings:
    """
    Base class for managing settings with type-safe defaults and dynamic loading.
    """

    _settings: dict = {}

    def __init__(
        self, settings_key: str = "AUTHX_SETTINGS", import_strings: set[str] = set()
    ):
        self.settings_key = settings_key
        self.import_strings = import_strings
        self.reload()

    def reload(self):
        """
        Reloads settings by merging user-defined settings with defaults.
        """
        # Load user settings from Django
        # Load settings based on the settings_key
        user_settings = getattr(django_settings, self.settings_key, {})

        if not isinstance(user_settings, dict):
            raise ImproperlyConfigured(f"{user_settings} must be a dictionary.")

        # Merge defaults with user settings
        self._settings.update(user_settings)

        # Validate and set attributes dynamically
        self.validate_settings()

    def validate_settings(self):
        """
        Validates the settings based on their default types.
        """
        errors = {}
        for key, value in self._settings.items():
            expected_type = self.__annotations__.get(key)
            if not self._is_union_compatible(value, expected_type):
                errors[key] = (
                    f"Invalid type for '{key}': Expected {expected_type.__name__}, "
                    f"got {type(value).__name__}."
                )
        if errors:
            raise ImproperlyConfigured(
                "\n".join(f"{k}: {v}" for k, v in errors.items())
            )

    def _is_union_compatible(self, value: Any, expected_type: Any) -> bool:
        """
        Checks compatibility for Union and Optional types.
        """
        # Handle Union types (including Optional, which is Union[None, ...])
        if get_origin(expected_type) is Union:
            return any(self._is_type_match(value, t) for t in get_args(expected_type))

        # Handle non-Union types
        return self._is_type_match(value, expected_type)

    def _is_type_match(self, value: Any, expected_type: Any) -> bool:
        """
        Checks if the value matches the expected type, accounting for parameterized generics.
        """
        origin_type = get_origin(expected_type)
        if origin_type:  # If it's a generic type like List, Dict, etc.
            return isinstance(value, origin_type)
        return isinstance(value, expected_type)

    def __getattr__(self, name: str):
        """
        Provides dynamic attribute access.
        """
        if name in self._settings:
            print(f"GETTING {name} ...")
            val = self._settings[name]
            if name in self.import_strings:
                print(f"IMPORTING {name} ...")
                return import_string(val)
            return val
        raise AttributeError(f"'{name}' is not a valid setting.")

    @classmethod
    def initialize_class(cls):
        """
        Initializes the DEFAULTS dictionary using type hints and class attributes.
        """

        cls_attrs = {
            key: value
            for key, value in cls.__dict__.items()
            if not key.startswith("_") and not callable(value)
        }

        cls._settings.update(cls_attrs)

        cls.__annotations__.update(
            {
                key: type(value)
                for key, value in cls_attrs.items()
                if key not in cls.__annotations__
            }
        )

    def __init_subclass__(cls):
        cls.initialize_class()
