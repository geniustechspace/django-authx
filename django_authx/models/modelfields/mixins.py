"""Django model field encryption utilities.

This module provides encryption capabilities for Django model fields using the Fernet
encryption scheme. Implementation based on Django Encrypted Model Fields
(https://github.com/lanshark/django-encrypted-model-fields).

Provides:
    - Key parsing and cryptographic setup
    - String encryption/decryption utilities
    - EncryptedMixin for creating encrypted model fields
"""

from typing import Union
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
import cryptography.fernet


def parse_key(key: Union[str, bytes]) -> cryptography.fernet.Fernet:
    """Parse encryption key into Fernet instance

    Args:
        key: The encryption key as string or bytes
    Returns:
        Fernet instance for encryption/decryption
    Raises:
        ImproperlyConfigured: If key is invalid
    """
    return cryptography.fernet.Fernet(key)


def get_crypter() -> cryptography.fernet.MultiFernet:
    """Initialize the cryptography engine with configured keys

    Returns:
        MultiFernet instance for encryption/decryption
    Raises:
        ImproperlyConfigured: If keys are missing or invalid
    """
    configured_keys = getattr(settings, "FIELD_ENCRYPTION_KEY", None)

    if configured_keys is None:
        raise ImproperlyConfigured("FIELD_ENCRYPTION_KEY must be defined in settings")

    try:
        keys = (
            [parse_key(k) for k in configured_keys]
            if isinstance(configured_keys, (tuple, list))
            else [parse_key(configured_keys)]
        )
    except Exception as e:
        raise ImproperlyConfigured(
            f"FIELD_ENCRYPTION_KEY defined incorrectly: {str(e)}"
        )

    if not keys:
        raise ImproperlyConfigured("No keys defined in setting FIELD_ENCRYPTION_KEY")

    return cryptography.fernet.MultiFernet(keys)


CRYPTER = get_crypter()


def encrypt_str(s: str) -> bytes:
    """Encrypt a string using the configured Fernet instance.

    Args:
        s: String to encrypt

    Returns:
        Encrypted bytes
    """
    # be sure to encode the string to bytes
    return CRYPTER.encrypt(s.encode("utf-8"))


def decrypt_str(t: str) -> str:
    """Decrypt a previously encrypted string.

    Args:
        t: Encrypted string to decrypt

    Returns:
        Decrypted string

    Raises:
        cryptography.fernet.InvalidToken: If decryption fails
    """
    # be sure to decode the bytes to a string
    return CRYPTER.decrypt(t.encode("utf-8")).decode("utf-8")


def calc_encrypted_length(n: int) -> int:
    """Calculate the storage length needed for an encrypted string.

    Args:
        n: Length of original string in bytes

    Returns:
        Length needed to store encrypted version
    """
    # calculates the characters necessary to hold an encrypted string of n bytes
    return len(encrypt_str("a" * n))


class EncryptedMixin(object):
    """Mixin class to add encryption capabilities to Django model fields.

    Provides transparent encryption/decryption of field values when reading from
    or writing to the database. Uses the configured FIELD_ENCRYPTION_KEY for
    cryptographic operations.
    """

    def to_python(self, value):
        """Convert the database value to a Python object.

        Args:
            value: Value from database

        Returns:
            Decrypted Python value
        """
        if value is None:
            return value

        if isinstance(value, (bytes, str)):
            if isinstance(value, bytes):
                value = value.decode("utf-8")
            try:
                value = decrypt_str(value)
            except cryptography.fernet.InvalidToken:
                pass

        return super(EncryptedMixin, self).to_python(value)

    def from_db_value(self, value, *args, **kwargs):
        """Convert database value to Python object on database load.

        Args:
            value: Value from database
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments

        Returns:
            Decrypted Python value
        """
        return self.to_python(value)

    def get_db_prep_save(self, value, connection):
        """Prepare value for database storage.

        Args:
            value: Python value to encrypt
            connection: Database connection

        Returns:
            Encrypted value ready for storage
        """
        value = super(EncryptedMixin, self).get_db_prep_save(value, connection)

        if value is None:
            return value
        # decode the encrypted value to a unicode string, else this breaks in pgsql
        return (encrypt_str(str(value))).decode("utf-8")

    def get_internal_type(self):
        """Get the database column type.

        Returns:
            str: Always 'TextField' since encrypted values are stored as text
        """
        return "TextField"

    def deconstruct(self):
        name, path, args, kwargs = super(EncryptedMixin, self).deconstruct()

        if "max_length" in kwargs:
            del kwargs["max_length"]

        return name, path, args, kwargs
