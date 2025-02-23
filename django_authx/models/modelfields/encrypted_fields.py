import itertools

import django.db
import django.db.models
from django.conf import settings
from django.core import validators
from django.utils import timezone
from django.utils.functional import cached_property


from .mixins import EncryptedMixin, encrypt_str


class EncryptedCharField(EncryptedMixin, django.db.models.CharField):
    pass


class EncryptedTextField(EncryptedMixin, django.db.models.TextField):
    pass


class EncryptedDateField(EncryptedMixin, django.db.models.DateField):
    pass


class EncryptedDateTimeField(EncryptedMixin, django.db.models.DateTimeField):
    # credit to Oleg Pesok...
    def to_python(self, value):
        value = super(EncryptedDateTimeField, self).to_python(value)

        if value is not None and settings.USE_TZ and timezone.is_naive(value):
            default_timezone = timezone.get_default_timezone()
            value = timezone.make_aware(value, default_timezone)

        return value


class EncryptedEmailField(EncryptedMixin, django.db.models.EmailField):
    pass


class EncryptedBooleanField(EncryptedMixin, django.db.models.BooleanField):

    def get_db_prep_save(self, value, connection):
        if value is None:
            return value
        if value is True:
            value = "1"
        elif value is False:
            value = "0"
        # decode the encrypted value to a unicode string, else this breaks in pgsql
        return encrypt_str(str(value)).decode("utf-8")


class EncryptedNumberMixin(EncryptedMixin):
    max_length = 20

    @cached_property
    def validators(self):
        # These validators can't be added at field initialization time since
        # they're based on values retrieved from `connection`.
        range_validators = []
        internal_type = self.__class__.__name__[9:]
        min_value, max_value = django.db.connection.ops.integer_field_range(
            internal_type
        )
        if min_value is not None:
            range_validators.append(validators.MinValueValidator(min_value))
        if max_value is not None:
            range_validators.append(validators.MaxValueValidator(max_value))
        return list(
            itertools.chain(self.default_validators, self._validators, range_validators)
        )


class EncryptedIntegerField(EncryptedNumberMixin, django.db.models.IntegerField):
    description = (
        "An IntegerField that is encrypted before "
        "inserting into a database using the python cryptography "
        "library"
    )
    pass


class EncryptedPositiveIntegerField(
    EncryptedNumberMixin, django.db.models.PositiveIntegerField
):
    pass


class EncryptedSmallIntegerField(
    EncryptedNumberMixin, django.db.models.SmallIntegerField
):
    pass


class EncryptedPositiveSmallIntegerField(
    EncryptedNumberMixin, django.db.models.PositiveSmallIntegerField
):
    pass


class EncryptedBigIntegerField(EncryptedNumberMixin, django.db.models.BigIntegerField):
    pass
