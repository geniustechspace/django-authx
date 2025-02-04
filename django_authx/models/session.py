import logging

from asgiref.sync import sync_to_async

from django.core.exceptions import SuspiciousOperation
from django.db import DatabaseError, IntegrityError, models, router, transaction
from django.conf import settings
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.translation import gettext_lazy as _
from django.contrib.sessions.backends.base import CreateError, SessionBase, UpdateError
from django_authx.dependencies import humanize
from django_authx.settings import authx_settings

from . import base


class BaseSessionManager(models.Manager):
    def encode(self, session_dict):
        """
        Return the given session dictionary serialized and encoded as a string.
        """
        session_store_class = self.model.get_session_store_class()
        return session_store_class().encode(session_dict)

    def save(self, session_key, session_dict, expires_at):
        s = self.model(session_key, self.encode(session_dict), expires_at)
        if session_dict:
            s.save()
        else:
            s.delete()  # Clear sessions with no data.
        return s


class AbstractBaseSession(models.Model):
    session_key = models.CharField(_("session key"), max_length=40, primary_key=True)
    session_data = models.TextField(_("session data"))
    expires_at = models.DateTimeField(_("expires at"), db_index=True)
    remember_session = models.BooleanField(default=False, db_index=True)

    objects = BaseSessionManager()

    class Meta:
        abstract = True
        verbose_name = _("session")
        verbose_name_plural = _("sessions")

    @property
    def expires_in(self) -> str:
        """
        Dynamic property that gives the :py:attr:`~expiry`
        attribute in human readable string format.

        Uses `humanize package <https://github.com/jmoiron/humanize>`__.
        """
        if self.expires_at:
            td = self.expires_at - self.created_at
            return humanize.naturaldelta(td)
        return "N/A"

    @property
    def has_expired(self) -> bool:
        """
        Dynamic property that returns ``True`` if token has expired,
        otherwise ``False``.
        """
        return timezone.now() > self.expires_at

    def __str__(self):
        return self.session_key

    @classmethod
    def get_session_store_class(cls):
        raise NotImplementedError

    def get_decoded(self):
        session_store_class = self.get_session_store_class()
        return session_store_class().decode(self.session_data)


class SessionManager(BaseSessionManager):
    use_in_migrations = True


class Session(base.BaseAuthModel, AbstractBaseSession):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="sessions",
    )

    #: Token Time To Live (TTL) in timedelta. Format: ``DAYS HH:MM:SS``.
    token_ttl = models.DurationField(
        null=False,
        default=authx_settings.DEFAULT_TOKEN_TTL,
        verbose_name=_("Token Time To Live (TTL)"),
        help_text=_(
            """
            Token Time To Live (TTL) in timedelta. Format: <code>DAYS HH:MM:SS</code>.
            """
        ),
    )

    #: Token string
    refresh_token = models.CharField(
        _("refresh token"),
        max_length=authx_settings.TOKEN_CHARACTER_LENGTH,
        null=False,
        blank=False,
        db_index=True,
        unique=True,
        help_text=_("Refresh Token is auto-generated on save."),
    )

    #: Throttle rate for requests with this session.
    throttle_rate = models.CharField(
        max_length=64,
        default="",
        blank=True,
        verbose_name=_("Throttle rate for requests with this session"),
        help_text=_(
            """Follows the same format as DRF's throttle rates.
            Format: <em>'number_of_requests/period'</em>
            where period should be one of: ('s', 'm', 'h', 'd').
            Example: '100/h' implies 100 requests each hour.
            """
        ),
        # validators=[validate_client_throttle_rate],
    )

    auth_backend = models.CharField(_("auth backend"), max_length=126, db_index=True)

    client_name = models.CharField(_("client name"), max_length=255, db_index=True)

    ip_address = models.GenericIPAddressField(_("IP address"), db_index=True)

    location = models.CharField(_("location"), max_length=255, db_index=True)

    last_activity = models.DateTimeField(
        _("last activity"), default=timezone.now, db_index=True
    )

    objects = SessionManager()

    class Meta:
        db_table = "sessions_model"
        verbose_name = _("Session")
        verbose_name_plural = _("Sessions")
        indexes = [
            models.Index(fields=["user", "auth_backend"]),
            models.Index(fields=["user", "auth_backend", "is_active"]),
            models.Index(fields=["client_name", "ip_address"]),
        ]
        constraints = [
            models.CheckConstraint(
                check=models.Q(expires_at__gt=models.F("created_at")),
                name="session_expiry_after_creation",
            )
        ]

    def __str__(self):
        td = humanize.naturaldelta(self.token_ttl)
        rate = self.throttle_rate or "0/s"
        return "({0}: {1}, {2})".format(self.client_name, td, rate)

    def __repr__(self) -> str:
        return "({0}, {1}/{2})".format(
            self.token, self.user.get_username(), self.client_name
        )

    @classmethod
    def get_session_store_class(cls):
        return SessionStore

    def renew_token(self, request=None) -> "timezone.datetime":
        """
        Utility function to renew the token.

        Updates the :py:attr:`~expiry` attribute by ``Client.token_ttl``.
        """
        new_expiry = timezone.now() + self.token_ttl
        self.expires_at = new_expiry
        self.save(update_fields=("expires_at",))
        return new_expiry


class SessionStore(SessionBase):
    """
    Implement database session store.
    """

    def __init__(self, session_key=None):
        super().__init__(session_key)

    @cached_property
    def model(self):
        return Session

    def _get_session_from_db(self):
        try:
            return self.model.objects.get(
                session_key=self.session_key, expires_at__gt=timezone.now()
            )
        except (self.model.DoesNotExist, SuspiciousOperation) as e:
            if isinstance(e, SuspiciousOperation):
                logger = logging.getLogger("django.security.%s" % e.__class__.__name__)
                logger.warning(str(e))
            self._session_key = None

    async def _aget_session_from_db(self):
        try:
            return await self.model.objects.aget(
                session_key=self.session_key, expires_at__gt=timezone.now()
            )
        except (self.model.DoesNotExist, SuspiciousOperation) as e:
            if isinstance(e, SuspiciousOperation):
                logger = logging.getLogger("django.security.%s" % e.__class__.__name__)
                logger.warning(str(e))
            self._session_key = None

    def load(self):
        s = self._get_session_from_db()
        return self.decode(s) if s else {}

    async def aload(self):
        s = await self._aget_session_from_db()
        return self.decode(s.session_data) if s else {}

    def exists(self, session_key):
        return self.model.objects.filter(session_key=session_key).exists()

    async def aexists(self, session_key):
        return await self.model.objects.filter(session_key=session_key).aexists()

    def create(self):
        while True:
            self._session_key = self._get_new_session_key()
            try:
                # Save immediately to ensure we have a unique entry in the
                # database.
                self.save(must_create=True)
            except CreateError:
                # Key wasn't unique. Try again.
                continue
            self.modified = True
            return

    async def acreate(self):
        while True:
            self._session_key = await self._aget_new_session_key()
            try:
                # Save immediately to ensure we have a unique entry in the
                # database.
                await self.asave(must_create=True)
            except CreateError:
                # Key wasn't unique. Try again.
                continue
            self.modified = True
            return

    def create_model_instance(self, data):
        """
        Return a new instance of the session model object, which represents the
        current session state. Intended to be used for saving the session data
        to the database.
        """
        return self.model(
            session_key=self._get_or_create_session_key(),
            session_data=self.encode(data),
            expires_at=self.get_expiry_date(),
        )

    async def acreate_model_instance(self, data):
        """See create_model_instance()."""
        return self.model(
            session_key=await self._aget_or_create_session_key(),
            session_data=self.encode(data),
            expires_at=await self.aget_expiry_date(),
        )

    def save(self, must_create=False):
        """
        Save the current session data to the database. If 'must_create' is
        True, raise a database error if the saving operation doesn't create a
        new entry (as opposed to possibly updating an existing entry).
        """
        if self.session_key is None:
            return self.create()
        data = self._get_session(no_load=must_create)
        obj = self.create_model_instance(data)
        using = router.db_for_write(self.model, instance=obj)
        try:
            with transaction.atomic(using=using):
                obj.save(
                    force_insert=must_create, force_update=not must_create, using=using
                )
        except IntegrityError:
            if must_create:
                raise CreateError
            raise
        except DatabaseError:
            if not must_create:
                raise UpdateError
            raise

    async def asave(self, must_create=False):
        """See save()."""
        if self.session_key is None:
            return await self.acreate()
        data = await self._aget_session(no_load=must_create)
        obj = await self.acreate_model_instance(data)
        using = router.db_for_write(self.model, instance=obj)
        try:
            # This code MOST run in a transaction, so it requires
            # @sync_to_async wrapping until transaction.atomic() supports
            # async.
            @sync_to_async
            def sync_transaction():
                with transaction.atomic(using=using):
                    obj.save(
                        force_insert=must_create,
                        force_update=not must_create,
                        using=using,
                    )

            await sync_transaction()
        except IntegrityError:
            if must_create:
                raise CreateError
            raise
        except DatabaseError:
            if not must_create:
                raise UpdateError
            raise

    def delete(self, session_key=None):
        if session_key is None:
            if self.session_key is None:
                return
            session_key = self.session_key
        try:
            self.model.objects.get(session_key=session_key).delete()
        except self.model.DoesNotExist:
            pass

    async def adelete(self, session_key=None):
        if session_key is None:
            if self.session_key is None:
                return
            session_key = self.session_key
        try:
            obj = await self.model.objects.aget(session_key=session_key)
            await obj.adelete()
        except self.model.DoesNotExist:
            pass

    @classmethod
    def clear_expired(cls):
        Session.objects.filter(expires_at__lt=timezone.now()).delete()

    @classmethod
    async def aclear_expired(cls):
        await Session.objects.filter(expires_at__lt=timezone.now()).adelete()
