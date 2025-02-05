from __future__ import annotations
import logging

from django.core.cache import cache
from django.core.exceptions import SuspiciousOperation
from django.db import DatabaseError, transaction
from django.utils import timezone
from django.contrib.sessions.backends.base import SessionBase, CreateError

from .models import Session

logger = logging.getLogger(__name__)


class SessionStore(SessionBase):
    cache_key_prefix = "django_authx.session"

    def __init__(self, session_key=None):
        super().__init__(session_key)
        self._cache_key = (
            f"{self.cache_key_prefix}:{session_key}" if session_key else None
        )

    def _get_cache(self):
        if self._cache_key:
            return cache.get(self._cache_key)
        return None

    def _set_cache(self, data, timeout):
        if self._cache_key:
            cache.set(self._cache_key, data, timeout)

    def create(self):
        while True:
            self._session_key = self._get_new_session_key()
            try:
                self.save(must_create=True)
            except CreateError:
                continue
            self.modified = True
            return

    def save(self, must_create=False):
        if not self.session_key:
            return self.create()

        session_data = self._get_session(no_load=must_create)
        expires = self.get_expiry_date()

        obj = Session(
            session_key=self.session_key,
            **session_data,
            expires_at=expires,
            is_active=True,
        )

        with transaction.atomic():
            try:
                obj.save(force_insert=must_create)
            except DatabaseError:
                if must_create:
                    raise CreateError
                raise

        self._set_cache(session_data, self.get_expiry_age())

    def delete(self, session_key=None):
        if session_key is None:
            if self.session_key is None:
                return
            session_key = self.session_key

        cache.delete(f"{self.cache_key_prefix}:{session_key}")
        try:
            Session.objects.filter(session_key=session_key).update(is_active=False)
        except Session.DoesNotExist:
            pass

    def load(self):
        data = self._get_cache()
        if data is None:
            try:
                s = Session.objects.get(
                    session_key=self.session_key,
                    expires_at__gt=timezone.now(),
                    is_active=True,
                )
                self._set_cache(dict(s), self.get_expiry_age())
                s.update_activity()
            except (Session.DoesNotExist, SuspiciousOperation):
                self._session_key = None
                data = {}

        return data

    def exists(self, session_key):
        return Session.objects.filter(
            session_key=session_key, expires_at__gt=timezone.now(), is_active=True
        ).exists()

    @classmethod
    def clear_expired(cls):
        Session.objects.expired.update(is_active=False)
