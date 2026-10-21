# pylint: disable=C0116
#
#   Copyright 2026 EPAM Systems
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Secret engine impl

Governed credential material (C-1009) lives in its own row '<project key>:cs' of secrets_data, never in the
legacy blob that every {{secret.*}} resolution decrypts. Migration of the pre-split 'credential_store' section
happens on the first governed read or mutation of a project (see _read_governed / _update_governed).

Deploy constraint: roll every pylon_main replica to this version BEFORE the first governed write against a
shared database. Once a project has its ':cs' row, the legacy section writers (_update_section,
_write_section) refuse the 'credential_store' section with GovernedSectionMoved, so a stale replica of THIS
code cannot recreate a diverging copy. A replica of the version before the split cannot be stopped from
here: it would write governed generations into the legacy section, where this version never reads them.
"""

import json

from cryptography.fernet import Fernet  # pylint: disable=E0401

from tools import context  # pylint: disable=E0401
from tools import config as c  # pylint: disable=E0401

from . import EngineBase
from ...models.secrets import SecretsKey, SecretsData


LEGACY_GOVERNED_SECTION = "credential_store"  # where governed material lived before the row split (migrated lazily)


class SectionCheckFailed(Exception):
    """ Raised by _update_section when its check callable rejects the current section """


class GovernedSectionMoved(Exception):
    """ The 'credential_store' section now lives in its own row: the legacy section writers refuse it """


class Engine(EngineBase):  # pylint: disable=R0902
    """ Engine class """
    # TODO: use project and system schemas here too

    @property
    def db_key(self):
        if self.project_id is None:
            return 'admin'
        return f'project-{self.project_id}'

    def __init__(
            self, project=None,
            fix_project_auth=False, track_used_secrets=False,
            **kwargs
    ):
        super().__init__(project, fix_project_auth, track_used_secrets, **kwargs)
        #
        self.master_key = None
        if c.SECRETS_MASTER_KEY is not None:
            self.master_key = c.SECRETS_MASTER_KEY.encode()

    def _write_key(self, key):
        if self.master_key is None:
            data = key
        else:
            data = Fernet(self.master_key).encrypt(key)
        #
        with context.db.make_session() as session:
            key_obj = session.query(SecretsKey).get(self.db_key)
            #
            if key_obj is None:
                key_obj = SecretsKey(id=self.db_key, data=data)
                session.add(key_obj)
            else:
                key_obj.data = data
            #
            try:
                session.commit()
            except:  # pylint: disable=W0702
                session.rollback()
                raise

    def _unwrap_key(self, data):
        if self.master_key is not None:
            return Fernet(self.master_key).decrypt(data)
        #
        return data

    def _read_key(self):
        with context.db.make_session() as session:
            data = session.query(SecretsKey).get(self.db_key).data
        #
        return self._unwrap_key(data)

    def _write(self, data):
        key = self._read_key()
        data = Fernet(key).encrypt(json.dumps(data).encode())
        #
        with context.db.make_session() as session:
            data_obj = session.query(SecretsData).get(self.db_key)
            #
            if data_obj is None:
                data_obj = SecretsData(id=self.db_key, data=data)
                session.add(data_obj)
            else:
                data_obj.data = data
            #
            try:
                session.commit()
            except:  # pylint: disable=W0702
                session.rollback()
                raise

    def _read(self):
        key = self._read_key()
        with context.db.make_session() as session:
            data = session.query(SecretsData).get(self.db_key).data
        return json.loads(Fernet(key).decrypt(data).decode())

    def _write_section(self, section, value):
        # Lock the row before reading it, so concurrent writers to different
        # sections (secrets vs hidden_secrets) can't clobber each other's update.
        key = self._read_key()
        with context.db.make_session() as session:
            data_obj = (
                session.query(SecretsData)
                .filter(SecretsData.id == self.db_key)
                .with_for_update()
                .one()
            )
            self._refuse_moved_section(session, section)
            data = json.loads(Fernet(key).decrypt(data_obj.data).decode())
            data[section] = value
            data_obj.data = Fernet(key).encrypt(json.dumps(data).encode())
            #
            try:
                session.commit()
            except:  # pylint: disable=W0702
                session.rollback()
                raise
        #
        self._cache[section] = value

    def set_secrets(self, secrets, **kwargs):
        _ = kwargs
        self._write_section("secrets", secrets)

    def set_hidden_secrets(self, secrets, **kwargs):
        _ = kwargs
        self._write_section("hidden_secrets", secrets)

    def set_external_access(self, flags, **kwargs):
        _ = kwargs
        self._write_section("external_access", flags)

    def _update_section(self, section, add=None, remove=None, check=None):
        # Lock before reading, so merge is atomic vs same-section concurrent writers.
        # check(current_section) runs under the row lock; falsy -> nothing is written
        # and SectionCheckFailed is raised (compare-and-set for callers).
        key = self._read_key()
        with context.db.make_session() as session:
            data_obj = (
                session.query(SecretsData)
                .filter(SecretsData.id == self.db_key)
                .with_for_update()
                .one()
            )
            self._refuse_moved_section(session, section)
            data = json.loads(Fernet(key).decrypt(data_obj.data).decode())
            target = data.setdefault(section, {})
            if check is not None and not check(target):
                session.rollback()
                raise SectionCheckFailed(section)
            target.update(add or {})
            for name in (remove or ()):
                target.pop(name, None)
            data_obj.data = Fernet(key).encrypt(json.dumps(data).encode())
            #
            try:
                session.commit()
            except:  # pylint: disable=W0702
                session.rollback()
                raise
        #
        self._cache[section] = target
        return target

    # -- governed credential store (C-1009): own row, never read by the legacy {{secret.*}} paths ------

    @property
    def governed_db_key(self):
        """ SecretsData id of the credential-store row: same project key, separate encrypted blob """
        return f"{self.db_key}:cs"

    def _refuse_moved_section(self, session, section):
        """ Legacy section writers must not recreate 'credential_store' once its own row exists """
        if section == LEGACY_GOVERNED_SECTION and session.query(SecretsData).get(self.governed_db_key) is not None:
            raise GovernedSectionMoved(section)

    def _read_governed(self, session=None):
        """ {'<ref_hex>:<generation>': bundle}: one session, ONE data statement, one blob decrypt (+ key unwrap).

        Both candidate rows are fetched by a single SELECT (the row with the longest id wins: '<key>:cs' sorts
        after '<key>'), so the read is one snapshot and cannot interleave with a migration. A project whose
        governed material still sits in the legacy section (written before the row split) is migrated on this
        first read, in its own transaction under the legacy row lock (a documented one-time write on a read
        path), then served from the new row.
        """
        if session is None:
            with context.db.make_session() as own:
                return self._read_governed(own)
        key_data = session.query(SecretsKey).get(self.db_key).data
        row = (
            session.query(SecretsData)
            .filter(SecretsData.id.in_([self.db_key, self.governed_db_key]))
            .order_by(SecretsData.id.desc())
            .first()
        )
        if row.id != self.governed_db_key:
            return self._update_governed(lambda section: None)  # migrates; the section it returns is current
        return json.loads(Fernet(self._unwrap_key(key_data)).decrypt(row.data).decode())

    def _update_governed(self, mutate):
        """ Run mutate(section) in place under the row lock; it raises to abort (nothing is written).

        First mutation of a project migrates the legacy 'credential_store' section into the row, in the
        same transaction, under the legacy row lock (so concurrent first writers serialise).
        """
        with context.db.make_session() as session:
            key = self._unwrap_key(session.query(SecretsKey).get(self.db_key).data)
            migrating = False
            row = self._lock_row(session, self.governed_db_key)
            if row is None:
                legacy = self._lock_row(session, self.db_key)
                row = self._lock_row(session, self.governed_db_key)  # a concurrent migrator may have won
            if row is not None:
                target = json.loads(Fernet(key).decrypt(row.data).decode())
            else:
                content = json.loads(Fernet(key).decrypt(legacy.data).decode())
                if LEGACY_GOVERNED_SECTION in content:
                    target = content.pop(LEGACY_GOVERNED_SECTION)
                    legacy.data = Fernet(key).encrypt(json.dumps(content).encode())
                else:
                    target = {}
                row = SecretsData(id=self.governed_db_key, data=b"")
                session.add(row)
                migrating = True
            before = json.dumps(target, sort_keys=True)
            try:
                mutate(target)
            except BaseException:
                session.rollback()
                raise
            if not migrating and json.dumps(target, sort_keys=True) == before:
                session.rollback()  # idempotent no-op (e.g. delete_all of nothing): no write, no new ciphertext
                return target
            row.data = Fernet(key).encrypt(json.dumps(target).encode())
            #
            try:
                session.commit()
            except:  # pylint: disable=W0702
                session.rollback()
                raise
            return target

    @staticmethod
    def _lock_row(session, row_id):
        return (
            session.query(SecretsData)
            .filter(SecretsData.id == row_id)
            .with_for_update()
            .one_or_none()
        )

    def update_secrets(self, add=None, remove=None, **kwargs):
        _ = kwargs
        return self._update_section("secrets", add, remove)

    def update_hidden_secrets(self, add=None, remove=None, **kwargs):
        _ = kwargs
        return self._update_section("hidden_secrets", add, remove)

    def update_external_access(self, add=None, remove=None, **kwargs):
        _ = kwargs
        return self._update_section("external_access", add, remove)

    def create_project_space(self, *args, **kwargs):
        _ = args, kwargs
        #
        with context.db.make_session() as session:
            key_obj = session.query(SecretsKey).get(self.db_key)
        #
        if key_obj is None:
            key = Fernet.generate_key()
            self._write_key(key)
        #
        with context.db.make_session() as session:
            data_obj = session.query(SecretsData).get(self.db_key)
        #
        if data_obj is None:
            self._write({
                "secrets": {},
                "hidden_secrets": {},
            })
        #
        return super().create_project_space(*args, **kwargs)

    def remove_project_space(self, *args, **kwargs):
        _ = args, kwargs
        #
        with context.db.make_session() as session:
            key_obj = session.query(SecretsKey).get(self.db_key)
            #
            if key_obj is not None:
                session.delete(key_obj)
            #
            data_obj = self._lock_row(session, self.db_key)  # legacy row first, as a migration does
            #
            if data_obj is not None:
                session.delete(data_obj)
            #
            governed_obj = self._lock_row(session, self.governed_db_key)
            #
            if governed_obj is not None:
                session.delete(governed_obj)
            #
            try:
                session.commit()
            except:  # pylint: disable=W0702
                session.rollback()
                raise
