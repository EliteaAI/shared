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

""" Secret engine impl """

import json

from cryptography.fernet import Fernet  # pylint: disable=E0401

from tools import context  # pylint: disable=E0401
from tools import config as c  # pylint: disable=E0401

from . import EngineBase
from ...models.secrets import SecretsKey, SecretsData


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

    def _read_key(self):
        with context.db.make_session() as session:
            data = session.query(SecretsKey).get(self.db_key).data
        #
        if self.master_key is not None:
            return Fernet(self.master_key).decrypt(data)
        #
        return data

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
            data_obj = session.query(SecretsData).get(self.db_key)
            #
            if data_obj is not None:
                session.delete(data_obj)
            #
            try:
                session.commit()
            except:  # pylint: disable=W0702
                session.rollback()
                raise
