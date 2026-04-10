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

import os
import json

from cryptography.fernet import Fernet  # pylint: disable=E0401

from tools import context  # pylint: disable=E0401
from tools import config as c  # pylint: disable=E0401

from . import EngineBase


class Engine(EngineBase):  # pylint: disable=R0902
    """ Engine class """

    @property
    def key_file_name(self) -> str:
        if self.project_id is None:
            return 'admin.key'
        return f'project-{self.project_id}.key'

    @property
    def secrets_file_name(self) -> str:
        if self.project_id is None:
            return 'admin.secrets'
        return f'project-{self.project_id}.secrets'

    def __init__(
            self, project=None,
            fix_project_auth=False, track_used_secrets=False,
            **kwargs
    ):
        super().__init__(project, fix_project_auth, track_used_secrets, **kwargs)
        self.key_storage = os.path.join(c.SECRETS_FILESYSTEM_PATH, self.key_file_name)
        self.secrets_storage = os.path.join(c.SECRETS_FILESYSTEM_PATH, self.secrets_file_name)
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
        with open(self.key_storage, "wb") as file:
            file.write(data)

    def _read_key(self):
        with open(self.key_storage, "rb") as file:
            data = file.read()
        #
        if self.master_key is not None:
            return Fernet(self.master_key).decrypt(data)
        #
        return data

    def _write(self, data):
        key = self._read_key()
        #
        with open(self.secrets_storage, "wb") as file:
            file.write(Fernet(key).encrypt(json.dumps(data).encode()))

    def _read(self):
        key = self._read_key()
        #
        with open(self.secrets_storage, "rb") as file:
            return json.loads(Fernet(key).decrypt(file.read()).decode())

    @staticmethod
    def init_vault(*args, **kwargs):
        _ = args, kwargs
        #
        os.makedirs(c.SECRETS_FILESYSTEM_PATH, exist_ok=True)

    def create_project_space(self, *args, **kwargs):
        _ = args, kwargs
        #
        if not os.path.exists(self.key_storage):
            key = Fernet.generate_key()
            self._write_key(key)
        #
        if not os.path.exists(self.secrets_storage):
            self._write({
                "secrets": {},
                "hidden_secrets": {},
            })
        #
        return super().create_project_space(*args, **kwargs)

    def remove_project_space(self, *args, **kwargs):
        _ = args, kwargs
        #
        if os.path.exists(self.key_storage):
            os.remove(self.key_storage)
        #
        if os.path.exists(self.secrets_storage):
            os.remove(self.secrets_storage)
