#!/usr/bin/python3
# coding=utf-8
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

""" Secret engine base """
from typing import Any, Optional

import re

from functools import wraps, partial

from pylon.core.tools import log  # pylint: disable=E0401
from pylon.core.tools.context import Context as Holder  # pylint: disable=E0401

from tools import context  # pylint: disable=E0401


def get_project_id(project: Any) -> Optional[int]:
    if project is None:
        return None
    elif isinstance(project, (int, str)):
        project = context.rpc_manager.call.project_get_or_404(project_id=project)
        return project.id
    elif isinstance(project, dict):
        return project["id"]
    elif project is not None:
        return project.id


class EngineMeta(type):
    """ Engine meta class """

    def __getattr__(cls, name):
        log.info("SecretEngine.cls.__getattr__(%s)", name)


class EngineBase(metaclass=EngineMeta):  # pylint: disable=R0902
    """ Engine base class """

    _secret_pattern = re.compile(r'{{secret\.([A-Za-z0-9_]+)}}')

    def __getattr__(self, name):
        log.info("SecretEngine.__getattr__(%s)", name)

    template_node_name = "secret"

    @classmethod
    def from_project(cls, project, **kwargs):
        return cls(project=project, **kwargs)

    def __init__(
            self, project: Any = None,
            fix_project_auth: bool = False,
            track_used_secrets: bool = False,
            **kwargs
    ):
        _ = project, fix_project_auth, kwargs
        self.project_id = get_project_id(project)
        #
        self.track_used_secrets = track_used_secrets
        self.used_secrets = set()
        #
        self._cache = {
            "secrets": {},
            "hidden_secrets": {},
            "shared_secrets": {},
        }
        #
        self.set_project_secrets = self.set_secrets
        self.set_project_hidden_secrets = self.set_hidden_secrets
        self.get_project_secrets = self.get_secrets
        self.get_project_hidden_secrets = self.get_hidden_secrets

    def _write(self, data):
        raise NotImplementedError

    def _read(self):
        raise NotImplementedError

    @property
    def db_data(self):
        raise RuntimeError("Not supported")

    @property
    def client(self):
        raise RuntimeError("Not supported")

    @staticmethod
    def init_vault(*args, **kwargs):
        _ = args, kwargs

    def with_admin_token(func):  # pylint: disable=E0213
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            return func(self, *args, **kwargs)  # pylint: disable=E1102

        return wrapper

    def create_project_space(self, *args, **kwargs):
        _ = args, kwargs
        #
        result = Holder()
        result.dict = lambda *args, **kwargs: {}
        return result

    def remove_project_space(self, *args, **kwargs):
        _ = args, kwargs

    def set_secrets(self, secrets, **kwargs):
        _ = kwargs
        #
        data = self._read()
        data["secrets"] = secrets
        self._write(data)
        #
        self._cache["secrets"] = secrets

    def set_hidden_secrets(self, secrets, **kwargs):
        _ = kwargs
        #
        data = self._read()
        data["hidden_secrets"] = secrets
        self._write(data)
        #
        self._cache["hidden_secrets"] = secrets

    def get_secrets(self, *args, **kwargs):
        _ = args, kwargs
        #
        if not self._cache["secrets"]:
            data = self._read()
            self._cache["secrets"] = data["secrets"]
        #
        return self._cache["secrets"].copy()

    def get_hidden_secrets(self, *args, **kwargs):
        _ = args, kwargs
        #
        if not self._cache["hidden_secrets"]:
            data = self._read()
            self._cache["hidden_secrets"] = data["hidden_secrets"]
        #
        return self._cache["hidden_secrets"].copy()

    def get_all_secrets(self, *args, **kwargs):
        _ = args, kwargs
        #
        if not self._cache["shared_secrets"]:
            self._cache["shared_secrets"] = self.__class__().get_secrets()
        #
        all_secrets = self._cache["shared_secrets"].copy()
        all_secrets.update(self.get_hidden_secrets())
        all_secrets.update(self.get_secrets())
        #
        return all_secrets

    def _unsecret_list(self, array, secrets, **kwargs):
        for i in range(len(array)):  # pylint: disable=C0200
            array[i] = self.unsecret(array[i], secrets, **kwargs)
        #
        return array

    def _unsecret_json(self, json_data, secrets, **kwargs):
        for key in json_data.keys():
            json_data[key] = self.unsecret(json_data[key], secrets, **kwargs)
        #
        return json_data

    def __unsecret_string(self, value, secrets):
        if self.track_used_secrets:
            for i in re.findall(self._secret_pattern, value):
                secret_value = secrets.get(i)
                if secret_value:
                    self.used_secrets.add(secret_value)
        replacer = partial(self._replacer, secrets=secrets)
        return re.sub(self._secret_pattern, replacer, value)

    def _replacer(self, match: re.Match, secrets: dict) -> str:
        secret_key = match.group(1)
        return str(secrets.get(secret_key, match.group(0)))

    def unsecret(self, value, secrets=None, **kwargs):
        _ = kwargs
        #
        if not secrets:
            secrets = self.get_all_secrets()

        from ..secret_field import SecretString
        if isinstance(value, SecretString):
            value.vault_client = self
            return value.unsecret(self.project_id)
        #
        if isinstance(value, str):
            return self.__unsecret_string(value, secrets)
        #
        if isinstance(value, list):
            return self._unsecret_list(value, secrets)
        #
        if isinstance(value, dict):
            return self._unsecret_json(value, secrets)
        #
        return value
