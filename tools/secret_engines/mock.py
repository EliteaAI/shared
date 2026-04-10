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

from . import EngineBase


class Engine(EngineBase):  # pylint: disable=R0902
    """ Engine class """

    storage = {}

    @property
    def secrets_key(self) -> str:
        if self.project_id is None:
            return 'admin'
        return f'project-{self.project_id}'

    def _write(self, data):
        Engine.storage[self.secrets_key] = data

    def _read(self):
        return Engine.storage[self.secrets_key]

    def create_project_space(self, *args, **kwargs):
        _ = args, kwargs
        #
        if self.secrets_key not in Engine.storage:
            self._write({
                "secrets": {},
                "hidden_secrets": {},
            })
        #
        return super().create_project_space(*args, **kwargs)

    def remove_project_space(self, *args, **kwargs):
        _ = args, kwargs
        #
        Engine.storage.pop(self.secrets_key, None)
