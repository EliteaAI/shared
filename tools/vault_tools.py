#!/usr/bin/python
# coding=utf-8

#     Copyright 2026 EPAM Systems
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.

""" Vault tools """
import re

import importlib
from functools import wraps, partial
from typing import Optional, Any, Union, List, Tuple

import hvac  # actually comes from pylon
from hvac.exceptions import InvalidRequest
from pydantic.v1 import BaseModel, constr, ValidationError

from pylon.core.tools import log
from jinja2 import Template

from . import db
from .rpc_tools import RpcMixin
from .secret_engines import get_project_id
from ..models.vault import Vault

from tools import config as c


AnyProject = Union[None, int, str, dict, 'Project']


class VaultAuth(BaseModel):
    role_id: constr(min_length=1) = '-'
    secret_id: constr(min_length=1) = '-'

    @property
    def _is_default(self) -> bool:
        return all({
            self.role_id == VaultAuth.__fields__['role_id'].default,
            self.secret_id == VaultAuth.__fields__['secret_id'].default
        })

    class Config:
        fields = {
            'role_id': 'vault_auth_role_id',
            'secret_id': 'vault_auth_secret_id'
        }


class VaultDbModel(BaseModel):
    root_token: str
    keys: List[str]
    keys_base64: List[str]

    @classmethod
    def from_db(cls, obj: Vault):
        return cls.parse_obj(obj.unseal_json)


class HashiCorpVaultClient:
    _secret_pattern = re.compile(r'{{secret\.([A-Za-z0-9_]+)}}')

    approle_auth_path: str = 'carrier-approle'
    secrets_path: str = 'project-secrets'
    admin_kv_mount: str = f'kv-for-{c.VAULT_ADMINISTRATION_NAME}'
    template_node_name: str = 'secret'

    @classmethod
    def from_project(cls, project: AnyProject, **kwargs):
        # This is here for compatibility. No need to init class form this method
        assert project is not None
        return cls(project=project, **kwargs)

    def __init__(self, project: AnyProject = None, fix_project_auth: bool = False,
                 track_used_secrets: bool = False, **kwargs):
        self.track_used_secrets = track_used_secrets
        self.used_secrets = set()
        self.auth: Optional[VaultAuth] = None

        self.project_id = get_project_id(project)
        self.is_administration = project is None

        if project is None:
            self.vault_name = c.VAULT_ADMINISTRATION_NAME
        else:
            auth = None
            if isinstance(project, int) or isinstance(project, str):
                project = RpcMixin().rpc.call.project_get_or_404(project_id=project)
                auth = project.secrets_json
            elif isinstance(project, dict):
                auth = project
            elif project is not None:
                auth = project.secrets_json
            self.vault_name = self.project_id
            try:
                self.auth = VaultAuth.parse_obj(auth)
            except ValidationError:
                log.info('No vault auth data for project %s', project)

        self.kv_mount = f'kv-for-{self.vault_name}'
        self.hidden_kv_mount = f'kv-for-hidden-{self.vault_name}'
        self.approle_name = f'role-for-{self.vault_name}'
        self.policy_name = f'policy-for-{self.vault_name}'

        self._client: hvac.Client = None
        self._db_data: VaultDbModel = None
        self._cache = {
            'secrets': {},
            'hidden_secrets': {},
            'shared_secrets': {}
        }

        self.set_project_secrets = self.set_secrets
        self.set_project_hidden_secrets = self.set_hidden_secrets
        self.get_project_secrets = self.get_secrets
        self.get_project_hidden_secrets = self.get_hidden_secrets

        if fix_project_auth:
            if not self.is_administration and self.auth and self.auth._is_default:
                log.info('Broken vault auth detected. Trying to fix')
                self.auth = self._init_approle()
                if not self.auth._is_default:
                    project = RpcMixin().rpc.call.project_get_or_404(project_id=self.project_id)
                    project.secrets_json = self.auth.dict(by_alias=True)
                    project.commit()
                    log.info('Vault auth fixed for project %s', self.project_id)

    @property
    def db_data(self) -> VaultDbModel:
        if not self._db_data:
            with db.get_session() as session:
                vault_db = session.query(Vault).get(c.VAULT_DB_PK)
            if vault_db is None:
                self._db_data = HashiCorpVaultClient.init_vault()
            else:
                self._db_data = VaultDbModel.from_db(vault_db)
        return self._db_data

    @property
    def client(self) -> hvac.Client:
        if not self._client:
            # Get root token from DB
            client = hvac.Client(url=c.VAULT_URL, token=self.db_data.root_token)
            client.__root_token = self.db_data.root_token
            if self.auth:
                try:
                    client.auth.approle.login(**self.auth.dict(), use_token=True, mount_point=HashiCorpVaultClient.approle_auth_path)
                except (NotImplementedError, InvalidRequest):  # workaround to handle outdated pylon
                    log.warning('Vault approle login failed. Vault will be using root token %s')
                    ...
            self._client = client
        return self._client

    @staticmethod
    def init_vault() -> VaultDbModel:
        """ Initialize Vault """
        log.info('Initializing vault')
        with db.get_session() as session:
            vault_db_obj = session.query(Vault).get(c.VAULT_DB_PK)
        if vault_db_obj is None:
            client = hvac.Client(url=c.VAULT_URL)
            if client.sys.is_initialized():
                log.critical('Vault is initialized, but no keys found in db!')
                raise
            vault_data = client.sys.initialize()
            vault_db_obj = Vault(id=c.VAULT_DB_PK, unseal_json=vault_data)

            # if vault_db_obj is None:
            #     vault_db_obj = Vault(id=c.VAULT_DB_PK, unseal_json=vault_data)
            # else:
            #     vault_db_obj.unseal_json = vault_data
            vault_db_obj.insert()
            db_data = VaultDbModel.from_db(vault_db_obj)
        else:
            db_data = VaultDbModel.from_db(vault_db_obj)
            client = hvac.Client(url=c.VAULT_URL, token=db_data.root_token)
            if not client.sys.is_initialized():
                vault_data = client.sys.initialize()
                vault_db_obj.unseal_json = vault_data
                vault_db_obj.insert()
                db_data = VaultDbModel.from_db(vault_db_obj)
        client.token = db_data.root_token
        if client.sys.is_sealed():
            client.sys.submit_unseal_keys(keys=db_data.keys)

        try:
            client.sys.enable_auth_method(
                method_type="approle",
                path=HashiCorpVaultClient.approle_auth_path,
            )
        except InvalidRequest as e:
            ...
        return db_data

    def with_admin_token(func):
        @wraps(func)
        def wrapper(self: 'HashiCorpVaultClient', *args, **kwargs):
            stashed_token = self.client.token
            self.client.token = self.client.__root_token
            result = func(self, *args, **kwargs)
            self.client.token = stashed_token
            return result

        return wrapper

    def _add_secrets_engine(self, mount_path: str, exists_ok: bool = True) -> None:
        # Create hidden secrets KV
        try:
            self.client.sys.enable_secrets_engine(
                backend_type="kv",
                path=mount_path,
                options={"version": "2"},
            )
            self.client.secrets.kv.v2.create_or_update_secret(
                path=self.secrets_path,
                mount_point=mount_path,
                secret=dict(),
            )
        except InvalidRequest:
            if not exists_ok:
                raise

    @staticmethod
    def _make_policy(path: str, capabilities: Optional[list] = None, comment: Optional[str] = None) -> str:
        if capabilities is None:
            capabilities = ["create", "read", "update", "delete", "list"]
        policy_template = '''
            {% if comment %}# {{ comment }}{% endif %}
            path "{{ path }}" {
              capabilities = {{ capabilities | tojson }}
            }
        '''
        return Template(policy_template).render(path=path, capabilities=capabilities, comment=comment)

    def __set_policy(self):
        policies = [
            self._make_policy('auth/approle/login', ["create", "read"], 'Login with AppRole'),
            self._make_policy(f'auth/{self.approle_auth_path}/login', ["create", "read"], 'Login with Carrier AppRole'),
            self._make_policy(f'{self.kv_mount}/*', comment='Read/write secrets'),
            self._make_policy(f'{self.hidden_kv_mount}/*', comment='Read/write hidden secrets'),
        ]
        if not self.is_administration:
            policies.append(
                self._make_policy(
                    f'{self.admin_kv_mount}/*',
                    capabilities=["read", "list"],
                    comment='Read/write shared secrets')
            )
        policy = '\n'.join(policies)
        return self.client.sys.create_or_update_policy(
            name=self.policy_name,
            policy=policy
        )

    def _init_approle(self) -> VaultAuth:
        try:
            self.client.auth.approle.create_or_update_approle(
                self.approle_name,
                token_policies=[self.policy_name],
                mount_point=self.approle_auth_path
            )
            approle_id = self.client.auth.approle.read_role_id(
                self.approle_name,
                mount_point=self.approle_auth_path
            )['data']['role_id']
            secret_id = self.client.auth.approle.generate_secret_id(
                self.approle_name,
                mount_point=self.approle_auth_path
            )['data']['secret_id']

            self._client = None
            return VaultAuth(vault_auth_role_id=approle_id, vault_auth_secret_id=secret_id)

        except NotImplementedError:
            log.warning('Vault approle login failed. Vault will be using root token %s')
            return VaultAuth(vault_auth_role_id='-', vault_auth_secret_id='-')

    @with_admin_token
    def create_project_space(self, quiet: bool = False) -> VaultAuth:
        """ Create project approle, policy and KV """
        # Create policy for project
        self.__set_policy()

        # Create secrets KV
        try:
            self._add_secrets_engine(self.kv_mount)
        except InvalidRequest:
            if not quiet:
                raise

        # Create hidden secrets KV
        try:
            self._add_secrets_engine(self.hidden_kv_mount)
        except InvalidRequest:
            if not quiet:
                raise

        # Create AppRole
        self.auth = self._init_approle()
        return self.auth

    @with_admin_token
    def remove_project_space(self) -> None:
        """ Remove project-specific data from Vault """
        for vault_mount in [self.hidden_kv_mount, self.kv_mount]:
            self.client.sys.disable_secrets_engine(
                path=vault_mount,
            )
        try:
            self.client.auth.approle.delete_role(
                self.approle_name,
                mount_point=self.approle_auth_path
            )
        except NotImplementedError:
            ...
        # Remove policy
        self.client.sys.delete_policy(
            name=self.policy_name,
        )

    def set_secrets(self, secrets: dict) -> None:
        """ Set secrets """
        self.client.secrets.kv.v2.create_or_update_secret(
            path=self.secrets_path,
            mount_point=self.kv_mount,
            secret=secrets,
        )
        self._cache['secrets'] = secrets

    def set_hidden_secrets(self, secrets: dict) -> None:
        """ Set hidden secrets """
        if self.is_administration:
            self.set_project_secrets(secrets)
        # try:
        self.client.secrets.kv.v2.create_or_update_secret(
            path=self.secrets_path,
            mount_point=self.hidden_kv_mount,
            secret=secrets,
        )
        self._cache['hidden_secrets'] = secrets
        # except (Forbidden, InvalidPath):
        #     log.error("Exception in set_project_hidden_secret")
        #     # self.__set_hidden_kv_permissions()
        #     # self.set_project_secrets(secrets)
        #     raise

    def _get_vault_data(self, mount_point: str) -> dict:
        return self.client.secrets.kv.v2.read_secret_version(
            path=self.secrets_path,
            mount_point=mount_point,
        ).get("data", {}).get("data", {})

    def get_secrets(self) -> dict:
        """ Get secrets """
        if not self._cache['secrets']:
            self._cache['secrets'] = self._get_vault_data(self.kv_mount)
        return self._cache['secrets']

    def get_hidden_secrets(self) -> dict:
        """ Get project hidden secrets """
        if self.is_administration:
            return self.get_secrets()
        # try:
        if not self._cache['hidden_secrets']:
            self._cache['hidden_secrets'] = self._get_vault_data(self.hidden_kv_mount)
        return self._cache['hidden_secrets']
        # except (hvac.exceptions.Forbidden, hvac.exceptions.InvalidPath):
        #     log.error("Exception Forbidden in get_project_hidden_secret")
        #     self.__set_hidden_kv_permissions()
        #     return {}

    def get_all_secrets(self) -> dict:
        if self.is_administration:
            return self.get_secrets()
        if not self._cache['shared_secrets']:
            self._cache['shared_secrets'] = self.__class__().get_all_secrets()
        all_secrets = self._cache['shared_secrets']
        all_secrets.update(self.get_hidden_secrets())
        all_secrets.update(self.get_secrets())
        return all_secrets

    def _unsecret_list(self, array: list, secrets: dict, **kwargs) -> list:
        for i in range(len(array)):
            array[i] = self.unsecret(array[i], secrets, **kwargs)
        return array

    def _unsecret_json(self, json: dict, secrets: dict, **kwargs) -> dict:
        for key in json.keys():
            json[key] = self.unsecret(json[key], secrets, **kwargs)
        return json

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

    def unsecret(self, value: Any, secrets: Optional[dict] = None, **kwargs) -> Any:
        if not secrets:
            secrets = self.get_all_secrets()
        if isinstance(value, str):
            return self.__unsecret_string(value, secrets)
        elif isinstance(value, list):
            return self._unsecret_list(value, secrets)
        elif isinstance(value, dict):
            return self._unsecret_json(value, secrets)
        else:
            return value

#
# Select active (compat) client for secrets
#

log.info("Using secrets engine: %s", c.SECRETS_ENGINE)
#
if c.SECRETS_ENGINE == "managed_vault":
    VaultClient = HashiCorpVaultClient
else:
    try:
        engine_pkg = importlib.import_module(
            f"plugins.shared.tools.secret_engines.{c.SECRETS_ENGINE}"
        )
        VaultClient = engine_pkg.Engine
    except:  # pylint: disable=W0702
        log.exception("Failed to set secrets engine: %s", c.SECRETS_ENGINE)
        raise
