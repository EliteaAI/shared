import re
from uuid import uuid4
from typing import Optional, Any

from pydantic import BaseModel, SecretStr
from pydantic_core import core_schema

from ..tools.vault_tools import VaultClient
from pylon.core.tools import log


class SecretString(SecretStr):
    _secret_pattern = re.compile(r'^{{secret\.([A-Za-z0-9_]+)}}$')

    def __bool__(self):
        return bool(self._secret_value or self._secret_repr)

    def __len__(self) -> int:
        if self._secret_value is None:
            return 0
        return len(self._secret_value)

    @classmethod
    def __get_pydantic_core_schema__(cls, source_type, handler):
        # Define how Pydantic should validate this type
        # Use str_schema for proper string validation with type coercion
        return core_schema.no_info_after_validator_function(
            cls._validate,
            core_schema.union_schema([
                core_schema.is_instance_schema(cls),
                core_schema.str_schema(),  # Validates and coerces to str
                core_schema.dict_schema(),
            ])
        )

    @classmethod
    def _validate(cls, value: str | dict) -> 'SecretString':
        """
        Validate and construct SecretString.
        Note: At this point, str_schema() has already validated/coerced strings,
        so we just need to handle the dict case and construct the instance.
        """
        if isinstance(value, cls):
            return value
        if isinstance(value, dict):
            # Validate that dict has 'value' key and it's a string
            if 'value' not in value:
                raise ValueError("Dict must have 'value' key")
            if not isinstance(value['value'], str):
                raise TypeError(f"Dict 'value' must be str, got {type(value['value'])}")
        # str_schema() already validated/coerced strings, so value is definitely str or dict here
        return cls(value)

    def __init__(self, value: str | dict, project_id: Optional[int] = None):
        self._project_id = project_id
        self._vault_client = None
        self._secret_repr = None
        self._secret_value = None
        self._is_secret = False

        if isinstance(value, dict):
            # assume that this is old-style secret field
            self._is_secret = value['from_secrets']
            if self._is_secret:
                self._secret_repr = value['value']
            else:
                self._secret_value = value['value']
        else:
            self._is_secret = re.fullmatch(self._secret_pattern, value) is not None
            if self._is_secret:
                self._secret_repr = value
            else:
                self._secret_value = value

        super().__init__(self._secret_value)

    @property
    def _secret_name(self) -> Optional[str]:
        if self._secret_repr:
            try:
                return re.fullmatch(self._secret_pattern, self._secret_repr).group(1)
            except IndexError:
                ...

    def __str__(self) -> str:
        return self._secret_repr if self._is_secret else self._secret_value

    @property
    def vault_client(self):
        if self._vault_client is None:
            self._vault_client = VaultClient(project=self.project_id)
        return self._vault_client

    @vault_client.setter
    def vault_client(self, value: VaultClient):
        self._vault_client = value
        self._project_id = value.project_id

    def get_secret_value(self) -> str:
        if self._is_secret:
            self._secret_value = self.vault_client.unsecret(self._secret_repr)
        return self._secret_value

    def store_secret(self, force_set_secret: bool = False) -> str:
        if not self._secret_repr:
            self._secret_repr = '{{secret.%s}}' % str(uuid4()).replace("-", "")
        if self._secret_value is None and not force_set_secret:
            raise ValueError(
                'Secret value was not set. If you are still sure to change secret, pass force_set_secret=True'
            )
        log.debug(f"Storing secret value: {self._secret_value} of {self._secret_repr}")

        # from pylon.core.tools import log
        # hs = self.vault_client.get_secrets()
        # hs[self._secret_name] = self._secret_value
        # self.vault_client.set_secrets(hs)

        hs = self.vault_client.get_hidden_secrets()
        hs[self._secret_name] = self._secret_value
        self.vault_client.set_hidden_secrets(hs)

        self._is_secret = True
        return self._secret_repr

    def set_value(self, value: str) -> None:
        self._secret_value = value

    def unsecret(self, project_id: Optional[int] = None) -> str:
        self._project_id = project_id
        return self.get_secret_value()

    @property
    def project_id(self):
        return self._project_id

    @project_id.setter
    def project_id(self, value):
        if self._project_id != value:
            self._vault_client = None
        self._project_id = value

    @classmethod
    def parse_obj(cls, v: dict):
        '''deprecated. here for compatibility'''
        return cls(v)

    @property
    def from_secrets(self):
        '''deprecated. here for compatibility'''
        return self._is_secret


def process_field(field_value, vault_client) -> tuple[set, Any]:
    log.info(f'processing field: {type(field_value)=}, {field_value=}')
    new_secrets = set()

    if type(field_value).__name__ == "SecretStr":
        secret_value = field_value.get_secret_value()
        s = SecretString(secret_value, project_id=vault_client.project_id)
        log.info(f'found SecretStr {secret_value=}, {s=}, {s._is_secret=}')
        if not s._is_secret:
            s.vault_client = vault_client
            secret_uuid_value = s.store_secret()
            new_secrets.add(secret_uuid_value)
            return new_secrets, secret_uuid_value
    elif isinstance(field_value, SecretString):
        if not field_value._is_secret:
            field_value.vault_client = vault_client
            secret_uuid_value = field_value.store_secret()
            new_secrets.add(secret_uuid_value)
    elif isinstance(field_value, dict):
        new_secrets.update(
            store_secrets_dict(field_value, project_id=vault_client.project_id, vault_client=vault_client)
        )
    elif isinstance(field_value, BaseModel):
        new_secrets.update(
            store_secrets_pd(field_value, project_id=vault_client.project_id, vault_client=vault_client)
        )
    return new_secrets, None

def store_secrets(model_dict: dict | BaseModel, project_id: Optional[int] = None, vault_client = None) -> set[str]:
    if isinstance(model_dict, dict):
        return store_secrets_dict(model_dict=model_dict, project_id=project_id, vault_client=vault_client)
    if isinstance(model_dict, BaseModel):
        return store_secrets_pd(model=model_dict, project_id=project_id, vault_client=vault_client)
    raise ValueError(f'Unsupported type {type(model_dict)}')

def store_secrets_dict(model_dict: dict, project_id: int, vault_client = None) -> set[str]:
    if not vault_client:
        if project_id is None:
            project_id = model_dict['project_id']
        vault_client = VaultClient(project=project_id)

    new_secrets = set()
    for field_name in model_dict.keys():
        field_value = model_dict[field_name]
        secrets_update, new_value = process_field(field_value, vault_client)
        if field_value != new_value and new_value is not None:
            log.info(f'Value to Secrets [{field_name}] {field_value=} -> {new_value}')
            model_dict[field_name] = new_value
            new_secrets.add(new_value)
        new_secrets.update(secrets_update)
    return new_secrets

def store_secrets_pd(model: BaseModel, project_id: Optional[int] = None, vault_client = None) -> set[str]:
    if not vault_client:
        if project_id is None:
            project_id = model.project_id
        vault_client = VaultClient(project=project_id)

    new_secrets = set()
    for field_name, field_info in model.model_fields.items():
        field_value = getattr(model, field_name)
        secrets_update, new_value = process_field(field_value, vault_client)
        if field_value != new_value and new_value is not None:
            log.info(f'Value to Secrets [{field_name}] {field_value=} -> {new_value}')
            setattr(model, field_name, new_value)
            new_secrets.add(new_value)
        new_secrets.update(secrets_update)
    return new_secrets

def purge_secrets(project_id: int, secrets_to_delete: list | set | tuple) -> None:
    vc = VaultClient(project_id)
    hs = vc.get_hidden_secrets()
    secret_uids = set(
        re.fullmatch(vc._secret_pattern, i).group(1)
        for i in secrets_to_delete
        if re.fullmatch(vc._secret_pattern, i)
    )
    for i in secret_uids:
        del hs[i]
    vc.set_hidden_secrets(hs)
    log.debug(f'secrets purged, {secrets_to_delete}')

def store_secrets_replaced(model_dict: dict, model_dict_before: dict, project_id: int) -> None:
    ''' Substitute old secret value with new one instead of storing a new secret'''

    vault_client = None
    for field_name, field_value in model_dict.items():
        if isinstance(field_value, SecretString):
            if not field_value._is_secret:
                field_value_before = model_dict_before.get(field_name)
                if isinstance(field_value_before, SecretString):
                    field_value_before.set_value(field_value.get_secret_value())
                    field_value = model_dict[field_name] = field_value_before
                if vault_client is None:
                    vault_client = VaultClient(project_id)
                field_value.vault_client = vault_client
                field_value.store_secret()
        elif isinstance(field_value, dict):
            store_secrets_replaced(field_value, model_dict_before.get(field_name, {}), project_id)
