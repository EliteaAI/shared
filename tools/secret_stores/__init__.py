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

""" SecretStore port: per-reference credential material behind a typed, audited interface.

Adapters (database, corporate Vault) are imported lazily by get_store(); nothing here
imports them at module load.
"""

import importlib
import uuid
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal, Mapping, Protocol, Sequence

from pydantic import SecretStr  # pylint: disable=E0401

from .authority import AuthorizedStoreContext, CredentialStoreProvider, OPERATION_PURPOSES, PURPOSES  # noqa: F401

StoreCode = Literal["DENIED", "SEALED", "UNAVAILABLE", "TLS_INVALID", "NOT_FOUND", "VERSION_CONFLICT"]

_MESSAGES = {
    "DENIED": "The secret store denied the operation.",
    "SEALED": "The secret store is sealed.",
    "UNAVAILABLE": "The secret store is unavailable.",
    "TLS_INVALID": "The secret store connection failed TLS validation.",
    "NOT_FOUND": "The secret was not found in the store.",
    "VERSION_CONFLICT": "The secret store version did not match the expected version.",
}


class StoreError(Exception):
    """ Typed store failure. Fixed message per code: never a path, URL, body or client text """

    def __init__(self, code, details=None):
        if code not in _MESSAGES:
            code = "UNAVAILABLE"
        self.code = code
        self.message = _MESSAGES[code]
        # attribution only (e.g. {"ref_id": "<uuid>"} of the failing reference): never material, never in the message
        self.details = dict(details or {})
        super().__init__(self.message)

    @property
    def audit_code(self):
        """ Code as used in operator results and audit events """
        return f"STORE_{self.code}"

    def __reduce__(self):
        return (StoreError, (self.code, self.details))


@dataclass(frozen=True)
class StoreRef:
    """ Pointer to one reference's material; locator is restricted and never rendered """

    ref_id: uuid.UUID
    project_id: int
    store_kind: str
    locator: Mapping = field(default_factory=dict, repr=False, compare=False)

    def __reduce__(self):
        raise TypeError("StoreRef cannot be pickled")


class SecretValue:
    """ Credential bundle: field name -> SecretStr, at a store generation """

    __slots__ = ("fields", "generation")

    def __init__(self, fields, generation):
        bundle = {}
        for name, value in dict(fields).items():
            if not isinstance(name, str) or not name:
                raise ValueError("invalid field name")
            if isinstance(value, str):
                value = SecretStr(value)
            if not isinstance(value, SecretStr):
                raise ValueError("invalid field value")
            bundle[name] = value
        object.__setattr__(self, "fields", MappingProxyType(bundle))
        object.__setattr__(self, "generation", int(generation))

    def __setattr__(self, name, value):
        raise AttributeError("SecretValue is immutable")

    def __delattr__(self, name):
        raise AttributeError("SecretValue is immutable")

    def __reduce__(self):
        raise TypeError("SecretValue cannot be copied or pickled")

    def __repr__(self):
        return f"SecretValue(fields={sorted(self.fields)}, generation={self.generation})"

    __str__ = __repr__


@dataclass(frozen=True)
class SecretMetadata:
    """ What the store knows about a reference: versions present and the vendor request id """

    current_version: int
    versions: frozenset
    request_id: "str | None" = None


class SecretStore(Protocol):
    """ Port implemented by every adapter. generation == store version, starting at 1 """

    def read(self, ref: StoreRef, generation: int, ctx: AuthorizedStoreContext) -> SecretValue:
        """ Material at one generation; NOT_FOUND if absent """

    def read_many(self, refs: Sequence[StoreRef], generations: Sequence[int],
                  ctx: "AuthorizedStoreContext | Sequence[AuthorizedStoreContext]"
                  ) -> "dict[tuple[uuid.UUID, int], SecretValue]":
        """ Material for refs[i] at generations[i], keyed (ref.ref_id, generation); same purposes as read.

        ctx is one context per ref (parallel to refs), or a single context when every ref is its ref_id.
        All-or-nothing: one failing ref fails the whole call (StoreError.details["ref_id"]), no partial material.
        """

    def write(self, ref: StoreRef, value: SecretValue, *, expected_version: int,
              ctx: AuthorizedStoreContext) -> SecretMetadata:
        """ Compare-and-set: stores generation expected_version + 1, else VERSION_CONFLICT """

    def metadata(self, ref: StoreRef, ctx: AuthorizedStoreContext) -> SecretMetadata:
        """ Versions present (current_version 0 and no versions when nothing is stored) """

    def prune(self, ref: StoreRef, keep_generations: int, ctx: AuthorizedStoreContext) -> SecretMetadata:
        """ Drop all but the newest keep_generations (>= 1) generations; returns what remains """

    def delete_all(self, ref: StoreRef, ctx: AuthorizedStoreContext) -> None:
        """ Remove every generation of the reference (retire / orphan); idempotent """


def check_context(ctx, ref, operation):
    """ Adapter-side re-check: genuine context, same ref and project, purpose fits the operation """
    if (
            type(ctx) is not AuthorizedStoreContext  # pylint: disable=C0123
            or ctx.ref_id != ref.ref_id
            or ctx.project_id != ref.project_id
            or ctx.purpose not in OPERATION_PURPOSES[operation]
    ):
        raise StoreError("DENIED", {"ref_id": str(ref.ref_id)})


MAX_READ_MANY = 64  # refs per read_many call (one release batch is a handful of slots)


def plan_read_many(refs, generations, ctx):
    """ Validate a read_many call before any I/O; returns [(ref, generation, ctx)] without duplicate pairs.

    Raises ValueError for malformed arguments (programming errors) and StoreError("DENIED") for a context
    that does not fit its ref or the read purposes, so a refused batch has no store effect.
    """
    refs, generations = list(refs), [int(item) for item in generations]
    contexts = list(ctx) if isinstance(ctx, (list, tuple)) else [ctx] * len(refs)
    if len(refs) != len(generations) or len(refs) != len(contexts) or len(refs) > MAX_READ_MANY:
        raise ValueError("invalid read_many arguments")
    planned, seen = [], set()
    for ref, generation, item_ctx in zip(refs, generations, contexts):
        check_context(item_ctx, ref, "read")
        if (ref.ref_id, generation) not in seen:
            seen.add((ref.ref_id, generation))
            planned.append((ref, generation, item_ctx))
    return planned


def get_store(store_kind: str, *, governed: bool) -> SecretStore:
    """ Adapter for a store kind, or StoreError("UNAVAILABLE"). No fallback to another store """
    from tools import config as c  # pylint: disable=E0401,C0415
    #
    if store_kind == "database":
        if getattr(c, "SECRETS_ENGINE", None) != "database":
            raise StoreError("UNAVAILABLE")
        if governed and not getattr(c, "SECRETS_MASTER_KEY", None):
            raise StoreError("UNAVAILABLE")
        module = importlib.import_module(".database", __package__)
        return module.DatabaseSecretStore()
    #
    if store_kind == "corporate_vault":
        if not governed or not getattr(c, "CORPORATE_VAULT_ADDR", None):
            raise StoreError("UNAVAILABLE")
        module = importlib.import_module(".corporate_vault", __package__)
        return module.get_store()
    #
    # managed_vault: adapter deferred (per-project approle/root-token model does not fit
    # per-reference paths); anything else is unknown
    raise StoreError("UNAVAILABLE")
