"""
Loads shared.tools.vault_tools as a real module for testing.

hvac ships with pylon rather than with this repo's dev requirements, and db/rpc_tools/
models.vault drag in flask_sqlalchemy, so all of those are stubbed. Everything the tests
actually exercise (the external-access CAS retry loop) lives in vault_tools itself.

run_tests.py already installs the pylon and tools stubs, so this only fills in the extra
config attributes vault_tools reads at import time.
"""
import sys
import types
from pathlib import Path

from ._module_loader import load_file_as_module

SHARED_ROOT = Path(__file__).resolve().parent.parent.parent

_VAULT_CONFIG = {
    "VAULT_ADMINISTRATION_NAME": "administration",
    "VAULT_URL": "http://vault.invalid",
    "VAULT_DB_PK": 1,
    # managed_vault keeps the import-time engine selection from importing a plugin path
    "SECRETS_ENGINE": "managed_vault",
}


class InvalidRequest(Exception):
    """Vault rejected the request, e.g. a check-and-set version mismatch."""


class InvalidPath(Exception):
    """Nothing stored at that path, or the mount does not exist."""


class Forbidden(Exception):
    """Token lacks the capability on that path."""


def _ensure_module(name, **attrs):
    module = sys.modules.get(name)
    if module is None:
        module = types.ModuleType(name)
        sys.modules[name] = module
    for key, value in attrs.items():
        setattr(module, key, value)
    return module


def load_vault_tools():
    """Return the vault_tools module, loading it (and its stubbed deps) on first call."""
    cached = sys.modules.get("shared.tools.vault_tools")
    if cached is not None:
        return cached

    # secret_engines_loader owns the fake shared/shared.tools/shared.models packages and
    # supplies get_project_id, which vault_tools imports.
    from .secret_engines_loader import load_secret_engines  # pylint: disable=C0415
    load_secret_engines()

    hvac_exceptions = _ensure_module(
        "hvac.exceptions",
        InvalidRequest=InvalidRequest, InvalidPath=InvalidPath, Forbidden=Forbidden,
    )
    _ensure_module("hvac", Client=object, exceptions=hvac_exceptions)

    config = _ensure_module("tools.config", **_VAULT_CONFIG)
    _ensure_module("tools", config=config)

    _ensure_module("shared.tools.db")
    _ensure_module("shared.tools.rpc_tools", RpcMixin=object)
    _ensure_module("shared.models.vault", Vault=object)

    return load_file_as_module(
        "shared.tools.vault_tools", SHARED_ROOT / "tools" / "vault_tools.py",
        package="shared.tools",
    )
