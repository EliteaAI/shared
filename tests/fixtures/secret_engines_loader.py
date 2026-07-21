"""
Loads shared.tools.secret_engines.database/mock as real modules for testing,
without pulling in shared/tools/db.py or shared/models/secrets.py (both drag in
flask_sqlalchemy, which is unneeded here and clashes with the stdlib `secrets`
module when this plugins/ tree is anywhere on sys.path).
"""
import importlib.util
import sys
import types
from pathlib import Path

SHARED_ROOT = Path(__file__).resolve().parent.parent.parent
ENGINES_DIR = SHARED_ROOT / "tools" / "secret_engines"


def _load_file_as_module(name, path, package):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    module.__package__ = package
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_secret_engines():
    """Return (database_module, mock_module), loading them (and fake parent
    packages / a stubbed models.secrets) on first call, from cache after."""
    cached = sys.modules.get("shared.tools.secret_engines.database")
    if cached is not None:
        return cached, sys.modules["shared.tools.secret_engines.mock"]

    for name, subpath in (
        ("shared", SHARED_ROOT),
        ("shared.tools", SHARED_ROOT / "tools"),
        ("shared.models", SHARED_ROOT / "models"),
    ):
        mod = types.ModuleType(name)
        mod.__path__ = [str(subpath)]
        sys.modules[name] = mod

    fake_models_secrets = types.ModuleType("shared.models.secrets")

    class SecretsKey:  # pylint: disable=too-few-public-methods
        id = None  # class-level so `SecretsKey.id == x` (used in .filter()) doesn't raise
        data = None

        def __init__(self, id=None, data=None):  # pylint: disable=redefined-builtin
            self.id = id
            self.data = data

    class SecretsData:  # pylint: disable=too-few-public-methods
        id = None
        data = None

        def __init__(self, id=None, data=None):  # pylint: disable=redefined-builtin
            self.id = id
            self.data = data

    fake_models_secrets.SecretsKey = SecretsKey
    fake_models_secrets.SecretsData = SecretsData
    sys.modules["shared.models.secrets"] = fake_models_secrets

    engines_pkg = _load_file_as_module(
        "shared.tools.secret_engines", ENGINES_DIR / "__init__.py",
        package="shared.tools.secret_engines",
    )
    engines_pkg.__path__ = [str(ENGINES_DIR)]

    database_mod = _load_file_as_module(
        "shared.tools.secret_engines.database", ENGINES_DIR / "database.py",
        package="shared.tools.secret_engines",
    )
    mock_mod = _load_file_as_module(
        "shared.tools.secret_engines.mock", ENGINES_DIR / "mock.py",
        package="shared.tools.secret_engines",
    )
    return database_mod, mock_mod
