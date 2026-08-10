"""
Loads shared.rpc.storage_cleanup as a real module for testing, without pulling
in shared/__init__.py (needs pylon.core.tools.module.ModuleModel) or the
minio_client/libcloud dependency chain (boto3/apache-libcloud, not installed
on the bare host Python that runs these tests).
"""
import importlib.util
import sys
import types
from pathlib import Path

SHARED_ROOT = Path(__file__).resolve().parent.parent.parent


def _load_file_as_module(name, path, package):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    module.__package__ = package
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_storage_cleanup():
    """Return the storage_cleanup module, loading it (and fake parent
    packages / a stubbed MinioClient+ManualCleanupMixin) on first call, from
    cache after."""
    cached = sys.modules.get("shared.rpc.storage_cleanup")
    if cached is not None:
        return cached

    for name, subpath in (
        ("shared", SHARED_ROOT),
        ("shared.tools", SHARED_ROOT / "tools"),
        ("shared.tools.storage_engines", SHARED_ROOT / "tools" / "storage_engines"),
        ("shared.rpc", SHARED_ROOT / "rpc"),
    ):
        mod = types.ModuleType(name)
        mod.__path__ = [str(subpath)]
        sys.modules[name] = mod

    fake_minio_client = types.ModuleType("shared.tools.minio_client")

    class MinioClient:  # pylint: disable=too-few-public-methods
        """Stand-in; tests monkeypatch this per-case."""

        def __init__(self, project):
            self.project = project

    fake_minio_client.MinioClient = MinioClient
    sys.modules["shared.tools.minio_client"] = fake_minio_client

    fake_libcloud = types.ModuleType("shared.tools.storage_engines.libcloud")

    class ManualCleanupMixin:  # pylint: disable=too-few-public-methods
        """Stand-in for the real mixin; identity is all storage_cleanup checks."""

    fake_libcloud.ManualCleanupMixin = ManualCleanupMixin
    sys.modules["shared.tools.storage_engines.libcloud"] = fake_libcloud

    return _load_file_as_module(
        "shared.rpc.storage_cleanup", SHARED_ROOT / "rpc" / "storage_cleanup.py",
        package="shared.rpc",
    )
