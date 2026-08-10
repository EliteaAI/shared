"""
Loads shared.tools.storage_engines.libcloud (the storage-engine impl module,
not the external `libcloud` package) as a real module for testing.

Stubs the external `libcloud` package (not installed on the bare host Python
that runs these tests) and the db/model/tool dependency chain. The pure
`storage_engines/__init__.py` (encoding, lifecycle_from_meta) and
`storage_mixin.py` are loaded as real modules so the highest-risk logic
(encoding round-trips, lifecycle extraction) runs as actually written.
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


def _install_fake_libcloud():
    if "libcloud" in sys.modules:
        return
    types_mod = types.ModuleType("libcloud.storage.types")
    providers_mod = types.ModuleType("libcloud.storage.providers")
    types_mod.Provider = types.SimpleNamespace()
    providers_mod.get_driver = lambda *a, **kw: None
    sys.modules["libcloud"] = types.ModuleType("libcloud")
    sys.modules["libcloud.storage"] = types.ModuleType("libcloud.storage")
    sys.modules["libcloud.storage.types"] = types_mod
    sys.modules["libcloud.storage.providers"] = providers_mod


class InCol:
    """Stand-in for a SQLAlchemy Column supporting only `.in_()`, as used by load_metas."""

    def in_(self, values):
        return ("in", list(values))


class StorageMeta:  # pylint: disable=too-few-public-methods
    """Stand-in for the real model; id/data are all storage_engines touches."""

    id = InCol()

    def __init__(self, id=None, data=None):  # pylint: disable=redefined-builtin
        self.id = id
        self.data = data


class FakeQuery:
    """Stand-in for session.query(StorageMeta); supports .get() and .filter(...in_()...)."""

    def __init__(self, rows):
        self._rows = rows
        self._filtered_ids = None

    def get(self, id_):
        data = self._rows.get(id_)
        return None if data is None else StorageMeta(id=id_, data=data)

    def filter(self, condition):
        _, ids = condition
        self._filtered_ids = ids
        return self

    def __iter__(self):
        ids = self._filtered_ids if self._filtered_ids is not None else list(self._rows)
        for id_ in ids:
            if id_ in self._rows:
                yield StorageMeta(id=id_, data=self._rows[id_])


class FakeSession:
    def __init__(self, rows):
        self._rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def query(self, model):
        _ = model
        return FakeQuery(self._rows)

    def add(self, obj):
        self._rows[obj.id] = obj.data

    def commit(self):
        pass

    def rollback(self):
        pass


class FakeDb:
    """Counts make_session() calls -- the I/O-count acceptance criterion from the plan."""

    def __init__(self, rows=None):
        self.rows = rows if rows is not None else {}
        self.make_session_calls = 0

    def make_session(self):
        self.make_session_calls += 1
        return FakeSession(self.rows)


class FakeContext:
    def __init__(self, rows=None):
        self.db = FakeDb(rows)
        self.event_manager = types.SimpleNamespace()
        self.rpc_manager = types.SimpleNamespace()


class FakeContainer:
    def __init__(self, name):
        self.name = name


class FakeDriver:
    """Counts iterate_containers() calls -- the other I/O-count acceptance criterion."""

    def __init__(self, container_names):
        self._containers = [FakeContainer(n) for n in container_names]
        self.iterate_containers_calls = 0

    def iterate_containers(self):
        self.iterate_containers_calls += 1
        return iter(self._containers)


def load_libcloud_engine():
    """Return the storage_engines.libcloud module, loading it (and stubbed
    parents/StorageMeta/minio_tools) on first call, from cache after."""
    cached = sys.modules.get("shared.tools.storage_engines.libcloud")
    if cached is not None:
        return cached

    _install_fake_libcloud()

    tools_stub = sys.modules["tools"]
    if not hasattr(tools_stub, "this"):
        tools_stub.this = types.SimpleNamespace(descriptor=types.SimpleNamespace(config={}))

    for name, subpath in (
        ("shared", SHARED_ROOT),
        ("shared.tools", SHARED_ROOT / "tools"),
        ("shared.tools.storage_engines", SHARED_ROOT / "tools" / "storage_engines"),
        ("shared.models", SHARED_ROOT / "models"),
    ):
        if name in sys.modules:
            continue
        mod = types.ModuleType(name)
        mod.__path__ = [str(subpath)]
        sys.modules[name] = mod

    _load_file_as_module(
        "shared.tools.storage_engines", SHARED_ROOT / "tools" / "storage_engines" / "__init__.py",
        package="shared.tools.storage_engines",
    )

    fake_db = types.ModuleType("shared.tools.db")
    sys.modules["shared.tools.db"] = fake_db

    fake_minio_tools = types.ModuleType("shared.tools.minio_tools")
    fake_minio_tools.space_monitor = lambda f: f
    fake_minio_tools.throughput_monitor = lambda *a, **kw: None
    sys.modules["shared.tools.minio_tools"] = fake_minio_tools

    fake_storage_model = types.ModuleType("shared.models.storage")
    fake_storage_model.StorageMeta = StorageMeta
    sys.modules["shared.models.storage"] = fake_storage_model

    _load_file_as_module(
        "shared.tools.storage_engines.storage_mixin",
        SHARED_ROOT / "tools" / "storage_engines" / "storage_mixin.py",
        package="shared.tools.storage_engines",
    )

    return _load_file_as_module(
        "shared.tools.storage_engines.libcloud", SHARED_ROOT / "tools" / "storage_engines" / "libcloud.py",
        package="shared.tools.storage_engines",
    )
