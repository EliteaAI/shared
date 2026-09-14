"""Unit tests for the per-secret external_access flag store (issue #5633).

The flag is what lets a code node in a shared project read a secret from the executing
user's personal project, so its default must be deny and no migration may be required
for projects created before the store existed.
"""
import json
import sys
from pathlib import Path

from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fixtures.secret_engines_loader import load_secret_engines  # noqa: E402  pylint: disable=C0413

database, mock = load_secret_engines()

_EMPTY_CACHE = {
    "secrets": {},
    "hidden_secrets": {},
    "shared_secrets": {},
    "external_access": {},
}


class _FakeQuery:
    def __init__(self, row):
        self._row = row

    def filter(self, *a, **kw):
        return self

    def with_for_update(self):
        return self

    def get(self, *a, **kw):
        return self._row

    def one(self):
        return self._row


class _FakeSession:
    def __init__(self, row):
        self._row = row
        self.commits = 0
        self.rollbacks = 0

    def query(self, *a, **kw):
        return _FakeQuery(self._row)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class _FakeRow:  # pylint: disable=too-few-public-methods
    def __init__(self, data):
        self.id = "project-1"
        self.data = data


def _make_database_engine(section_data, fernet_key):
    encrypted_row = _FakeRow(Fernet(fernet_key).encrypt(json.dumps(section_data).encode()))
    engine = database.Engine.__new__(database.Engine)
    engine.project_id = 1
    engine._cache = dict(_EMPTY_CACHE)
    engine.master_key = None
    engine._read_key = lambda: fernet_key
    database.context.db.make_session = lambda *a, **kw: _FakeSession(encrypted_row)
    return engine, encrypted_row


def _make_mock_engine(stored=None):
    engine = mock.Engine.__new__(mock.Engine)
    engine.project_id = 1
    engine._cache = dict(_EMPTY_CACHE)
    mock.Engine.storage = {
        engine.secrets_key: stored if stored is not None else {"secrets": {}, "hidden_secrets": {}},
    }
    return engine


# --- default-off / no migration -------------------------------------------------


def test_legacy_blob_without_section_denies_everything():
    """A project created before the store existed must read as 'nothing shared'."""
    key = Fernet.generate_key()
    engine, _row = _make_database_engine(
        {"secrets": {"TOKEN": "v"}, "hidden_secrets": {}}, key,
    )

    assert engine.get_external_access() == {}


def test_base_engine_legacy_blob_without_section_denies_everything():
    engine = _make_mock_engine({"secrets": {"TOKEN": "v"}, "hidden_secrets": {}})

    assert engine.get_external_access() == {}


def test_creating_a_secret_does_not_share_it():
    engine = _make_mock_engine()

    engine.set_secrets({"TOKEN": "v"})

    assert engine.get_external_access().get("TOKEN", False) is False


def test_getter_returns_a_copy_so_callers_cannot_grant_access_in_place():
    engine = _make_mock_engine()
    engine.set_external_access({"TOKEN": True})

    engine.get_external_access()["OTHER"] = True

    assert engine.get_external_access() == {"TOKEN": True}


# --- base engine (filesystem/mock) ----------------------------------------------


def test_base_engine_set_and_get_roundtrip():
    engine = _make_mock_engine()

    engine.set_external_access({"TOKEN": True, "OTHER": False})

    assert engine.get_external_access() == {"TOKEN": True, "OTHER": False}
    assert mock.Engine.storage[engine.secrets_key]["external_access"] == {
        "TOKEN": True, "OTHER": False,
    }


def test_base_engine_update_merges_and_removes():
    engine = _make_mock_engine()
    engine.set_external_access({"KEEP": True, "DROP": True})

    result = engine.update_external_access(add={"ADDED": True}, remove=["DROP"])

    assert result == {"KEEP": True, "ADDED": True}
    assert engine.get_external_access() == {"KEEP": True, "ADDED": True}


def test_base_engine_flag_writes_leave_secrets_untouched():
    engine = _make_mock_engine()
    engine.set_secrets({"TOKEN": "v"})
    engine.set_hidden_secrets({"HIDDEN": "h"})

    engine.update_external_access(add={"TOKEN": True})

    assert engine.get_secrets() == {"TOKEN": "v"}
    assert engine.get_hidden_secrets() == {"HIDDEN": "h"}


# --- database engine (row-locking overrides) ------------------------------------


def test_database_engine_set_writes_only_its_own_section():
    key = Fernet.generate_key()
    engine, row = _make_database_engine(
        {"secrets": {"TOKEN": "v"}, "hidden_secrets": {"HIDDEN": "h"}}, key,
    )

    engine.set_external_access({"TOKEN": True})

    decrypted = json.loads(Fernet(key).decrypt(row.data).decode())
    assert decrypted["external_access"] == {"TOKEN": True}
    assert decrypted["secrets"] == {"TOKEN": "v"}
    assert decrypted["hidden_secrets"] == {"HIDDEN": "h"}


def test_database_engine_update_merges_against_stored_section():
    key = Fernet.generate_key()
    engine, row = _make_database_engine(
        {"secrets": {}, "hidden_secrets": {}, "external_access": {"KEEP": True, "DROP": True}}, key,
    )

    result = engine.update_external_access(add={"ADDED": True}, remove=["DROP"])

    assert result == {"KEEP": True, "ADDED": True}
    decrypted = json.loads(Fernet(key).decrypt(row.data).decode())
    assert decrypted["external_access"] == {"KEEP": True, "ADDED": True}


def test_database_engine_update_on_legacy_blob_adds_section_without_loss():
    key = Fernet.generate_key()
    engine, row = _make_database_engine(
        {"secrets": {"TOKEN": "v"}, "hidden_secrets": {}}, key,
    )

    engine.update_external_access(add={"TOKEN": True})

    decrypted = json.loads(Fernet(key).decrypt(row.data).decode())
    assert decrypted["external_access"] == {"TOKEN": True}
    assert decrypted["secrets"] == {"TOKEN": "v"}


def test_database_engine_update_refreshes_local_cache():
    key = Fernet.generate_key()
    engine, _row = _make_database_engine({"secrets": {}, "hidden_secrets": {}}, key)

    engine.update_external_access(add={"TOKEN": True})

    assert engine._cache["external_access"] == {"TOKEN": True}
