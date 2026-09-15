"""Unit tests for the per-secret external_access flag store (issue #5633).

The flag is what lets a code node in a shared project read a secret from the executing
user's personal project, so its default must be deny and no migration may be required
for projects created before the store existed.
"""
import json
import sys
import types
from pathlib import Path

from cryptography.fernet import Fernet

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fixtures.secret_engines_loader import load_secret_engines  # noqa: E402  pylint: disable=C0413
from fixtures.vault_tools_loader import (  # noqa: E402  pylint: disable=C0413
    InvalidPath,
    InvalidRequest,
    load_vault_tools,
)

database, mock = load_secret_engines()
vault_tools = load_vault_tools()

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


class _FakeKvV2:
    """Minimal KV v2 with real check-and-set semantics.

    on_write is called before each write with the attempt number, so a test can simulate
    another writer landing between our read and our write.
    """

    def __init__(self, stored=None, version=0, on_write=None):
        self.entry = None if stored is None else {"data": dict(stored), "version": version}
        self.on_write = on_write
        self.writes = []
        self.reads = 0
        self.attempts = 0

    def read_secret_version(self, path, mount_point):  # pylint: disable=unused-argument
        self.reads += 1
        if self.entry is None:
            raise InvalidPath("no data at that path")
        return {"data": {
            "data": dict(self.entry["data"]),
            "metadata": {"version": self.entry["version"]},
        }}

    def create_or_update_secret(self, path, mount_point, secret, cas=None):  # pylint: disable=unused-argument
        self.attempts += 1
        if self.on_write is not None:
            self.on_write(self, self.attempts)
        current = 0 if self.entry is None else self.entry["version"]
        if cas is not None and cas != current:
            raise InvalidRequest("check-and-set parameter did not match the current version")
        self.writes.append({"secret": dict(secret), "cas": cas})
        self.entry = {"data": dict(secret), "version": current + 1}

    def force_write(self, secret):
        """Stand-in for a concurrent writer that already committed."""
        current = 0 if self.entry is None else self.entry["version"]
        self.entry = {"data": dict(secret), "version": current + 1}


def _make_vault_engine(stored=None, version=0, on_write=None):
    engine = vault_tools.HashiCorpVaultClient.__new__(vault_tools.HashiCorpVaultClient)
    engine.project_id = 1
    engine.vault_name = 1
    engine.external_kv_mount = "kv-for-external-1"
    engine._cache = dict(_EMPTY_CACHE)
    engine._ensure_external_kv = lambda: None
    kv = _FakeKvV2(stored=stored, version=version, on_write=on_write)
    engine._client = types.SimpleNamespace(secrets=types.SimpleNamespace(kv=types.SimpleNamespace(v2=kv)))
    return engine, kv


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


# --- managed Vault engine (KV v2 check-and-set) ----------------------------------


def test_vault_engine_update_writes_with_the_version_it_read():
    engine, kv = _make_vault_engine({"KEEP": True}, version=7)

    result = engine.update_external_access(add={"ADDED": True})

    assert result == {"KEEP": True, "ADDED": True}
    assert kv.writes[0]["cas"] == 7


def test_vault_engine_first_write_uses_cas_zero_for_absent_mount():
    """cas=0 means 'only if this key does not exist yet', so two first-writers can't both win."""
    engine, kv = _make_vault_engine(stored=None)

    engine.update_external_access(add={"TOKEN": True})

    assert kv.writes[0]["cas"] == 0
    assert kv.entry["data"] == {"TOKEN": True}


def test_vault_engine_concurrent_revoke_is_not_undone_by_a_grant():
    """The review scenario: a grant racing a revoke must not resurrect the revoked flag."""
    def revoke_everything_before_first_write(kv, attempt):
        if attempt == 1:
            kv.force_write({})

    engine, kv = _make_vault_engine(
        {"A": True}, version=1, on_write=revoke_everything_before_first_write,
    )

    result = engine.update_external_access(add={"C": True})

    assert result == {"C": True}, "A was revoked concurrently and must stay revoked"
    assert kv.entry["data"] == {"C": True}
    assert len(kv.writes) == 1, "the losing write must be rejected, not stored"
    assert kv.reads == 2, "the retry has to re-read rather than reuse the stale snapshot"


def test_vault_engine_retry_merges_onto_the_winners_result():
    def grant_b_before_first_write(kv, attempt):
        if attempt == 1:
            kv.force_write({"A": True, "B": True})

    engine, _kv = _make_vault_engine(
        {"A": True}, version=1, on_write=grant_b_before_first_write,
    )

    result = engine.update_external_access(add={"C": True})

    assert result == {"A": True, "B": True, "C": True}


def test_vault_engine_removal_survives_a_race():
    def grant_c_before_first_write(kv, attempt):
        if attempt == 1:
            kv.force_write({"A": True, "C": True})

    engine, kv = _make_vault_engine(
        {"A": True}, version=1, on_write=grant_c_before_first_write,
    )

    result = engine.update_external_access(remove=["A"])

    assert result == {"C": True}
    assert kv.entry["data"] == {"C": True}


def test_vault_engine_raises_rather_than_writing_a_stale_map():
    """Losing every attempt must fail loudly: silently dropping the write loses an intent."""
    def always_move_the_version(kv, _attempt):
        kv.force_write({"MOVED": True})

    engine, kv = _make_vault_engine(
        {"A": True}, version=1, on_write=always_move_the_version,
    )

    with pytest.raises(RuntimeError, match="CAS races"):
        engine.update_external_access(add={"C": True})

    assert kv.writes == [], "no attempt may be persisted"
    assert "C" not in kv.entry["data"]


def test_vault_engine_update_ignores_a_stale_local_cache():
    engine, kv = _make_vault_engine({"FRESH": True}, version=3)
    engine._cache["external_access"] = {"STALE": True}

    result = engine.update_external_access(add={"ADDED": True})

    assert result == {"FRESH": True, "ADDED": True}
    assert "STALE" not in kv.entry["data"]
