"""Unit tests for the atomic update_secrets/update_hidden_secrets API (issue #5906)."""
import json
import sys
from pathlib import Path

from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fixtures.secret_engines_loader import load_secret_engines  # noqa: E402  pylint: disable=C0413

database, mock = load_secret_engines()


class _FakeQuery:
    """Mimics session.query(SecretsData).filter(...).with_for_update().one()"""

    def __init__(self, row):
        self._row = row

    def filter(self, *a, **kw):
        return self

    def with_for_update(self):
        return self

    def one(self):
        return self._row


class _FakeSession:
    """Records commit()/rollback() calls; used as the `with ... as session` value."""

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
    """
    Build a database.Engine with a real Fernet key and a fake DB session whose
    query returns a row pre-populated with `section_data` (e.g. {"secrets": {...}}).
    """
    encrypted_row = _FakeRow(Fernet(fernet_key).encrypt(json.dumps(section_data).encode()))
    fake_session = _FakeSession(encrypted_row)

    engine = database.Engine.__new__(database.Engine)
    engine.project_id = 1
    engine._cache = {"secrets": {}, "hidden_secrets": {}, "shared_secrets": {}}
    engine.master_key = None
    engine._read_key = lambda: fernet_key
    database.context.db.make_session = lambda *a, **kw: fake_session

    return engine, fake_session, encrypted_row


def test_update_section_merges_add_without_dropping_existing_keys():
    key = Fernet.generate_key()
    engine, _session, row = _make_database_engine(
        {"secrets": {"existing": "1"}, "hidden_secrets": {}}, key,
    )

    result = engine.update_secrets(add={"new_key": "v"})

    assert result == {"existing": "1", "new_key": "v"}
    decrypted = json.loads(Fernet(key).decrypt(row.data).decode())
    assert decrypted["secrets"] == {"existing": "1", "new_key": "v"}


def test_update_section_removes_keys():
    key = Fernet.generate_key()
    engine, _session, row = _make_database_engine(
        {"secrets": {"keep": "1", "drop": "2"}, "hidden_secrets": {}}, key,
    )

    result = engine.update_secrets(remove=["drop"])

    assert result == {"keep": "1"}
    decrypted = json.loads(Fernet(key).decrypt(row.data).decode())
    assert decrypted["secrets"] == {"keep": "1"}


def test_update_section_commits_exactly_once():
    key = Fernet.generate_key()
    engine, session, _row = _make_database_engine(
        {"secrets": {}, "hidden_secrets": {}}, key,
    )

    engine.update_secrets(add={"k": "v"})

    assert session.commits == 1
    assert session.rollbacks == 0


def test_update_section_updates_local_cache():
    key = Fernet.generate_key()
    engine, _session, _row = _make_database_engine(
        {"secrets": {}, "hidden_secrets": {}}, key,
    )

    engine.update_secrets(add={"k": "v"})

    assert engine._cache["secrets"] == {"k": "v"}


def test_update_hidden_secrets_targets_hidden_section_only():
    key = Fernet.generate_key()
    engine, _session, row = _make_database_engine(
        {"secrets": {"regular": "1"}, "hidden_secrets": {"hidden": "1"}}, key,
    )

    engine.update_hidden_secrets(add={"new_hidden": "v"})

    decrypted = json.loads(Fernet(key).decrypt(row.data).decode())
    assert decrypted["secrets"] == {"regular": "1"}
    assert decrypted["hidden_secrets"] == {"hidden": "1", "new_hidden": "v"}


def _make_mock_engine():
    engine = mock.Engine.__new__(mock.Engine)
    engine.project_id = 1
    engine._cache = {"secrets": {}, "hidden_secrets": {}, "shared_secrets": {}}
    mock.Engine.storage = {engine.secrets_key: {"secrets": {}, "hidden_secrets": {}}}
    return engine


def test_mock_engine_update_secrets_merges_against_storage():
    engine = _make_mock_engine()
    engine.set_secrets({"existing": "1"})

    result = engine.update_secrets(add={"new_key": "v"}, remove=None)

    assert result == {"existing": "1", "new_key": "v"}
    assert mock.Engine.storage[engine.secrets_key]["secrets"] == {
        "existing": "1", "new_key": "v",
    }


def test_mock_engine_update_hidden_secrets_merges_and_removes():
    engine = _make_mock_engine()
    engine.set_hidden_secrets({"keep": "1", "drop": "2"})

    result = engine.update_hidden_secrets(add={"added": "v"}, remove=["drop"])

    assert result == {"keep": "1", "added": "v"}
