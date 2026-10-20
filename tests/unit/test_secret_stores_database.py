"""Database adapter specifics and the additive `check=` hook of Engine._update_section (C-1009 #6757)."""
import json
from importlib import import_module

import pytest

from fixtures.secret_stores_loader import FakeSecretsDb, load_secret_stores, mint, new_ref

stores = load_secret_stores()


@pytest.fixture(name="db")
def _db(monkeypatch):
    import tools  # pylint: disable=C0415
    monkeypatch.setattr(tools.config, "SECRETS_MASTER_KEY", None)
    fake = FakeSecretsDb()
    fake.install()
    return fake


@pytest.fixture(name="store")
def _store(db):
    _ = db
    return import_module(f"{stores.__name__}.database").DatabaseSecretStore()


def _engine(db):
    return db.install().Engine(project={"id": 1})


def test_check_none_keeps_todays_behaviour(db):
    result = _engine(db).update_secrets(add={"n": "v"})
    assert result == {"keep": "kept", "n": "v"} and db.commits == 1 and db.rollbacks == 0


def test_check_runs_on_current_section_and_can_allow(db):
    seen = []
    _engine(db)._update_section(  # pylint: disable=W0212
        "credential_store", add={"k": "v"}, check=lambda current: seen.append(dict(current)) or True)
    assert seen == [{}] and db.section(1, "credential_store") == {"k": "v"}


def test_check_failure_writes_nothing_and_rolls_back(db):
    database = db.install()
    before = db.raw(1)
    with pytest.raises(database.SectionCheckFailed):
        _engine(db)._update_section("secrets", add={"n": "v"}, check=lambda current: False)  # pylint: disable=W0212
    assert db.raw(1) == before and db.commits == 0 and db.rollbacks == 1


def test_material_lives_in_its_own_section_and_other_sections_are_untouched(db, store):
    ref = new_ref(stores, 1)
    store.write(ref, stores.SecretValue({"api_key": "key-fixture"}, 1), expected_version=0,
                ctx=mint(stores, "onboard", ref))
    data = db.decrypted(1)
    assert data["secrets"] == {"keep": "kept"} and data["hidden_secrets"] == {"h": "hidden"}
    assert data["credential_store"] == {f"{ref.ref_id.hex}:1": {"api_key": "key-fixture"}}
    # template resolution merges secrets + hidden_secrets only: the reference's material is unreachable
    engine = _engine(db)
    assert "key-fixture" not in json.dumps({**engine._read()["secrets"], **engine._read()["hidden_secrets"]})  # pylint: disable=W0212
    assert "key-fixture" not in db.raw(1).decode(errors="replace")  # encrypted at rest


def test_projects_are_isolated(db, store):
    ref = new_ref(stores, 1)
    store.write(ref, stores.SecretValue({"a": "b"}, 1), expected_version=0, ctx=mint(stores, "onboard", ref))
    assert db.section(2, "credential_store") is None
    foreign = stores.StoreRef(ref.ref_id, 2, "database", {})
    with pytest.raises(stores.StoreError) as raised:
        store.read(foreign, 1, mint(stores, "probe", foreign))
    assert raised.value.code == "NOT_FOUND"


def test_cas_runs_under_the_row_lock_with_one_commit(db, store):
    ref = new_ref(stores, 1)
    store.write(ref, stores.SecretValue({"a": "b"}, 1), expected_version=0, ctx=mint(stores, "onboard", ref))
    assert db.commits == 1
    with pytest.raises(stores.StoreError):
        store.write(ref, stores.SecretValue({"a": "c"}, 1), expected_version=0, ctx=mint(stores, "onboard", ref))
    assert db.commits == 1 and db.rollbacks == 1


def test_infrastructure_failure_is_unavailable_without_leaking_text(db, store):
    ref = new_ref(stores, 1)
    database = db.install()
    database.context.db.make_session = lambda *a, **kw: (_ for _ in ()).throw(
        RuntimeError("postgres://user:pw-fixture@host/db"))
    for call in (
            lambda: store.read(ref, 1, mint(stores, "probe", ref)),
            lambda: store.metadata(ref, mint(stores, "probe", ref)),
            lambda: store.delete_all(ref, mint(stores, "retire", ref)),
            lambda: store.write(ref, stores.SecretValue({"a": "b"}, 1), expected_version=0,
                                ctx=mint(stores, "onboard", ref)),
    ):
        with pytest.raises(stores.StoreError) as raised:
            call()
        assert raised.value.code == "UNAVAILABLE"
        assert "pw-fixture" not in str(raised.value) and raised.value.__cause__ is None
        assert raised.value.__suppress_context__


def test_second_writer_with_the_same_expected_version_conflicts(db, store):
    ref = new_ref(stores, 1)
    results = []
    for value in ("0", "1"):
        try:
            store.write(ref, stores.SecretValue({"v": value}, 1), expected_version=0, ctx=mint(stores, "onboard", ref))
            results.append("ok")
        except stores.StoreError as exc:
            results.append(exc.code)
    assert results == ["ok", "VERSION_CONFLICT"]
    assert store.metadata(ref, mint(stores, "probe", ref)).versions == frozenset({1})
