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


def test_material_lives_in_its_own_row_and_the_legacy_blob_is_untouched(db, store):
    ref = new_ref(stores, 1)
    legacy_before = db.raw(1)
    store.write(ref, stores.SecretValue({"api_key": "key-fixture"}, 1), expected_version=0,
                ctx=mint(stores, "onboard", ref))
    assert db.decrypted(1, governed=True) == {f"{ref.ref_id.hex}:1": {"api_key": "key-fixture"}}
    # the legacy blob is not even re-encrypted: governed material never enters it
    assert db.raw(1) == legacy_before
    assert db.decrypted(1) == {"secrets": {"keep": "kept"}, "hidden_secrets": {"h": "hidden"}}
    assert "key-fixture" not in db.raw(1, governed=True).decode(errors="replace")  # encrypted at rest


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


# -- read_many / S10 row split / prune (perf PR 1) ----------------------------------------------


@pytest.fixture(name="decrypts")
def _decrypts(db, monkeypatch):
    """ Input lengths of every Fernet.decrypt the engine performs (key unwrap included) """
    database = db.install()
    calls = []

    class CountingFernet(database.Fernet):
        def decrypt(self, token, *args, **kwargs):
            calls.append(len(token))
            return super().decrypt(token, *args, **kwargs)

    monkeypatch.setattr(database, "Fernet", CountingFernet)
    return calls


def _seed(db, store, count, project_id=1, generations=1, size=8):
    """ count refs with `generations` generations each; counters are reset afterwards """
    refs = []
    for index in range(count):
        ref = new_ref(stores, project_id)
        for generation in range(1, generations + 1):
            store.write(ref, stores.SecretValue({"api_key": f"key-{index}-{generation}" + "x" * size}, generation),
                        expected_version=generation - 1, ctx=mint(stores, "onboard", ref))
        refs.append(ref)
    db.sessions = db.commits = db.rollbacks = 0
    db.touched.clear()
    return refs


def _plain(value):
    return {name: secret.get_secret_value() for name, secret in value.fields.items()}


def test_read_many_of_six_refs_is_one_session_and_one_decrypt(db, store, decrypts):
    refs = _seed(db, store, 6)
    decrypts.clear()
    ctxs = [mint(stores, "release", ref) for ref in refs]
    found = store.read_many(refs, [1] * 6, ctxs)
    assert db.sessions == 1 and len(decrypts) == 1  # master key unset: the one decrypt is the blob
    assert sorted(found) == sorted((ref.ref_id, 1) for ref in refs)
    assert _plain(found[(refs[3].ref_id, 1)]) == {"api_key": "key-3-1xxxxxxxx"}
    assert found[(refs[3].ref_id, 1)].generation == 1


def test_read_many_with_a_master_key_adds_only_the_key_unwrap(db, store, decrypts, monkeypatch):
    import tools  # pylint: disable=C0415
    from cryptography.fernet import Fernet  # pylint: disable=C0415
    refs = _seed(db, store, 4)
    master = Fernet.generate_key()
    monkeypatch.setattr(tools.config, "SECRETS_MASTER_KEY", master.decode())
    db.keys["project-1"].data = Fernet(master).encrypt(db.keys["project-1"].data)
    decrypts.clear()
    store.read_many(refs, [1] * 4, [mint(stores, "release", ref) for ref in refs])
    assert db.sessions == 1 and len(decrypts) == 2  # one key unwrap + one blob, independent of the ref count


def test_single_read_is_one_session_and_one_decrypt_and_touches_the_governed_row_only(db, store, decrypts):
    (ref,) = _seed(db, store, 1)
    decrypts.clear()
    assert _plain(store.read(ref, 1, mint(stores, "probe", ref))) == {"api_key": "key-0-1xxxxxxxx"}
    assert db.sessions == 1 and len(decrypts) == 1
    assert db.touched == [("key", "project-1"), ("data", "project-1:cs")]


def test_read_many_returns_every_requested_generation_and_dedupes_pairs(db, store):
    (ref,) = _seed(db, store, 1, generations=3)
    ctx = mint(stores, "reconcile", ref)  # one context is enough when every ref is its ref_id
    found = store.read_many([ref, ref, ref], [1, 3, 1], ctx)
    assert sorted(found) == [(ref.ref_id, 1), (ref.ref_id, 3)]
    assert _plain(found[(ref.ref_id, 3)]) == {"api_key": "key-0-3xxxxxxxx"}


def test_read_many_spanning_two_projects_is_one_session_and_one_decrypt_per_project(db, store, decrypts):
    first, second = _seed(db, store, 1)[0], _seed(db, store, 1, project_id=2)[0]
    decrypts.clear()
    store.read_many([first, second], [1, 1], [mint(stores, "release", first), mint(stores, "release", second)])
    assert db.sessions == 1 and len(decrypts) == 2


def test_read_many_is_all_or_nothing_and_names_the_failing_ref(db, store):
    ok, missing = _seed(db, store, 2)
    with pytest.raises(stores.StoreError) as raised:
        store.read_many([ok, missing], [1, 2], [mint(stores, "release", ok), mint(stores, "release", missing)])
    assert raised.value.code == "NOT_FOUND" and raised.value.details == {"ref_id": str(missing.ref_id)}
    assert str(missing.ref_id) not in str(raised.value) and "key-" not in repr(raised.value.details)


def test_read_many_refused_context_does_no_io(db, store):
    first, second = _seed(db, store, 2)
    for ctxs in (mint(stores, "release", first),                                    # one ctx cannot cover two refs
                 [mint(stores, "release", first), mint(stores, "onboard", second)]):  # purpose does not fit
        with pytest.raises(stores.StoreError) as raised:
            store.read_many([first, second], [1, 1], ctxs)
        assert raised.value.code == "DENIED" and raised.value.details == {"ref_id": str(second.ref_id)}
    assert db.sessions == 0 and db.touched == []


def test_read_many_argument_validation_and_empty_call(db, store):
    (ref,) = _seed(db, store, 1)
    ctx = mint(stores, "release", ref)
    assert store.read_many([], [], []) == {} and db.sessions == 0
    for refs, generations, contexts in (([ref], [], ctx), ([ref], [1], [ctx, ctx])):
        with pytest.raises(stores.StoreError) as raised:
            store.read_many(refs, generations, contexts)
        assert raised.value.code == "INVALID_REQUEST" and raised.value.details == {}
    too_many = stores.MAX_READ_MANY + 1
    with pytest.raises(stores.StoreError) as raised:
        store.read_many([ref] * too_many, [1] * too_many, ctx)
    assert raised.value.code == "INVALID_REQUEST" and raised.value.details == {"max": stores.MAX_READ_MANY}
    assert len(store.read_many([ref] * stores.MAX_READ_MANY, [1] * stores.MAX_READ_MANY, ctx)) == 1  # limit is allowed
    for bad in (True, 1.0, None, "1", 0, -1):
        with pytest.raises(stores.StoreError) as raised:
            store.read_many([ref], [bad], ctx)
        assert raised.value.code == "INVALID_REQUEST"
    with pytest.raises(stores.StoreError) as raised:
        store.read_many(["not-a-ref"], [1], ctx)
    assert raised.value.code == "INVALID_REQUEST"
    assert db.sessions == 1  # only the limit-sized call above reached the database


@pytest.mark.parametrize("purpose", sorted(stores.PURPOSES))
def test_read_many_purpose_matrix_is_the_read_matrix(db, store, purpose):
    (ref,) = _seed(db, store, 1)
    ctx = mint(stores, purpose, ref)
    if purpose in stores.OPERATION_PURPOSES["read"]:
        assert store.read_many([ref], [1], ctx)
    else:
        with pytest.raises(stores.StoreError) as raised:
            store.read_many([ref], [1], ctx)
        assert raised.value.code == "DENIED"


def test_legacy_secrets_never_decrypt_or_touch_governed_material(db, store, decrypts):
    # S10 regression: ten rotations of a large bundle must not change what a legacy unsecret decrypts
    legacy_blob = db.raw(1)
    engine = _engine(db)
    engine.get_secrets()
    baseline = list(decrypts)
    (ref,) = _seed(db, store, 1, generations=10, size=4096)
    assert db.raw(1) == legacy_blob
    decrypts.clear()
    db.touched.clear()
    fresh = _engine(db)  # no cache: a real decrypt of the legacy blob, as VaultClient.unsecret does per dispatch
    assert fresh.get_secrets() == {"keep": "kept"} and fresh.get_hidden_secrets() == {"h": "hidden"}
    assert decrypts == baseline * 2 and decrypts[0] == len(legacy_blob)  # same ciphertext as before any governed write
    assert ("data", "project-1:cs") not in db.touched
    assert "x" * 100 not in json.dumps(db.decrypted(1))


def test_governed_operations_never_touch_the_legacy_row_once_migrated(db, store):
    (ref,) = _seed(db, store, 1, generations=2)
    for call in (
            lambda: store.read(ref, 2, mint(stores, "probe", ref)),
            lambda: store.read_many([ref], [1], mint(stores, "release", ref)),
            lambda: store.metadata(ref, mint(stores, "probe", ref)),
            lambda: store.write(ref, stores.SecretValue({"a": "b"}, 3), expected_version=2,
                                ctx=mint(stores, "onboard", ref)),
            lambda: store.prune(ref, 1, mint(stores, "reconcile", ref)),
            lambda: store.delete_all(ref, mint(stores, "retire", ref)),
    ):
        db.touched.clear()
        call()
        assert ("data", "project-1") not in db.touched


def test_first_read_migrates_an_unmigrated_project_once(db, store, decrypts):
    # documented one-time write on a read path (S10 activation without waiting for a mutation)
    ref = new_ref(stores, 1)
    db.seed_legacy_governed(1, {f"{ref.ref_id.hex}:1": {"api_key": "old-fixture"}})
    db.commits = 0
    assert _plain(store.read(ref, 1, mint(stores, "probe", ref))) == {"api_key": "old-fixture"}
    assert db.commits == 1 and db.decrypted(1) == {"secrets": {"keep": "kept"}, "hidden_secrets": {"h": "hidden"}}
    assert db.decrypted(1, governed=True) == {f"{ref.ref_id.hex}:1": {"api_key": "old-fixture"}}
    db.touched.clear()
    db.sessions = db.data_statements = 0
    assert store.metadata(ref, mint(stores, "probe", ref)).versions == frozenset({1})
    assert db.commits == 1 and db.sessions == 1 and ("data", "project-1") not in db.touched  # steady state


def test_metadata_also_migrates_and_a_project_without_governed_material_gets_an_empty_row(db, store):
    ref = new_ref(stores, 1)
    assert store.metadata(ref, mint(stores, "probe", ref)).current_version == 0
    assert db.decrypted(1, governed=True) == {}
    assert db.decrypted(1) == {"secrets": {"keep": "kept"}, "hidden_secrets": {"h": "hidden"}}


@pytest.mark.parametrize("call", ["read", "read_many", "metadata"])
def test_a_governed_read_is_one_data_statement(db, store, call):
    # one SELECT over both candidate rows = one snapshot: a read cannot straddle a migration
    (ref,) = _seed(db, store, 1)
    db.data_statements = 0
    ctx = mint(stores, "probe", ref)
    {"read": lambda: store.read(ref, 1, ctx), "read_many": lambda: store.read_many([ref], [1], ctx),
     "metadata": lambda: store.metadata(ref, ctx)}[call]()
    assert db.data_statements == 1


def test_a_read_of_an_unmigrated_project_sees_either_the_old_or_the_new_state_never_neither(db, store):
    # the single statement returns the new row if it exists, else the legacy one: both carry the material
    ref = new_ref(stores, 1)
    db.seed_legacy_governed(1, {f"{ref.ref_id.hex}:1": {"api_key": "old-fixture"}})
    engine = _engine(db)
    assert engine._read_governed() == {f"{ref.ref_id.hex}:1": {"api_key": "old-fixture"}}  # pylint: disable=W0212
    assert engine._read_governed() == {f"{ref.ref_id.hex}:1": {"api_key": "old-fixture"}}  # pylint: disable=W0212


def test_first_write_migrates_the_legacy_section_in_one_commit(db, store):
    ref = new_ref(stores, 1)
    db.seed_legacy_governed(1, {f"{ref.ref_id.hex}:1": {"api_key": "old-fixture"}})
    db.commits = 0
    store.write(ref, stores.SecretValue({"api_key": "new-fixture"}, 2), expected_version=1,
                ctx=mint(stores, "onboard", ref))
    assert db.commits == 1
    assert db.decrypted(1, governed=True) == {
        f"{ref.ref_id.hex}:1": {"api_key": "old-fixture"}, f"{ref.ref_id.hex}:2": {"api_key": "new-fixture"}}
    assert db.decrypted(1) == {"secrets": {"keep": "kept"}, "hidden_secrets": {"h": "hidden"}}  # section gone
    db.touched.clear()
    assert _plain(store.read(ref, 1, mint(stores, "probe", ref))) == {"api_key": "old-fixture"}
    assert ("data", "project-1") not in db.touched


def test_prune_migrates_and_a_failed_check_rolls_the_migration_back(db, store):
    ref = new_ref(stores, 1)
    db.seed_legacy_governed(1, {f"{ref.ref_id.hex}:{n}": {"v": str(n)} for n in (1, 2, 3)})
    legacy_blob = db.raw(1)
    with pytest.raises(stores.StoreError):  # stale CAS: nothing moves
        store.write(ref, stores.SecretValue({"v": "x"}, 1), expected_version=0, ctx=mint(stores, "onboard", ref))
    assert db.raw(1) == legacy_blob and "project-1:cs" not in db.rows
    meta = store.prune(ref, 2, mint(stores, "reconcile", ref))
    assert meta.versions == frozenset({2, 3}) and meta.current_version == 3
    assert "credential_store" not in db.decrypted(1) and sorted(db.decrypted(1, governed=True)) == sorted(
        f"{ref.ref_id.hex}:{n}" for n in (2, 3))


def test_prune_keeps_exactly_the_newest_n_generations_of_that_reference_only(db, store):
    ref, other = _seed(db, store, 2, generations=5)
    meta = store.prune(ref, 2, mint(stores, "reconcile", ref))
    assert meta.versions == frozenset({4, 5}) and meta.current_version == 5
    assert store.metadata(ref, mint(stores, "probe", ref)).versions == frozenset({4, 5})
    assert store.metadata(other, mint(stores, "probe", other)).versions == frozenset({1, 2, 3, 4, 5})
    for gone in (1, 2, 3):
        with pytest.raises(stores.StoreError) as raised:
            store.read(ref, gone, mint(stores, "probe", ref))
        assert raised.value.code == "NOT_FOUND"
    assert _plain(store.read(ref, 5, mint(stores, "probe", ref))) == {"api_key": "key-0-5xxxxxxxx"}
    # the next write continues from the real newest generation
    assert store.write(ref, stores.SecretValue({"a": "b"}, 6), expected_version=5,
                       ctx=mint(stores, "onboard", ref)).current_version == 6


def test_prune_is_a_no_op_without_a_write_when_nothing_is_older(db, store):
    (ref,) = _seed(db, store, 1, generations=2)
    before = db.raw(1, governed=True)
    assert store.prune(ref, 2, mint(stores, "reconcile", ref)).versions == frozenset({1, 2})
    assert store.prune(ref, 9, mint(stores, "retire", ref)).versions == frozenset({1, 2})
    assert db.commits == 0 and db.raw(1, governed=True) == before


@pytest.mark.parametrize("keep", [0, -1, True, 1.5, "1", None])
def test_prune_rejects_a_bad_keep_count_before_any_io(db, store, keep):
    (ref,) = _seed(db, store, 1)
    with pytest.raises(ValueError):
        store.prune(ref, keep, mint(stores, "reconcile", ref))
    assert db.sessions == 0


@pytest.mark.parametrize("purpose", sorted(stores.PURPOSES))
def test_prune_purpose_matrix(db, store, purpose):
    (ref,) = _seed(db, store, 1)
    ctx = mint(stores, purpose, ref)
    if purpose in ("retire", "reconcile"):
        store.prune(ref, 1, ctx)
    else:
        with pytest.raises(stores.StoreError) as raised:
            store.prune(ref, 1, ctx)
        assert raised.value.code == "DENIED"
        assert db.sessions == 0


def test_delete_all_of_nothing_writes_nothing(db, store):
    ref = new_ref(stores, 1)
    db.seed_legacy_governed(1, {})  # an unmigrated project with no references: the first delete_all migrates it
    store.delete_all(ref, mint(stores, "retire", ref))
    first = db.commits
    store.delete_all(ref, mint(stores, "retire", ref))
    assert db.commits == first


def test_removing_the_project_space_removes_the_governed_row(db, store):
    ref = new_ref(stores, 1)
    store.write(ref, stores.SecretValue({"a": "b"}, 1), expected_version=0, ctx=mint(stores, "onboard", ref))
    assert "project-1:cs" in db.rows
    _engine(db).remove_project_space()
    assert "project-1" not in db.rows and "project-1:cs" not in db.rows and "project-1" not in db.keys


# -- review fixes: typed argument errors, legacy writer guard, concurrency, failure injection ------------------


def test_duplicate_pairs_keep_the_first_context_and_must_name_the_same_project(db, store):
    first = new_ref(stores, 1)
    store.write(first, stores.SecretValue({"a": "b"}, 1), expected_version=0, ctx=mint(stores, "onboard", first))
    db.sessions = 0
    twin = stores.StoreRef(first.ref_id, 2, "database", {})  # same ref_id and generation, another project
    with pytest.raises(stores.StoreError) as raised:
        store.read_many([first, twin], [1, 1], [mint(stores, "release", first), mint(stores, "release", twin)])
    assert raised.value.code == "DENIED" and raised.value.details == {"ref_id": str(first.ref_id)}
    assert db.sessions == 0
    ctx_a, ctx_b = mint(stores, "release", first, decision_id="first"), mint(stores, "probe", first, decision_id="second")
    assert len(store.read_many([first, first], [1, 1], [ctx_a, ctx_b])) == 1


def test_legacy_section_writers_refuse_credential_store_once_its_row_exists(db, store):
    ref = new_ref(stores, 1)
    engine = _engine(db)
    engine._update_section("credential_store", add={"legacy": {"v": "1"}})  # pylint: disable=W0212  # before the split: fine
    store.write(ref, stores.SecretValue({"a": "b"}, 1), expected_version=0, ctx=mint(stores, "onboard", ref))
    database = db.install()
    before = db.raw(1)
    with pytest.raises(database.GovernedSectionMoved):
        engine._update_section("credential_store", add={"legacy": {"v": "2"}})  # pylint: disable=W0212
    with pytest.raises(database.GovernedSectionMoved):
        engine._write_section("credential_store", {"legacy": {"v": "3"}})  # pylint: disable=W0212
    assert db.raw(1) == before and "credential_store" not in db.decrypted(1)
    engine.update_secrets(add={"other": "fine"})  # every other section is untouched by the guard
    assert db.decrypted(1)["secrets"] == {"keep": "kept", "other": "fine"}


def test_a_legacy_secret_edit_racing_the_migration_loses_nothing(db, store):
    import threading  # pylint: disable=C0415
    ref = new_ref(stores, 1)
    db.seed_legacy_governed(1, {f"{ref.ref_id.hex}:1": {"api_key": "old-fixture"}})
    entered, release, errors = threading.Event(), threading.Event(), []

    def migrate():
        try:
            _engine(db)._update_governed(lambda section: (entered.set(), release.wait(5)))  # pylint: disable=W0212
        except Exception as exc:  # pylint: disable=W0703
            errors.append(exc)

    def edit():
        try:
            _engine(db).set_secrets({"edited": "value"})
        except Exception as exc:  # pylint: disable=W0703
            errors.append(exc)

    migrator = threading.Thread(target=migrate)
    migrator.start()
    assert entered.wait(5)                      # the migration holds the legacy row lock, mid-transaction
    editor = threading.Thread(target=edit)
    editor.start()
    editor.join(0.3)
    assert editor.is_alive()                    # the legacy edit is blocked behind the lock
    release.set()
    migrator.join(5)
    editor.join(5)
    assert not errors and not migrator.is_alive() and not editor.is_alive()
    assert db.decrypted(1) == {"secrets": {"edited": "value"}, "hidden_secrets": {"h": "hidden"}}
    assert db.decrypted(1, governed=True) == {f"{ref.ref_id.hex}:1": {"api_key": "old-fixture"}}


def test_a_failed_commit_during_migration_leaves_legacy_and_governed_state_consistent(db, store):
    ref = new_ref(stores, 1)
    db.seed_legacy_governed(1, {f"{ref.ref_id.hex}:1": {"api_key": "old-fixture"}})
    legacy_blob = db.raw(1)
    db.fail_commit = True
    with pytest.raises(stores.StoreError) as raised:
        store.write(ref, stores.SecretValue({"api_key": "new"}, 2), expected_version=1, ctx=mint(stores, "onboard", ref))
    assert raised.value.code == "UNAVAILABLE" and "injected" not in str(raised.value)
    with pytest.raises(stores.StoreError):
        store.read(ref, 1, mint(stores, "probe", ref))  # the read-side migration fails the same way
    assert db.raw(1) == legacy_blob and "project-1:cs" not in db.rows        # nothing half-moved
    db.fail_commit = False
    assert _plain(store.read(ref, 1, mint(stores, "probe", ref))) == {"api_key": "old-fixture"}  # and it still works
    assert "credential_store" not in db.decrypted(1)


def test_a_failed_commit_after_migration_leaves_the_governed_row_unchanged(db, store):
    (ref,) = _seed(db, store, 1)
    before = db.raw(1, governed=True)
    db.fail_commit = True
    with pytest.raises(stores.StoreError):
        store.write(ref, stores.SecretValue({"a": "b"}, 2), expected_version=1, ctx=mint(stores, "onboard", ref))
    assert db.raw(1, governed=True) == before


def test_write_and_metadata_are_one_session_each(db, store):
    ref = new_ref(stores, 1)
    store.metadata(ref, mint(stores, "probe", ref))  # migrates the (empty) project once
    db.sessions = 0
    store.write(ref, stores.SecretValue({"a": "b"}, 1), expected_version=0, ctx=mint(stores, "onboard", ref))
    assert db.sessions == 1
    db.sessions = 0
    store.metadata(ref, mint(stores, "probe", ref))
    assert db.sessions == 1
    store.prune(ref, 1, mint(stores, "reconcile", ref))
    assert db.sessions == 2


def test_removing_a_project_locks_the_legacy_row_before_the_governed_row(db, store):
    ref = new_ref(stores, 1)
    store.write(ref, stores.SecretValue({"a": "b"}, 1), expected_version=0, ctx=mint(stores, "onboard", ref))
    db.touched.clear()
    _engine(db).remove_project_space()
    data_order = [row_id for table, row_id in db.touched if table == "data"]
    assert data_order == ["project-1", "project-1:cs"]
