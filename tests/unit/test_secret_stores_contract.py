"""One contract suite, run against both adapters (database over a Fernet-backed fake, corporate over a fake KV v2)."""
import pytest

from fixtures.secret_stores_loader import (
    FakeSecretsDb, FakeVault, install_fake_vault, load_secret_stores, mint, new_ref, vault_config,
)

stores = load_secret_stores()


@pytest.fixture(name="env", params=["database", "corporate_vault"])
def _env(request, monkeypatch, tmp_path):
    """ (store, kind, project_id, extras) for each adapter """
    import tools  # pylint: disable=C0415
    if request.param == "database":
        fake = FakeSecretsDb()
        fake.install()
        monkeypatch.setattr(tools.config, "SECRETS_MASTER_KEY", None)
        from importlib import import_module  # pylint: disable=C0415
        module = import_module(f"{stores.__name__}.database")
        return module.DatabaseSecretStore(), "database", 1, fake
    pytest.importorskip("hvac")
    from importlib import import_module  # pylint: disable=C0415
    module = import_module(f"{stores.__name__}.corporate_vault")
    vault = FakeVault()
    install_fake_vault(monkeypatch, vault)
    return module.CorporateVaultSecretStore(vault_config(tmp_path)), "corporate_vault", 1, vault


def _value(generation=1, **fields):
    return stores.SecretValue(fields or {"api_key": "key-fixture", "user": "user-fixture"}, generation)


def _plain(value):
    return {name: secret.get_secret_value() for name, secret in value.fields.items()}


def test_write_read_metadata_delete_roundtrip(env):
    store, kind, project_id, _ = env
    ref = new_ref(stores, project_id, kind)
    written = store.write(ref, _value(), expected_version=0, ctx=mint(stores, "onboard", ref))
    assert written.current_version == 1
    got = store.read(ref, 1, mint(stores, "probe", ref))
    assert got.generation == 1 and _plain(got) == {"api_key": "key-fixture", "user": "user-fixture"}
    meta = store.metadata(ref, mint(stores, "probe", ref))
    assert meta.current_version == 1 and meta.versions == frozenset({1})
    store.delete_all(ref, mint(stores, "retire", ref))
    with pytest.raises(stores.StoreError) as raised:
        store.read(ref, 1, mint(stores, "probe", ref))
    assert raised.value.code == "NOT_FOUND"
    assert store.metadata(ref, mint(stores, "probe", ref)).current_version == 0


def test_generation_equals_version_and_history_is_kept(env):
    store, kind, project_id, _ = env
    ref = new_ref(stores, project_id, kind)
    for expected in range(0, 3):
        meta = store.write(ref, _value(expected + 1, n=str(expected + 1)), expected_version=expected,
                           ctx=mint(stores, "onboard", ref))
        assert meta.current_version == expected + 1
    probe = mint(stores, "probe", ref)
    assert [_plain(store.read(ref, g, probe)) for g in (1, 2, 3)] == [{"n": "1"}, {"n": "2"}, {"n": "3"}]
    assert store.metadata(ref, probe).versions == frozenset({1, 2, 3})
    assert store.metadata(ref, probe).current_version == 3


def test_cas_conflict_on_stale_and_future_expected_version(env):
    store, kind, project_id, _ = env
    ref = new_ref(stores, project_id, kind)
    onboard = mint(stores, "onboard", ref)
    store.write(ref, _value(1), expected_version=0, ctx=onboard)
    for stale in (0, 2, 5):
        with pytest.raises(stores.StoreError) as raised:
            store.write(ref, _value(stale + 1, x="y"), expected_version=stale, ctx=onboard)
        assert raised.value.code == "VERSION_CONFLICT"
    meta = store.metadata(ref, mint(stores, "probe", ref))
    assert meta.current_version == 1 and meta.versions == frozenset({1})
    assert _plain(store.read(ref, 1, mint(stores, "probe", ref)))["api_key"] == "key-fixture"


def test_not_found(env):
    store, kind, project_id, _ = env
    ref = new_ref(stores, project_id, kind)
    probe = mint(stores, "probe", ref)
    with pytest.raises(stores.StoreError) as raised:
        store.read(ref, 1, probe)
    assert raised.value.code == "NOT_FOUND"
    store.write(ref, _value(1), expected_version=0, ctx=mint(stores, "onboard", ref))
    with pytest.raises(stores.StoreError) as raised:
        store.read(ref, 2, probe)
    assert raised.value.code == "NOT_FOUND"


def test_delete_all_is_idempotent_and_scoped_to_one_reference(env):
    store, kind, project_id, _ = env
    first, second = new_ref(stores, project_id, kind), new_ref(stores, project_id, kind)
    for ref in (first, second):
        store.write(ref, _value(1), expected_version=0, ctx=mint(stores, "onboard", ref))
    store.delete_all(first, mint(stores, "retire", first))
    store.delete_all(first, mint(stores, "reconcile", first))  # already gone
    assert store.metadata(second, mint(stores, "probe", second)).current_version == 1
    assert _plain(store.read(second, 1, mint(stores, "probe", second)))["user"] == "user-fixture"


def test_references_do_not_share_generations(env):
    store, kind, project_id, _ = env
    first, second = new_ref(stores, project_id, kind), new_ref(stores, project_id, kind)
    store.write(first, _value(1, a="1"), expected_version=0, ctx=mint(stores, "onboard", first))
    # the second reference starts at 0 independently of the first
    store.write(second, _value(1, b="2"), expected_version=0, ctx=mint(stores, "onboard", second))
    with pytest.raises(stores.StoreError) as raised:
        store.read(second, 2, mint(stores, "probe", second))
    assert raised.value.code == "NOT_FOUND"


# -- context matrix ----------------------------------------------------------------------------

OPERATIONS = {
    "read": lambda store, ref, ctx: store.read(ref, 1, ctx),
    "write": lambda store, ref, ctx: store.write(ref, _value(1), expected_version=0, ctx=ctx),
    "metadata": lambda store, ref, ctx: store.metadata(ref, ctx),
    "prune": lambda store, ref, ctx: store.prune(ref, 1, ctx),
    "delete_all": lambda store, ref, ctx: store.delete_all(ref, ctx),
}


@pytest.mark.parametrize("operation", sorted(OPERATIONS))
@pytest.mark.parametrize("purpose", sorted(stores.PURPOSES))
def test_purpose_must_fit_the_operation(env, operation, purpose):
    store, kind, project_id, _ = env
    ref = new_ref(stores, project_id, kind)
    ctx = mint(stores, purpose, ref)
    if purpose in stores.OPERATION_PURPOSES[operation]:
        try:
            OPERATIONS[operation](store, ref, ctx)
        except stores.StoreError as exc:
            assert exc.code != "DENIED"  # NOT_FOUND etc. are fine: the context was accepted
    else:
        with pytest.raises(stores.StoreError) as raised:
            OPERATIONS[operation](store, ref, ctx)
        assert raised.value.code == "DENIED"


@pytest.mark.parametrize("operation", sorted(OPERATIONS))
def test_context_for_another_ref_or_project_is_refused(env, operation):
    store, kind, project_id, _ = env
    ref, other = new_ref(stores, project_id, kind), new_ref(stores, project_id, kind)
    purpose = sorted(stores.OPERATION_PURPOSES[operation])[0]
    wrong_project = stores.CredentialStoreProvider.mint(
        purpose, decision_id="d1", actor_ref="user:1", project_id=project_id + 1, ref_id=ref.ref_id)
    for ctx in (mint(stores, purpose, other), wrong_project):
        with pytest.raises(stores.StoreError) as raised:
            OPERATIONS[operation](store, ref, ctx)
        assert raised.value.code == "DENIED"


@pytest.mark.parametrize("operation", sorted(OPERATIONS))
@pytest.mark.parametrize("fake_ctx", [None, object(), "ctx", {"purpose": "onboard"}])
def test_non_context_objects_are_refused(env, operation, fake_ctx):
    store, kind, project_id, _ = env
    ref = new_ref(stores, project_id, kind)
    with pytest.raises(stores.StoreError) as raised:
        OPERATIONS[operation](store, ref, fake_ctx)
    assert raised.value.code == "DENIED"


def test_refused_context_causes_no_store_effect(env):
    store, kind, project_id, backend = env
    ref = new_ref(stores, project_id, kind)
    with pytest.raises(stores.StoreError):
        store.write(ref, _value(1), expected_version=0, ctx=mint(stores, "probe", ref))
    assert store.metadata(ref, mint(stores, "probe", ref)).current_version == 0
    if kind == "corporate_vault":
        assert backend.requests_to("/data/") == [] or all(r.method != "POST" for r in backend.requests_to("/data/"))


# -- read_many / prune (perf PR 1) --------------------------------------------------------------


def _stored(store, kind, project_id, count, generations=1):
    refs = []
    for index in range(count):
        ref = new_ref(stores, project_id, kind)
        for generation in range(1, generations + 1):
            store.write(ref, _value(generation, n=f"{index}.{generation}"), expected_version=generation - 1,
                        ctx=mint(stores, "onboard", ref))
        refs.append(ref)
    return refs


def test_read_many_returns_what_read_returns_for_every_pair(env):
    store, kind, project_id, _ = env
    first, second = _stored(store, kind, project_id, 2, generations=2)
    refs, generations = [first, second, first], [1, 2, 2]
    found = store.read_many(refs, generations, [mint(stores, "release", ref) for ref in refs])
    assert sorted(found) == sorted({(first.ref_id, 1), (second.ref_id, 2), (first.ref_id, 2)})
    for (ref_id, generation), value in found.items():
        ref = first if ref_id == first.ref_id else second
        assert value.generation == generation
        assert _plain(value) == _plain(store.read(ref, generation, mint(stores, "probe", ref)))
    assert _plain(found[(second.ref_id, 2)]) == {"n": "1.2"}


def test_read_many_is_all_or_nothing_and_names_the_failing_ref(env):
    store, kind, project_id, _ = env
    ok, missing = _stored(store, kind, project_id, 2)
    with pytest.raises(stores.StoreError) as raised:
        store.read_many([ok, missing], [1, 7], [mint(stores, "release", ok), mint(stores, "release", missing)])
    assert raised.value.code == "NOT_FOUND" and raised.value.details == {"ref_id": str(missing.ref_id)}
    assert "fixture" not in repr(raised.value.details) and str(missing.ref_id) not in str(raised.value)


def test_read_many_of_nothing_is_empty(env):
    store, _kind, _project_id, _ = env
    assert store.read_many([], [], []) == {}


@pytest.mark.parametrize("purpose", sorted(stores.PURPOSES))
def test_read_many_purposes_are_the_read_purposes(env, purpose):
    store, kind, project_id, _ = env
    (ref,) = _stored(store, kind, project_id, 1)
    ctx = mint(stores, purpose, ref)
    if purpose in stores.OPERATION_PURPOSES["read"]:
        assert store.read_many([ref], [1], ctx)[(ref.ref_id, 1)].generation == 1
    else:
        with pytest.raises(stores.StoreError) as raised:
            store.read_many([ref], [1], ctx)
        assert raised.value.code == "DENIED" and raised.value.details == {"ref_id": str(ref.ref_id)}


def test_read_many_refused_context_causes_no_read(env):
    store, kind, project_id, backend = env
    first, second = _stored(store, kind, project_id, 2)
    if kind == "corporate_vault":
        before = len(backend.seen)
    with pytest.raises(stores.StoreError) as raised:
        store.read_many([first, second], [1, 1], mint(stores, "release", first))  # one ctx, two refs
    assert raised.value.code == "DENIED"
    if kind == "corporate_vault":
        assert len(backend.seen) == before


def test_prune_keeps_the_newest_n_generations_of_one_reference(env):
    store, kind, project_id, _ = env
    ref, other = _stored(store, kind, project_id, 2, generations=4)
    meta = store.prune(ref, 2, mint(stores, "reconcile", ref))
    assert meta.versions == frozenset({3, 4}) and meta.current_version == 4
    assert store.metadata(ref, mint(stores, "probe", ref)).versions == frozenset({3, 4})
    assert store.metadata(other, mint(stores, "probe", other)).versions == frozenset({1, 2, 3, 4})
    with pytest.raises(stores.StoreError) as raised:
        store.read(ref, 2, mint(stores, "probe", ref))
    assert raised.value.code == "NOT_FOUND"
    assert _plain(store.read(ref, 4, mint(stores, "probe", ref))) == {"n": "0.4"}
    assert store.prune(ref, 2, mint(stores, "retire", ref)).versions == frozenset({3, 4})  # idempotent


def test_prune_of_an_unknown_reference_is_empty_not_an_error(env):
    store, kind, project_id, _ = env
    ref = new_ref(stores, project_id, kind)
    meta = store.prune(ref, 1, mint(stores, "reconcile", ref))
    assert meta.current_version == 0 and meta.versions == frozenset()


@pytest.mark.parametrize("keep", [0, -1, True, 2.0, "2", None])
def test_prune_rejects_a_bad_keep_count(env, keep):
    store, kind, project_id, _ = env
    (ref,) = _stored(store, kind, project_id, 1, generations=2)
    with pytest.raises(ValueError):
        store.prune(ref, keep, mint(stores, "reconcile", ref))
    assert store.metadata(ref, mint(stores, "probe", ref)).versions == frozenset({1, 2})
