"""Corporate Vault adapter: configuration rules, transport, login, error map, smoke, static lint (C-1009 #6757)."""
import ast
import json
import pickle
import traceback
from importlib import import_module
from pathlib import Path

import pytest

hvac = pytest.importorskip("hvac")
import requests  # noqa: E402  pylint: disable=C0413

from fixtures.secret_stores_loader import (  # noqa: E402  pylint: disable=C0413
    FakeVault, install_fake_vault, load_secret_stores, mint, new_ref, response, vault_config,
)

stores = load_secret_stores()
corporate = import_module(f"{stores.__name__}.corporate_vault")
SECRET_TEXT = "secret-text-fixture"


@pytest.fixture(name="vault")
def _vault(monkeypatch):
    vault = FakeVault()
    vault.sessions = install_fake_vault(monkeypatch, vault)
    return vault


@pytest.fixture(name="make")
def _make(tmp_path):
    return lambda **overrides: corporate.CorporateVaultSecretStore(vault_config(tmp_path, **overrides))


@pytest.fixture(name="store")
def _store(vault, make):
    _ = vault
    return make()


def _value(**fields):
    return stores.SecretValue(fields or {"api_key": SECRET_TEXT}, 1)


def _write(store, ref, expected=0):
    return store.write(ref, _value(), expected_version=expected, ctx=mint(stores, "onboard", ref))


# -- configuration rules -----------------------------------------------------------------------


@pytest.mark.parametrize("addr,insecure", [
    ("https://vault.example.test", None),
    ("https://vault.example.test:8200", False),
    ("http://vault.localhost:8200", True),
    ("http://a.b.localhost", True),
    ("http://localhost:8200", True),
    ("http://127.0.0.1:8200", True),
])
def test_accepted_addresses(make, addr, insecure):
    make(ADDR=addr, INSECURE_DEV_HTTP=insecure)


@pytest.mark.parametrize("addr,insecure", [
    ("http://vault.example.test", True),       # http only for local hosts
    ("http://vault.localhost:8200", None),     # and only with the explicit dev flag
    ("http://vault.localhost:8200", False),
    ("http://notlocalhost", True),             # suffix match must be on a label boundary
    ("http://localhost.evil.test", True),
    ("http://127.0.0.2", True),
    ("ftp://vault.example.test", True),
])
def test_insecure_addresses_are_refused_as_tls_invalid(make, addr, insecure):
    with pytest.raises(stores.StoreError) as raised:
        make(ADDR=addr, INSECURE_DEV_HTTP=insecure)
    assert raised.value.code == "TLS_INVALID"


@pytest.mark.parametrize("overrides", [
    dict(ADDR=None), dict(ADDR=""), dict(ADDR="https://user:pw-fixture@vault.example.test"), dict(ADDR="https://"),
    dict(TENANT_SEGMENT=None), dict(TENANT_SEGMENT="Bad_Tenant"), dict(TENANT_SEGMENT="a/b"),
    dict(TENANT_SEGMENT="-x"), dict(TENANT_SEGMENT="x" * 64), dict(MOUNT="kv/../sys"), dict(MOUNT="KV"),
    dict(AUTH_MOUNT="a b"), dict(ROLE="r/../x"), dict(AUTH_METHOD=None), dict(AUTH_METHOD="token"),
    dict(AUTH_METHOD="approle"), dict(NAMESPACE="a\r\nb"), dict(JWT_PATH="/nonexistent/jwt-fixture"),
    dict(TIMEOUT_S=0), dict(TIMEOUT_S=61), dict(TIMEOUT_S="abc"),
])
def test_invalid_configuration_is_refused_without_naming_values(make, overrides):
    with pytest.raises(stores.StoreError) as raised:
        make(**overrides)
    assert raised.value.code in ("UNAVAILABLE", "TLS_INVALID")
    assert "pw-fixture" not in "".join(traceback.format_exception(raised.value))


def test_defaults_apply_when_optional_keys_are_unset(vault, tmp_path):
    cfg = vault_config(tmp_path)
    for key in ("MOUNT", "AUTH_MOUNT", "ROLE", "TIMEOUT_S"):
        assert getattr(cfg, f"CORPORATE_VAULT_{key}", None) is None
    ref = new_ref(stores)
    _write(corporate.CorporateVaultSecretStore(cfg), ref)
    assert any(f"/v1/kv-elitea/data/t/local/cred/{ref.ref_id}" in item.url for item in vault.seen)
    assert vault.seen[-1].kwargs["timeout"] == 5


def test_paths_come_from_the_reference_id_only(vault, store):
    ref = new_ref(stores)
    ref = stores.StoreRef(ref.ref_id, ref.project_id, "corporate_vault", {"tenant": "../other", "mount": "sys"})
    _write(store, ref)
    urls = [item.url for item in vault.seen if "/data/" in item.url]
    assert urls == [f"https://vault.example.test/v1/kv-elitea/data/t/local/cred/{ref.ref_id}"]


# -- transport ---------------------------------------------------------------------------------


def test_correlation_id_on_every_request_and_no_env_proxies(vault, store, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("https_proxy", "http://proxy.invalid:3128")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/nonexistent/ca-fixture")
    ref = new_ref(stores)
    ctx = mint(stores, "onboard", ref, decision_id="decision-fixture-1")
    store.write(ref, _value(), expected_version=0, ctx=ctx)
    assert len(vault.seen) == 2  # login + write
    for item in vault.seen:
        assert item.headers["X-Correlation-Id"] == "decision-fixture-1"
        assert item.headers["X-Vault-Request"] == "true"
        assert not item.kwargs["proxies"]  # trust_env False: proxy variables are ignored
        assert item.kwargs["verify"] is True and item.kwargs["timeout"] == 5


def test_session_hardening_one_session_per_call(vault, store):
    ref = new_ref(stores)
    _write(store, ref)  # login and write share the call's session
    assert len(vault.sessions) == 1
    store.metadata(ref, mint(stores, "probe", ref))
    store.metadata(ref, mint(stores, "probe", ref))
    assert len(vault.sessions) == 3
    for session in vault.sessions:
        assert session.trust_env is False and session.max_redirects == 0 and session.verify is True
        assert not session.proxies


def test_ca_bundle_is_used_for_verification(vault, make):
    ref = new_ref(stores)
    _write(make(CA_BUNDLE="/etc/ca-fixture.pem"), ref)
    assert {item.kwargs["verify"] for item in vault.seen} == {"/etc/ca-fixture.pem"}


def test_namespace_header(vault, make):
    _write(make(NAMESPACE="team/a"), new_ref(stores))
    assert {item.headers.get("X-Vault-Namespace") for item in vault.seen} == {"team/a"}


def test_namespace_header_absent_by_default(vault, store):
    _write(store, new_ref(stores))
    assert all("X-Vault-Namespace" not in item.headers for item in vault.seen)


def test_redirects_are_refused_and_not_followed(vault, store):
    ref = new_ref(stores)
    _write(store, ref)
    vault.fail_next(307, headers={"Location": "https://evil.example.test/v1/steal"})
    seen_before = len(vault.seen)
    with pytest.raises(stores.StoreError) as raised:
        store.read(ref, 1, mint(stores, "probe", ref))
    assert raised.value.code == "UNAVAILABLE"
    assert len(vault.seen) == seen_before + 1
    assert not [item for item in vault.seen if "evil.example.test" in item.url]


def test_redirect_on_delete_is_not_success(vault, store):
    ref = new_ref(stores)
    _write(store, ref)
    vault.fail_next(307, headers={"Location": "https://evil.example.test/x"})
    with pytest.raises(stores.StoreError) as raised:
        store.delete_all(ref, mint(stores, "retire", ref))
    assert raised.value.code == "UNAVAILABLE"
    assert vault.kv  # nothing was deleted


def test_write_sends_cas_and_returns_request_id(vault, store):
    ref = new_ref(stores)
    meta = _write(store, ref)
    post = [item for item in vault.seen if item.method == "POST" and "/data/" in item.url][0]
    assert post.body["options"] == {"cas": 0} and post.body["data"] == {"api_key": SECRET_TEXT}
    assert meta.request_id == "req-write"
    assert store.metadata(ref, mint(stores, "probe", ref)).request_id == "req-meta"


def test_write_whose_returned_version_is_unexpected_is_a_conflict(vault, store):
    ref = new_ref(stores)
    _write(store, ref)
    vault.faults.append(lambda request: response(200, {"request_id": "r", "data": {"version": 9}}, request.url))
    with pytest.raises(stores.StoreError) as raised:
        store.write(ref, _value(), expected_version=1, ctx=mint(stores, "onboard", ref))
    assert raised.value.code == "VERSION_CONFLICT"


# -- login -------------------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["jwt", "kubernetes"])
def test_login_methods_send_role_and_jwt_and_token_is_reused(vault, make, method):
    store = make(AUTH_METHOD=method)
    ref = new_ref(stores)
    _write(store, ref)
    store.metadata(ref, mint(stores, "probe", ref))
    store.read(ref, 1, mint(stores, "probe", ref))
    assert vault.logins == 1
    login = vault.requests_to("/login")[0]
    assert login.body == {"role": "elitea-main", "jwt": "jwt-fixture-not-a-credential"}
    assert "X-Vault-Token" not in login.headers
    assert {item.headers["X-Vault-Token"] for item in vault.seen if "/login" not in item.url} == {"token-fixture-1"}


def test_relogin_when_token_is_near_expiry(vault, make):
    vault.lease = 30  # below the 60 s margin: never considered fresh
    store = make()
    ref = new_ref(stores)
    _write(store, ref)
    store.metadata(ref, mint(stores, "probe", ref))
    assert vault.logins == 2


def test_relogin_once_on_403_with_a_cached_token(vault, store):
    ref = new_ref(stores)
    _write(store, ref)
    vault.valid_tokens.clear()  # server revoked the token
    meta = store.metadata(ref, mint(stores, "probe", ref))
    assert meta.current_version == 1 and vault.logins == 2


def test_genuine_403_on_a_fresh_token_is_denied_without_retry(vault, store):
    ref = new_ref(stores)
    vault.fail_next(403, ["permission denied"])
    with pytest.raises(stores.StoreError) as raised:
        store.metadata(ref, mint(stores, "probe", ref))
    assert raised.value.code == "DENIED" and vault.logins == 1


def test_persistent_403_with_a_cached_token_retries_once_then_denied(vault, store):
    ref = new_ref(stores)
    _write(store, ref)
    vault.fail_next(403)
    vault.fail_next(403)
    with pytest.raises(stores.StoreError) as raised:
        store.metadata(ref, mint(stores, "probe", ref))
    assert raised.value.code == "DENIED" and vault.logins == 2


def test_login_rejected_is_denied(vault, store):
    vault.login_fault = lambda request: response(403, {"errors": ["permission denied"]}, request.url)
    ref = new_ref(stores)
    with pytest.raises(stores.StoreError) as raised:
        store.metadata(ref, mint(stores, "probe", ref))
    assert raised.value.code == "DENIED" and not vault.requests_to("/metadata/")


def test_malformed_login_reply_is_unavailable(vault, store):
    vault.login_fault = lambda request: response(200, {"auth": None}, request.url)
    ref = new_ref(stores)
    with pytest.raises(stores.StoreError) as raised:
        store.metadata(ref, mint(stores, "probe", ref))
    assert raised.value.code == "UNAVAILABLE"


def test_empty_jwt_file_is_unavailable_and_never_calls_vault(vault, tmp_path):
    cfg = vault_config(tmp_path)
    store = corporate.CorporateVaultSecretStore(cfg)
    Path(cfg.CORPORATE_VAULT_JWT_PATH).write_text("  \n")  # rotated to empty after startup
    ref = new_ref(stores)
    with pytest.raises(stores.StoreError) as raised:
        store.metadata(ref, mint(stores, "probe", ref))
    assert raised.value.code == "UNAVAILABLE" and vault.seen == []


def test_jwt_file_is_reread_on_every_login(vault, tmp_path):
    vault.lease = 0  # every call logs in again
    cfg = vault_config(tmp_path)
    store = corporate.CorporateVaultSecretStore(cfg)
    ref = new_ref(stores)
    store.metadata(ref, mint(stores, "probe", ref))
    Path(cfg.CORPORATE_VAULT_JWT_PATH).write_text("rotated-jwt-fixture")
    store.metadata(ref, mint(stores, "probe", ref))
    assert [item.body["jwt"] for item in vault.requests_to("/login")] == [
        "jwt-fixture-not-a-credential", "rotated-jwt-fixture"]


# -- error map ---------------------------------------------------------------------------------

ERROR_MATRIX = [
    ("403", dict(status=403, errors=["permission denied"]), "DENIED"),
    ("503 sealed", dict(status=503, errors=["Vault is sealed"]), "SEALED"),
    ("404", dict(status=404, errors=[]), "NOT_FOUND"),
    ("400 cas", dict(status=400, errors=["check-and-set parameter did not match the current version"]),
     "VERSION_CONFLICT"),
    ("400 other", dict(status=400, errors=["invalid request"]), "UNAVAILABLE"),
    ("500", dict(status=500, errors=["internal error at /secret/path"]), "UNAVAILABLE"),
    ("502", dict(status=502, errors=[]), "UNAVAILABLE"),
    ("429", dict(status=429, errors=[]), "UNAVAILABLE"),
    ("401", dict(status=401, errors=[]), "UNAVAILABLE"),
    ("ssl", dict(exc=requests.exceptions.SSLError("certificate verify failed for vault.example.test")),
     "TLS_INVALID"),
    ("read timeout", dict(exc=requests.exceptions.ReadTimeout("timed out")), "UNAVAILABLE"),
    ("connect timeout", dict(exc=requests.exceptions.ConnectTimeout("timed out")), "UNAVAILABLE"),
    ("connection error", dict(exc=requests.exceptions.ConnectionError("refused")), "UNAVAILABLE"),
    ("unexpected", dict(exc=RuntimeError(SECRET_TEXT)), "UNAVAILABLE"),
]


@pytest.mark.parametrize("name,fault,code", ERROR_MATRIX, ids=[row[0] for row in ERROR_MATRIX])
@pytest.mark.parametrize("operation", ["read", "write", "metadata", "delete_all"])
def test_error_map(vault, store, name, fault, code, operation):
    _ = name
    ref = new_ref(stores)
    _write(store, ref)  # logs in; cached token
    vault.fail_next(**fault)
    calls = {
        "read": lambda: store.read(ref, 1, mint(stores, "probe", ref)),
        "write": lambda: store.write(ref, _value(), expected_version=1, ctx=mint(stores, "onboard", ref)),
        "metadata": lambda: store.metadata(ref, mint(stores, "probe", ref)),
        "delete_all": lambda: store.delete_all(ref, mint(stores, "retire", ref)),
    }
    expected = code
    if code == "DENIED":
        vault.fail_next(**fault)  # a cached token gets one re-login retry; the second 403 is final
    try:
        calls[operation]()
        outcome = "ok"
    except stores.StoreError as exc:
        outcome = exc.code
        text = "".join(traceback.format_exception(exc))
        for leaked in (SECRET_TEXT, str(ref.ref_id), "token-fixture", "vault.example.test", "/secret/path",
                       "jwt-fixture", "certificate verify"):
            assert leaked not in text and leaked not in repr(exc)
        assert exc.__cause__ is None and exc.__context__ is None
    if operation == "metadata" and code == "NOT_FOUND":
        assert outcome == "ok"  # absent reference: empty metadata, not an error
    elif operation == "delete_all" and code == "NOT_FOUND":
        assert outcome == "ok"  # already gone: idempotent
    elif operation == "write" and code == "NOT_FOUND":
        assert outcome == "NOT_FOUND"
    else:
        assert outcome == expected


def test_unexpected_hvac_errors_never_escape_raw(vault, store, monkeypatch):
    ref = new_ref(stores)
    monkeypatch.setattr(hvac, "Client", lambda **kw: (_ for _ in ()).throw(RuntimeError(SECRET_TEXT)))
    with pytest.raises(stores.StoreError) as raised:
        store.metadata(ref, mint(stores, "probe", ref))
    assert raised.value.code == "UNAVAILABLE" and SECRET_TEXT not in "".join(
        traceback.format_exception(raised.value))
    assert isinstance(raised.value, stores.StoreError)
    assert pickle.loads(pickle.dumps(raised.value)).code == "UNAVAILABLE"


def test_token_is_never_in_results_or_reprs(vault, store):
    ref = new_ref(stores)
    meta = _write(store, ref)
    value = store.read(ref, 1, mint(stores, "probe", ref))
    for obj in (meta, value, ref, store.metadata(ref, mint(stores, "probe", ref))):
        assert "token-fixture" not in repr(obj) and "token-fixture" not in str(obj)
    assert SECRET_TEXT not in repr(value) and SECRET_TEXT not in repr(meta)


def test_deleted_or_destroyed_versions_are_not_listed(vault, store):
    ref = new_ref(stores)
    _write(store, ref)
    _write(store, ref, 1)
    entry = vault.kv[f"t/local/cred/{ref.ref_id}"]
    original = vault.send

    def metadata_with_destroyed(request, **kwargs):
        reply = original(request, **kwargs)
        if request.method == "GET" and "/metadata/" in request.url and reply.status_code == 200:
            body = reply.json()
            body["data"]["versions"]["1"]["destroyed"] = True
            reply._content = json.dumps(body).encode()  # pylint: disable=W0212
        return reply

    vault.send = metadata_with_destroyed
    meta = store.metadata(ref, mint(stores, "probe", ref))
    assert meta.current_version == 2 and meta.versions == frozenset({2}) and entry["current"] == 2


# -- smoke -------------------------------------------------------------------------------------


def test_smoke_reports_each_policy_check(vault, store):
    ref = new_ref(stores)
    results = store.smoke(mint(stores, "smoke", ref, decision_id="smoke-decision-1"))
    assert results == {
        "read_canary": True, "list_denied": True, "foreign_tenant_denied": True, "write_without_cas_refused": True,
    }
    assert all(item.headers["X-Correlation-Id"] == "smoke-decision-1" for item in vault.seen)
    paths = [item.url.split("/v1/kv-elitea/")[1].split("?")[0] for item in vault.seen if "/v1/kv-elitea/" in item.url]
    assert "data/t/local/cred/canary-shared" in paths and "data/t/other-tenant/cred/canary-shared" in paths
    assert vault.logins == 1  # expected denials do not trigger re-login


@pytest.mark.parametrize("purpose", sorted(stores.PURPOSES - {"smoke"}))
def test_smoke_only_with_smoke_purpose(vault, store, purpose):
    with pytest.raises(stores.StoreError) as raised:
        store.smoke(mint(stores, purpose, new_ref(stores)))
    assert raised.value.code == "DENIED" and vault.seen == []


@pytest.mark.parametrize("canary", ["canary-", "x", "canary-UPPER", "canary-a/../b", "canary-" + "a" * 33, "", None,
                                    "t/other/cred/canary-x"])
def test_smoke_canary_names_are_validated(vault, store, canary):
    with pytest.raises(stores.StoreError) as raised:
        store.smoke(mint(stores, "smoke", new_ref(stores)), canary=canary)
    assert raised.value.code == "DENIED" and vault.seen == []


def test_smoke_detects_a_policy_that_allows_list_and_cas_less_write(vault, store):
    original = vault.send

    def permissive(request, **kwargs):
        if request.method == "LIST":
            return response(200, {"data": {"keys": ["a"]}}, request.url)
        if request.method == "POST" and "canary-smoke-nocas" in request.url and "login" not in request.url:
            return response(200, {"data": {"version": 1}}, request.url)
        return original(request, **kwargs)

    vault.send = permissive
    results = store.smoke(mint(stores, "smoke", new_ref(stores)))
    assert results["list_denied"] is False and results["write_without_cas_refused"] is False
    assert results["read_canary"] is True


def test_smoke_unreachable_vault_raises_typed_error(vault, store):
    vault.fail_next(exc=requests.exceptions.ConnectionError("down"))
    with pytest.raises(stores.StoreError) as raised:
        store.smoke(mint(stores, "smoke", new_ref(stores)))
    assert raised.value.code == "UNAVAILABLE"


# -- process-wide instance ---------------------------------------------------------------------


def test_get_store_builds_once_from_config_and_keeps_the_token(vault, monkeypatch, tmp_path):
    import tools  # pylint: disable=C0415
    cfg = vault_config(tmp_path)
    for name, value in vars(cfg).items():
        monkeypatch.setattr(tools.config, name, value, raising=False)
    monkeypatch.setattr(corporate, "_STORE", None)
    monkeypatch.setattr(tools.config, "SECRETS_ENGINE", "database", raising=False)
    first = stores.get_store("corporate_vault", governed=True)
    assert stores.get_store("corporate_vault", governed=True) is first
    ref = new_ref(stores)
    _write(first, ref)
    first.metadata(ref, mint(stores, "probe", ref))
    assert vault.logins == 1


def test_get_store_does_not_cache_a_failed_construction(monkeypatch, tmp_path):
    import tools  # pylint: disable=C0415
    monkeypatch.setattr(corporate, "_STORE", None)
    monkeypatch.setattr(tools.config, "CORPORATE_VAULT_ADDR", "https://vault.example.test", raising=False)
    monkeypatch.setattr(tools.config, "CORPORATE_VAULT_TENANT_SEGMENT", None, raising=False)
    with pytest.raises(stores.StoreError):
        stores.get_store("corporate_vault", governed=True)
    assert corporate._STORE is None  # pylint: disable=W0212
    _ = tmp_path


# -- static lint -------------------------------------------------------------------------------

FORBIDDEN = {
    "initialize", "submit_unseal_key", "submit_unseal_keys", "seal", "generate_root", "create_or_update_policy",
    "enable_secrets_engine", "enable_auth_method", "root_token",
}


def _tree():
    return ast.parse(Path(corporate.__file__).read_text(encoding="utf-8"))


def test_no_initialisation_unseal_root_policy_mount_or_auth_enable_paths():
    names = set()
    for node in ast.walk(_tree()):
        if isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
        elif isinstance(node, ast.keyword) and node.arg:
            names.add(node.arg)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update(alias.name.split(".")[-1] for alias in node.names)
    assert not names & FORBIDDEN, names & FORBIDDEN


def test_no_static_token_keyword_and_no_sys_or_policy_api_use():
    tree = _tree()
    keywords = {kw.arg for node in ast.walk(tree) if isinstance(node, ast.Call) for kw in node.keywords}
    assert "token" not in keywords
    attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert "sys" not in attributes  # client.sys.* is the administration surface
    assert not [a for a in attributes if "policy" in a or "unseal" in a or a.startswith("enable_")]


def test_only_the_designed_hvac_calls_are_used():
    attributes = {node.attr for node in ast.walk(_tree()) if isinstance(node, ast.Attribute)}
    used = attributes & {
        "read_secret_version", "create_or_update_secret", "read_secret_metadata",
        "delete_metadata_and_all_versions", "list_secrets", "jwt_login", "login",
    }
    assert used == {
        "read_secret_version", "create_or_update_secret", "read_secret_metadata",
        "delete_metadata_and_all_versions", "list_secrets", "jwt_login", "login",
    }


def test_mint_is_not_referenced_by_the_adapters():
    for name in ("corporate_vault.py", "database.py", "__init__.py"):
        source = (Path(corporate.__file__).parent / name).read_text(encoding="utf-8")
        assert ".mint(" not in source and "_SEAL" not in source
