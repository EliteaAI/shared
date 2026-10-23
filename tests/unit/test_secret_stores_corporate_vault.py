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
_REAL_NEW_ADAPTER = corporate._new_adapter  # pylint: disable=W0212  # before any fixture swaps it for the fake
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
    elif name == "connection error" and operation in ("read", "metadata"):
        assert outcome == "ok"  # a dead kept-alive connection: read-only calls retry once (never write/delete)
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


# -- read_many / shared connection pool / prune (perf PR 1) ---------------------------------------


def _stored(store, count, generations=1):
    refs = []
    for index in range(count):
        ref = new_ref(stores, 1, "corporate_vault")
        for generation in range(1, generations + 1):
            store.write(ref, _value(n=f"{index}.{generation}"), expected_version=generation - 1,
                        ctx=mint(stores, "onboard", ref))
        refs.append(ref)
    return refs


def test_read_many_of_six_refs_is_six_gets_over_one_session_one_login(vault, store):
    refs = _stored(store, 6)
    sessions_before, logins_before, gets_before = len(vault.sessions), vault.logins, len(vault.requests_to("/data/"))
    ctxs = [mint(stores, "release", ref, decision_id=f"decision-fixture-{n}") for n, ref in enumerate(refs)]
    found = store.read_many(refs, [1] * 6, ctxs)
    assert len(vault.sessions) - sessions_before == 1                  # one Session() for the whole batch
    assert vault.logins == logins_before                                 # token cached: no login at all
    reads = vault.requests_to("/data/")[gets_before:]
    assert [item.method for item in reads] == ["GET"] * 6
    assert [item.headers["X-Correlation-Id"] for item in reads] == [f"decision-fixture-{n}" for n in range(6)]
    assert sorted(found) == sorted((ref.ref_id, 1) for ref in refs)


def test_read_is_a_thin_wrapper_one_session_one_get(vault, store):
    (ref,) = _stored(store, 1)
    sessions_before, gets_before = len(vault.sessions), len(vault.requests_to("/data/"))
    ctx = mint(stores, "probe", ref, decision_id="decision-fixture-9")
    assert store.read(ref, 1, ctx).generation == 1
    assert len(vault.sessions) - sessions_before == 1
    (item,) = vault.requests_to("/data/")[gets_before:]
    assert item.headers["X-Correlation-Id"] == "decision-fixture-9"


def test_read_many_names_the_failing_ref_for_missing_and_forbidden(vault, store):
    ok, missing = _stored(store, 2)
    ctxs = [mint(stores, "release", ok), mint(stores, "release", missing)]
    with pytest.raises(stores.StoreError) as raised:
        store.read_many([ok, missing], [1, 5], ctxs)
    assert raised.value.code == "NOT_FOUND" and raised.value.details == {"ref_id": str(missing.ref_id)}
    vault.fail_next(status=500, errors=["boom-fixture"])  # fault applies to the first KV request of the call
    with pytest.raises(stores.StoreError) as raised:
        store.read_many([ok, missing], [1, 1], ctxs)
    assert raised.value.code == "UNAVAILABLE" and raised.value.details == {"ref_id": str(ok.ref_id)}
    assert "boom-fixture" not in "".join(traceback.format_exception(raised.value))


def test_read_many_relogs_in_once_on_a_stale_token_and_still_uses_one_session(vault, store):
    refs = _stored(store, 3)
    vault.valid_tokens.clear()  # every cached token is now stale -> first GET is 403
    sessions_before = len(vault.sessions)
    found = store.read_many(refs, [1] * 3, [mint(stores, "release", ref) for ref in refs])
    assert len(found) == 3 and len(vault.sessions) - sessions_before == 1


def test_pool_size_defaults_to_eight_and_is_configurable_and_validated(vault, make):
    _ = vault
    with pytest.MonkeyPatch.context() as patch:  # the fixture replaced the adapter factory with the fake
        patch.setattr(corporate, "_new_adapter", _REAL_NEW_ADAPTER)
        assert make()._adapter._pool_maxsize == 8  # pylint: disable=W0212
        assert make(POOL_SIZE=3)._adapter._pool_maxsize == 3  # pylint: disable=W0212
        assert make(POOL_SIZE="16")._adapter._pool_maxsize == 16  # pylint: disable=W0212
        for bad in (0, 65, "x", -1):
            with pytest.raises(stores.StoreError) as raised:
                make(POOL_SIZE=bad)
            assert raised.value.code == "UNAVAILABLE"




class _KvServer:
    """ Real loopback HTTP/1.1 keep-alive server: login + KV v2 reads; counts TCP connections and requests """

    def __init__(self, bundles):
        import http.server  # pylint: disable=C0415
        import threading  # pylint: disable=C0415
        outer = self
        self.requests, self.connections, self.drop = [], 0, 0  # drop: next N requests get the socket closed unanswered

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _reply(self, body):
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):  # login
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.requests.append(("POST", self.path))
                self._reply({"auth": {"client_token": "token-fixture", "lease_duration": 3600}})

            def do_GET(self):
                outer.requests.append(("GET", self.path))
                if outer.drop > 0:  # a kept-alive connection the peer is closing just as we reuse it
                    outer.drop -= 1
                    self.close_connection = True
                    return
                path, _, query = self.path.partition("?")
                version = int(query.split("version=")[1].split("&")[0])
                self._reply({"data": {"data": bundles[path.rsplit("/", 1)[1]],
                                      "metadata": {"version": version}}})

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = True

            def get_request(self):
                request = super().get_request()
                outer.connections += 1
                return request

        self.server = Server(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def test_connections_are_reused_across_reads_and_calls(tmp_path):
    # real sockets, real requests/urllib3 pool: the shared adapter keeps the TCP connection alive
    refs = [new_ref(stores, 1, "corporate_vault") for _ in range(6)]
    kv = _KvServer({str(ref.ref_id): {"api_key": SECRET_TEXT} for ref in refs})
    try:
        store = corporate.CorporateVaultSecretStore(
            vault_config(tmp_path, ADDR=kv.url, INSECURE_DEV_HTTP=True))
        ctxs = [mint(stores, "release", ref) for ref in refs]
        assert len(store.read_many(refs, [1] * 6, ctxs)) == 6
        assert kv.connections == 1                                       # login + 6 GETs on ONE connection
        assert len([r for r in kv.requests if r[0] == "GET"]) == 6 and len(kv.requests) == 7
        assert len(store.read_many(refs, [1] * 6, ctxs)) == 6
        store.read(refs[0], 1, mint(stores, "probe", refs[0]))
        assert kv.connections == 1                                       # and across later calls (no close())
    finally:
        kv.close()


def test_prune_destroys_all_but_the_newest_versions_over_one_session(vault, store):
    ref, other = _stored(store, 2, generations=4)
    sessions_before = len(vault.sessions)
    meta = store.prune(ref, 2, mint(stores, "reconcile", ref))
    assert len(vault.sessions) - sessions_before == 1
    assert meta.versions == frozenset({3, 4}) and meta.current_version == 4
    (destroy,) = [item for item in vault.seen if "/destroy/" in item.url]
    assert destroy.method == "POST" and destroy.body == {"versions": [1, 2]}
    assert destroy.url.endswith(f"/destroy/t/local/cred/{ref.ref_id}")
    assert store.metadata(other, mint(stores, "probe", other)).versions == frozenset({1, 2, 3, 4})


def test_prune_with_nothing_older_makes_no_destroy_call(vault, store):
    (ref,) = _stored(store, 1, generations=2)
    assert store.prune(ref, 2, mint(stores, "reconcile", ref)).versions == frozenset({1, 2})
    assert not [item for item in vault.seen if "/destroy/" in item.url]


def test_prune_destroy_redirect_is_not_success(vault, store):
    (ref,) = _stored(store, 1, generations=3)
    vault.faults.append(lambda request: response(200, {"data": {
        "current_version": 3, "versions": {"1": {}, "2": {}, "3": {}}}}, request.url))
    vault.fail_next(status=307, errors=[], headers={"Location": "https://elsewhere.invalid/"})
    with pytest.raises(stores.StoreError) as raised:
        store.prune(ref, 1, mint(stores, "reconcile", ref))
    assert raised.value.code == "UNAVAILABLE"


def _kv_store(tmp_path, refs, pool_size=None):
    kv = _KvServer({str(ref.ref_id): {"api_key": SECRET_TEXT} for ref in refs})
    overrides = {"POOL_SIZE": pool_size} if pool_size else {}
    store = corporate.CorporateVaultSecretStore(vault_config(tmp_path, ADDR=kv.url, INSECURE_DEV_HTTP=True, **overrides))
    return kv, store


def test_a_dead_kept_alive_connection_is_retried_once_for_reads(tmp_path):
    refs = [new_ref(stores, 1, "corporate_vault") for _ in range(3)]
    ctxs = [mint(stores, "release", ref) for ref in refs]
    kv, store = _kv_store(tmp_path, refs)
    try:
        assert len(store.read_many(refs, [1] * 3, ctxs)) == 3 and kv.connections == 1
        kv.drop = 1                                   # the pooled connection dies under the next request
        assert len(store.read_many(refs, [1] * 3, ctxs)) == 3
        assert kv.connections == 2                    # pool dropped, one fresh connection, no more
        gets = [r for r in kv.requests if r[0] == "GET"]
        assert len(gets) == 3 + 1 + 3                 # first call, the dropped GET, the complete retry
        kv.drop = 2                                   # a second consecutive failure is final: one retry only
        with pytest.raises(stores.StoreError) as raised:
            store.read(refs[0], 1, mint(stores, "probe", refs[0]))
        assert raised.value.code == "UNAVAILABLE"
        kv.drop = 0
        assert store.read(refs[0], 1, mint(stores, "probe", refs[0])).generation == 1  # and the store recovers
    finally:
        kv.close()


def test_connection_errors_are_retried_for_reads_only_never_for_writes_or_tls(vault, store):
    ref = new_ref(stores)
    _write(store, ref)
    posts = lambda: len([item for item in vault.requests_to("/data/") if item.method == "POST"])  # noqa: E731
    gets = lambda: len([item for item in vault.requests_to("/data/") if item.method == "GET"])  # noqa: E731
    #
    vault.fail_next(exc=requests.exceptions.ConnectionError("reset"))
    assert store.read(ref, 1, mint(stores, "probe", ref)).generation == 1
    assert (vault.pool_clears, gets()) == (1, 2)
    #
    vault.fail_next(exc=requests.exceptions.ChunkedEncodingError("cut"))
    store.metadata(ref, mint(stores, "probe", ref))
    assert vault.pool_clears == 2
    #
    before = posts()
    vault.fail_next(exc=requests.exceptions.ConnectionError("reset"))
    with pytest.raises(stores.StoreError) as raised:
        store.write(ref, _value(n="2"), expected_version=1, ctx=mint(stores, "onboard", ref))
    assert raised.value.code == "UNAVAILABLE" and posts() - before == 1 and vault.pool_clears == 2  # CAS: never
    #
    vault.fail_next(exc=requests.exceptions.SSLError("bad certificate"))
    with pytest.raises(stores.StoreError) as raised:
        store.read(ref, 1, mint(stores, "probe", ref))
    assert raised.value.code == "TLS_INVALID" and vault.pool_clears == 2                # deterministic: no retry
    #
    vault.fail_next(exc=requests.exceptions.ConnectTimeout("slow"))
    with pytest.raises(stores.StoreError):
        store.read(ref, 1, mint(stores, "probe", ref))
    assert vault.pool_clears == 2                                                         # timeouts: no retry


def test_sockets_get_tcp_keepalive_and_the_pool_is_sized_from_config(vault, make):
    _ = vault
    import socket  # pylint: disable=C0415
    adapter = _REAL_NEW_ADAPTER(5)
    options = adapter.poolmanager.connection_pool_kw["socket_options"]
    assert (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1) in options and (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1) in options
    assert adapter._pool_maxsize == 5  # pylint: disable=W0212


def test_concurrent_callers_never_leave_more_idle_connections_than_pool_size(tmp_path):
    import threading  # pylint: disable=C0415
    refs = [new_ref(stores, 1, "corporate_vault") for _ in range(2)]
    kv, store = _kv_store(tmp_path, refs, pool_size=3)
    store._adapter.pool_block = False  # pylint: disable=W0212
    results, errors = [], []
    start = threading.Barrier(12)
    #
    def work(index):
        try:
            start.wait(5)
            for _ in range(3):
                results.append(store.read(refs[index % 2], 1, mint(stores, "probe", refs[index % 2])).generation)
        except Exception as exc:  # pylint: disable=W0703
            errors.append(exc)
    #
    threads = [threading.Thread(target=work, args=(index,)) for index in range(12)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        assert not errors and results == [1] * 36
        pools = store._adapter.poolmanager.pools  # pylint: disable=W0212
        idle = sum(1 for key in list(pools.keys()) for conn in list(pools[key].pool.queue) if conn is not None)
        assert 1 <= idle <= 3                          # overflow connections were closed, not kept
        assert kv.connections >= 2
    finally:
        kv.close()


def test_pool_overflow_warning_is_silenced_for_the_vault_host_only(vault, store, caplog):
    _ = vault, store
    import logging  # pylint: disable=C0415
    logger = logging.getLogger("urllib3.connectionpool")
    with caplog.at_level(logging.WARNING, logger="urllib3.connectionpool"):
        logger.warning("Connection pool is full, discarding connection: %s. Connection pool size: %s",
                       "vault.example.test", 8)
        logger.warning("Connection pool is full, discarding connection: %s. Connection pool size: %s",
                       "other.example.test", 8)
        logger.warning("Retrying (%r) after connection broken by %r: %s", "r", "e", "/x")
    messages = [record.getMessage() for record in caplog.records]
    assert not any("vault.example.test" in message for message in messages)
    assert any("other.example.test" in message for message in messages) and any("Retrying" in m for m in messages)


def test_details_are_reset_for_every_attempt(vault, store):
    ref = new_ref(stores)
    _write(store, ref)  # caches a token so a stale-token 403 triggers a re-login retry
    seen, details = [], {}
    #
    def operation(client):
        seen.append(dict(details))
        details["ref_id"] = "stale-from-attempt-one"
        if len(seen) == 1:
            raise hvac.exceptions.Forbidden("denied")
        return "done"
    #
    assert store._call(mint(stores, "probe", ref), operation, details=details) == "done"  # pylint: disable=W0212
    assert seen == [{}, {}]


def test_prune_is_denied_when_the_policy_lacks_destroy(vault, store):
    ref, other = _stored(store, 2, generations=3)
    vault.denied_kinds.add("destroy")
    with pytest.raises(stores.StoreError) as raised:
        store.prune(ref, 1, mint(stores, "reconcile", ref))
    assert raised.value.code == "DENIED"
    assert store.metadata(ref, mint(stores, "probe", ref)).versions == frozenset({1, 2, 3})  # nothing was destroyed


def test_prune_counts_only_live_versions_and_soft_deleted_ones_are_kept(vault, store):
    (ref,) = _stored(store, 1, generations=5)
    vault.kv[f"t/local/cred/{ref.ref_id}"]["destroyed"] = {1}       # destroyed earlier: listed, data gone
    meta = store.prune(ref, 2, mint(stores, "reconcile", ref))
    (destroy,) = [item for item in vault.seen if "/destroy/" in item.url]
    assert destroy.body == {"versions": [2, 3]}                       # not 1: already destroyed, so not counted
    assert meta.versions == frozenset({4, 5})
    assert store.prune(ref, 2, mint(stores, "reconcile", ref)).versions == frozenset({4, 5})
    assert len([item for item in vault.seen if "/destroy/" in item.url]) == 1  # second prune: nothing to do
    with pytest.raises(stores.StoreError) as raised:
        store.read(ref, 3, mint(stores, "probe", ref))
    assert raised.value.code == "NOT_FOUND"


def test_smoke_only_warns_when_destroy_is_not_permitted(vault, store, monkeypatch):
    warnings = []
    monkeypatch.setattr(corporate, "log", type("L", (), {
        "warning": staticmethod(lambda *a, **kw: warnings.append(a)), "info": staticmethod(lambda *a, **kw: None)}))
    ref = new_ref(stores)
    expected = {"read_canary": True, "list_denied": True, "foreign_tenant_denied": True, "write_without_cas_refused": True}
    assert store.smoke(mint(stores, "smoke", ref)) == expected and warnings == []
    vault.denied_kinds.add("destroy")
    assert store.smoke(mint(stores, "smoke", ref)) == expected       # still passes: destroy is a warning, not a check
    assert len(warnings) == 1 and "destroy" in warnings[0][0] and SECRET_TEXT not in repr(warnings)
    probe = [item for item in vault.seen if "/destroy/" in item.url][-1]
    assert probe.body == {"versions": [corporate._NO_SUCH_VERSION]}  # pylint: disable=W0212  # nothing real is destroyed


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
        "delete_metadata_and_all_versions", "list_secrets", "jwt_login", "login", "destroy_secret_versions",
    }
    assert used == {
        "read_secret_version", "create_or_update_secret", "read_secret_metadata",
        "delete_metadata_and_all_versions", "list_secrets", "jwt_login", "login", "destroy_secret_versions",
    }


def test_mint_is_not_referenced_by_the_adapters():
    for name in ("corporate_vault.py", "database.py", "__init__.py"):
        source = (Path(corporate.__file__).parent / name).read_text(encoding="utf-8")
        assert ".mint(" not in source and "_SEAL" not in source
