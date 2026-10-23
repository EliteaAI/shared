"""Live check against the local dev Vault (c1009-dev). Skipped unless C1009_VAULT_ADDR is set.

Environment:
  C1009_VAULT_ADDR      e.g. http://vault.localhost:8200 (http only for localhost / *.localhost / 127.0.0.1)
  C1009_VAULT_JWT_PATH  file holding a JWT whose subject is bound to role elitea-main
  C1009_VAULT_TENANT    tenant segment (default: local)
  C1009_VAULT_CA_BUNDLE optional CA bundle for https
"""
import os
import uuid
from importlib import import_module
from types import SimpleNamespace

import pytest

from fixtures.secret_stores_loader import load_secret_stores, mint

pytestmark = [
    pytest.mark.vault_dev,
    pytest.mark.skipif(not os.environ.get("C1009_VAULT_ADDR"), reason="C1009_VAULT_ADDR not set"),
]

stores = load_secret_stores()


@pytest.fixture(name="store")
def _store():
    pytest.importorskip("hvac")
    cfg = SimpleNamespace(
        CORPORATE_VAULT_ADDR=os.environ["C1009_VAULT_ADDR"],
        CORPORATE_VAULT_TENANT_SEGMENT=os.environ.get("C1009_VAULT_TENANT", "local"),
        CORPORATE_VAULT_AUTH_METHOD="jwt",
        CORPORATE_VAULT_JWT_PATH=os.environ["C1009_VAULT_JWT_PATH"],
        CORPORATE_VAULT_CA_BUNDLE=os.environ.get("C1009_VAULT_CA_BUNDLE"),
        CORPORATE_VAULT_INSECURE_DEV_HTTP=os.environ["C1009_VAULT_ADDR"].startswith("http://"),
    )
    return import_module(f"{stores.__name__}.corporate_vault").CorporateVaultSecretStore(cfg)


def test_login_cas_write_read_metadata_delete(store):
    ref = stores.StoreRef(uuid.uuid4(), 1, "corporate_vault", {})
    written = store.write(
        ref, stores.SecretValue({"api_key": "live-fixture-not-a-credential"}, 1), expected_version=0,
        ctx=mint(stores, "onboard", ref))
    assert written.current_version == 1 and written.request_id
    probe = mint(stores, "probe", ref)
    assert store.read(ref, 1, probe).fields["api_key"].get_secret_value() == "live-fixture-not-a-credential"
    meta = store.metadata(ref, probe)
    assert meta.current_version == 1 and meta.request_id
    with pytest.raises(stores.StoreError) as raised:
        store.write(ref, stores.SecretValue({"a": "b"}, 1), expected_version=0, ctx=mint(stores, "onboard", ref))
    assert raised.value.code == "VERSION_CONFLICT"
    store.delete_all(ref, mint(stores, "retire", ref))
    assert store.metadata(ref, probe).current_version == 0


def test_policy_smoke(store):
    ref = stores.StoreRef(uuid.uuid4(), 1, "corporate_vault", {})
    assert store.smoke(mint(stores, "smoke", ref)) == {
        "read_canary": True, "list_denied": True, "foreign_tenant_denied": True, "write_without_cas_refused": True,
    }
