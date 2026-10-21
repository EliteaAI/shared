"""SecretStore port: types, redaction, authority, factory and the flag-off guarantee (C-1009 #6757)."""
import copy
import json
import pickle
import sys
import traceback
from pathlib import Path
import uuid

import pytest

from fixtures.secret_stores_loader import load_secret_stores, mint, new_ref

stores = load_secret_stores()
FAKE_VALUE = "value-fixture-not-a-credential"
CORPORATE_MODULE = f"{stores.__name__}.corporate_vault"
CORPORATE_MODULE_FILE = Path(stores.__file__).parent / "corporate_vault.py"


@pytest.fixture(name="config")
def _config(monkeypatch):
    import tools  # the stub installed by conftest  # pylint: disable=C0415
    for name, value in (
            ("SECRETS_ENGINE", "database"), ("SECRETS_MASTER_KEY", "master-fixture"),
            ("CORPORATE_VAULT_ADDR", None)):
        monkeypatch.setattr(tools.config, name, value, raising=False)
    return tools.config


# -- redaction ---------------------------------------------------------------------------------


def test_secret_value_renders_field_names_only():
    value = stores.SecretValue({"password": FAKE_VALUE, "user": "name-fixture"}, 3)
    for text in (repr(value), str(value), f"{value}", "%s" % (value,)):
        assert text == "SecretValue(fields=['password', 'user'], generation=3)"
        assert FAKE_VALUE not in text


def test_secret_value_has_no_serializers_and_is_immutable():
    value = stores.SecretValue({"password": FAKE_VALUE}, 1)
    assert not hasattr(value, "model_dump") and not hasattr(value, "dict")
    with pytest.raises(TypeError):
        json.dumps(value)
    with pytest.raises(AttributeError):
        value.generation = 2
    with pytest.raises(TypeError):
        value.fields["x"] = "y"  # mapping proxy
    assert FAKE_VALUE not in repr(value.fields)  # SecretStr masks itself


@pytest.mark.parametrize("protocol", range(0, pickle.HIGHEST_PROTOCOL + 1))
def test_secret_value_cannot_be_pickled_or_copied(protocol):
    value = stores.SecretValue({"password": FAKE_VALUE}, 1)
    with pytest.raises(TypeError):
        pickle.dumps(value, protocol=protocol)
    with pytest.raises(TypeError):
        copy.copy(value)
    with pytest.raises(TypeError):
        copy.deepcopy(value)


def test_secret_value_rejects_bad_fields():
    with pytest.raises(ValueError):
        stores.SecretValue({"": "x"}, 1)
    with pytest.raises(ValueError):
        stores.SecretValue({"a": 1}, 1)


def test_store_ref_repr_omits_locator_and_is_not_picklable():
    ref = new_ref(stores)
    assert "restricted" not in repr(ref) and "restricted" not in str(ref)
    assert "locator" not in repr(ref)
    assert ref == stores.StoreRef(ref.ref_id, ref.project_id, ref.store_kind, {"other": "locator"})
    with pytest.raises(TypeError):
        pickle.dumps(ref)
    with pytest.raises(TypeError):
        json.dumps(ref)


@pytest.mark.parametrize("code", ["DENIED", "SEALED", "UNAVAILABLE", "TLS_INVALID", "NOT_FOUND", "VERSION_CONFLICT", "INVALID_REQUEST"])
def test_store_error_has_fixed_message_per_code(code):
    err = stores.StoreError(code)
    assert err.code == code and err.audit_code == f"STORE_{code}"
    assert str(err) == err.message == stores._MESSAGES[code]  # pylint: disable=W0212
    assert pickle.loads(pickle.dumps(err)).code == code
    assert stores.StoreError("something else").code == "UNAVAILABLE"


def test_store_error_messages_carry_no_locations_or_vendor_text():
    for message in stores._MESSAGES.values():  # pylint: disable=W0212
        assert "/" not in message and "http" not in message.lower() and "vault" not in message.lower()


# -- authority ---------------------------------------------------------------------------------


def test_context_cannot_be_constructed_without_the_seal():
    kwargs = dict(purpose="probe", decision_id="d1", actor_ref="user:1", project_id=1, ref_id=uuid.uuid4())
    with pytest.raises(TypeError):
        stores.AuthorizedStoreContext(**kwargs)
    with pytest.raises(TypeError):
        stores.AuthorizedStoreContext(_seal=object(), **kwargs)
    with pytest.raises(TypeError):
        stores.AuthorizedStoreContext(_seal=None, **kwargs)


def test_minted_context_is_immutable_and_uncopyable():
    ref = new_ref(stores)
    ctx = mint(stores, "probe", ref)
    with pytest.raises(AttributeError):
        ctx.purpose = "onboard"
    with pytest.raises(AttributeError):
        del ctx.purpose
    with pytest.raises(AttributeError):
        ctx.extra = 1
    for clone in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            clone(ctx)
    assert str(ref.ref_id) not in repr(ctx)


@pytest.mark.parametrize("bad", [
    dict(purpose="unknown"), dict(purpose=None), dict(decision_id="a\r\nX-Evil: 1"), dict(decision_id=""),
    dict(decision_id="x" * 129), dict(actor_ref=""), dict(project_id="1"), dict(project_id=True),
    dict(ref_id="not-a-uuid"),
])
def test_mint_validates_inputs(bad):
    kwargs = dict(purpose="probe", decision_id="d1", actor_ref="user:1", project_id=1, ref_id=uuid.uuid4())
    kwargs.update(bad)
    purpose = kwargs.pop("purpose")
    with pytest.raises(ValueError):
        stores.CredentialStoreProvider.mint(purpose, **kwargs)


def test_mint_accepts_uuid_decision_id():
    decision = uuid.uuid4()
    assert mint(stores, "smoke", new_ref(stores), decision_id=decision).decision_id == str(decision)


def test_purposes_are_the_designed_set():
    assert stores.PURPOSES == {"onboard", "probe", "retire", "reconcile", "smoke", "release"}


# -- factory and flag-off ----------------------------------------------------------------------


def _unload_corporate(monkeypatch):
    monkeypatch.delitem(sys.modules, CORPORATE_MODULE, raising=False)
    if hasattr(stores, "corporate_vault"):
        monkeypatch.delattr(stores, "corporate_vault")


def test_database_store_requires_database_engine_and_master_key_when_governed(config, monkeypatch):
    assert type(stores.get_store("database", governed=True)).__name__ == "DatabaseSecretStore"
    monkeypatch.setattr(config, "SECRETS_MASTER_KEY", None)
    assert type(stores.get_store("database", governed=False)).__name__ == "DatabaseSecretStore"
    with pytest.raises(stores.StoreError) as raised:
        stores.get_store("database", governed=True)
    assert raised.value.code == "UNAVAILABLE"
    monkeypatch.setattr(config, "SECRETS_ENGINE", "managed_vault")
    for governed in (True, False):
        with pytest.raises(stores.StoreError) as raised:
            stores.get_store("database", governed=governed)
        assert raised.value.code == "UNAVAILABLE"


@pytest.mark.parametrize("kind", ["managed_vault", "filesystem", "", None])
def test_other_store_kinds_are_unavailable(config, kind):
    _ = config
    with pytest.raises(stores.StoreError) as raised:
        stores.get_store(kind, governed=True)
    assert raised.value.code == "UNAVAILABLE"


@pytest.mark.parametrize("governed,addr", [(False, "https://vault.example.test"), (True, None), (True, "")])
def test_corporate_vault_unavailable_without_flag_or_address(config, monkeypatch, governed, addr):
    monkeypatch.setattr(config, "CORPORATE_VAULT_ADDR", addr)
    _unload_corporate(monkeypatch)
    with pytest.raises(stores.StoreError) as raised:
        stores.get_store("corporate_vault", governed=governed)
    assert raised.value.code == "UNAVAILABLE"
    assert CORPORATE_MODULE not in sys.modules  # flag off: the adapter module is never imported


def test_flag_off_database_use_never_imports_corporate_vault(config, monkeypatch):
    _ = config
    _unload_corporate(monkeypatch)
    stores.get_store("database", governed=False)
    stores.get_store("database", governed=True)
    assert CORPORATE_MODULE not in sys.modules


def test_flag_off_never_constructs_hvac_client(config, monkeypatch):
    hvac = pytest.importorskip("hvac")
    monkeypatch.setattr(config, "CORPORATE_VAULT_ADDR", "https://vault.example.test")
    constructed = []
    monkeypatch.setattr(hvac, "Client", lambda *a, **kw: constructed.append((a, kw)))
    _unload_corporate(monkeypatch)
    with pytest.raises(stores.StoreError):
        stores.get_store("corporate_vault", governed=False)
    stores.get_store("database", governed=False)
    assert constructed == [] and CORPORATE_MODULE not in sys.modules


def test_package_import_does_not_pull_adapters():
    source = open(stores.__file__, encoding="utf-8").read()
    assert "import corporate_vault" not in source and "from .database" not in source
    assert "importlib.import_module" in source


def test_errors_raised_by_factory_do_not_leak_config(config, monkeypatch):
    monkeypatch.setattr(config, "CORPORATE_VAULT_ADDR", "https://vault-secret-host.example.test")
    with pytest.raises(stores.StoreError) as raised:
        stores.get_store("corporate_vault", governed=False)
    text = "".join(traceback.format_exception(raised.value))
    assert "vault-secret-host" not in text


def test_store_error_details_are_attribution_only_and_survive_pickling():
    err = stores.StoreError("NOT_FOUND", {"ref_id": "11111111-1111-1111-1111-111111111111"})
    assert err.details == {"ref_id": "11111111-1111-1111-1111-111111111111"}
    assert "1111" not in str(err) and "1111" not in repr(err.args)  # the message stays fixed per code
    clone = pickle.loads(pickle.dumps(err))
    assert (clone.code, clone.details) == ("NOT_FOUND", err.details)
    assert stores.StoreError("DENIED").details == {}
    err.details["x"] = "y"
    assert stores.StoreError("DENIED").details == {}  # no shared default


def test_every_corporate_vault_key_the_adapter_reads_is_declared_in_both_config_files():
    import ast  # pylint: disable=C0415
    import re  # pylint: disable=C0415
    tools_dir = Path(CORPORATE_MODULE_FILE).parent.parent
    adapter = Path(CORPORATE_MODULE_FILE).read_text(encoding="utf-8")
    wanted = {f"CORPORATE_VAULT_{name}" for name in re.findall(r'get\("([A-Z_]+)"\)', adapter)}
    wanted |= {f"CORPORATE_VAULT_{name}" for name in re.findall(r'^    "([A-Z_]+)": ', adapter, re.M)}
    assert {"CORPORATE_VAULT_POOL_SIZE", "CORPORATE_VAULT_ADDR", "CORPORATE_VAULT_TIMEOUT_S"} <= wanted
    #
    settings = {  # (name, type, default) tuples of the real settings table in config.py
        node.elts[0].value: node.elts[1].value
        for node in ast.walk(ast.parse((tools_dir / "config.py").read_text(encoding="utf-8")))
        if isinstance(node, ast.Tuple) and len(node.elts) == 3
        and all(isinstance(item, ast.Constant) for item in node.elts[:2])
        and str(node.elts[0].value).startswith("CORPORATE_VAULT_")
    }
    fields = {
        node.target.id: ast.unparse(node.annotation)
        for node in ast.walk(ast.parse((tools_dir / "config_pydantic.py").read_text(encoding="utf-8")))
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
        and node.target.id.startswith("CORPORATE_VAULT_")
    }
    assert wanted <= set(settings), wanted - set(settings)
    assert wanted <= set(fields), wanted - set(fields)
    assert settings["CORPORATE_VAULT_POOL_SIZE"] == "int" and fields["CORPORATE_VAULT_POOL_SIZE"] == "Optional[int]"


def test_invalid_request_is_a_fixed_typed_code():
    err = stores.StoreError("INVALID_REQUEST", {"max": 64})
    assert err.audit_code == "STORE_INVALID_REQUEST" and err.details == {"max": 64} and "64" not in str(err)
