"""
Loads shared.tools.secret_stores as a real package (reusing the secret_engines loader's fake
parent packages) and provides in-memory fakes: a Fernet-backed SecretsData store for the
database adapter and a KV v2 Vault served through a `requests` transport adapter, so the
corporate adapter runs the real hvac code against it.
"""
import importlib
import json
import sys
import uuid
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import requests
from cryptography.fernet import Fernet

from fixtures.secret_engines_loader import load_secret_engines

PACKAGE = "shared.tools.secret_stores"


def load_secret_stores():
    """ Return the secret_stores package (adapter modules are NOT imported here) """
    load_secret_engines()
    return importlib.import_module(PACKAGE)


# -- database fake -----------------------------------------------------------------------------


class _Column:
    """ Records `Model.id == value` so the fake query knows which row is asked for """

    def __eq__(self, other):
        return ("eq", other)

    __hash__ = object.__hash__


class _Row:  # pylint: disable=too-few-public-methods
    def __init__(self, data):
        self.data = data


class _Query:
    def __init__(self, session, model):
        self._session, self._model, self._id = session, model, None

    @property
    def _table(self):
        db = self._session.db
        return db.keys if self._model.__name__ == "SecretsKey" else db.rows

    def get(self, row_id):
        return self._session.touch(self._table, row_id)

    def filter(self, condition):
        self._id = condition[1]
        return self

    def with_for_update(self):
        return self

    def one_or_none(self):
        return self._session.touch(self._table, self._id)

    def one(self):
        row = self.one_or_none()
        if row is None:
            raise KeyError(self._id)
        return row


class _Session:
    """ Transactional enough for the adapters: rollback restores data/adds/deletes; touched ids are recorded """

    def __init__(self, db):
        self.db = db
        self._restore, self._added, self._deleted = [], [], []
        db.sessions += 1

    def touch(self, table, row_id):
        self.db.touched.append(("key" if table is self.db.keys else "data", row_id))
        row = table.get(row_id)
        if row is not None:
            self._restore.append((row, row.data))
        return row

    def query(self, model):
        return _Query(self, model)

    def add(self, obj):
        self._added.append(obj)

    def delete(self, obj):
        self._deleted.append(obj)

    def commit(self):
        self.db.commits += 1
        for obj in self._added:
            self.db.rows[obj.id] = obj
        for obj in self._deleted:
            for table in (self.db.rows, self.db.keys):
                for row_id in [k for k, v in table.items() if v is obj]:
                    del table[row_id]
        self._restore, self._added, self._deleted = [], [], []

    def rollback(self):
        self.db.rollbacks += 1
        for row, data in reversed(self._restore):
            row.data = data
        self._restore, self._added, self._deleted = [], [], []

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class FakeSecretsDb:
    """ SecretsKey/SecretsData rows with real Fernet; one row per project id.

    Counters: sessions (make_session calls), commits, rollbacks; touched = every (table, row id) looked up, in order, table being 'key' or 'data'.
    """

    def __init__(self, project_ids=(1, 2)):
        self.commits = 0
        self.rollbacks = 0
        self.sessions = 0
        self.touched = []
        self.keys, self.rows = {}, {}
        for project_id in project_ids:
            key = Fernet.generate_key()
            self.keys[f"project-{project_id}"] = _Row(key)
            self.rows[f"project-{project_id}"] = _Row(Fernet(key).encrypt(json.dumps(
                {"secrets": {"keep": "kept"}, "hidden_secrets": {"h": "hidden"}}).encode()))
        self._fernet = {name: Fernet(row.data) for name, row in self.keys.items()}

    def install(self):
        """ Point the loaded database engine at this fake; returns the engine module """
        database, _mock = load_secret_engines()
        models = sys.modules["shared.models.secrets"]
        models.SecretsData.id = _Column()
        models.SecretsKey.id = _Column()
        database.context.db.make_session = lambda *a, **kw: _Session(self)
        return database

    def section(self, project_id, name):
        data = self.decrypted(project_id)
        return data.get(name)

    def decrypted(self, project_id, governed=False):
        db_key = f"project-{project_id}"
        row = self.rows[f"{db_key}:cs" if governed else db_key]
        return json.loads(self._fernet[db_key].decrypt(row.data).decode())

    def raw(self, project_id, governed=False):
        return self.rows[f"project-{project_id}" + (":cs" if governed else "")].data

    def seed_legacy_governed(self, project_id, section):
        """ Put a pre-split 'credential_store' section into the legacy blob (an unmigrated project) """
        db_key = f"project-{project_id}"
        data = self.decrypted(project_id)
        data["credential_store"] = section
        self.rows[db_key].data = self._fernet[db_key].encrypt(json.dumps(data).encode())


# -- Vault fake --------------------------------------------------------------------------------


def response(status, body=None, url="https://vault.example.test", headers=None):
    resp = requests.Response()
    resp.status_code = status
    resp.url = url
    resp.encoding = "utf-8"
    resp._content = b"" if body is None else json.dumps(body).encode()  # pylint: disable=W0212
    resp.headers["Content-Type"] = "application/json"
    resp.headers.update(headers or {})
    return resp


class FakeVault(requests.adapters.BaseAdapter):  # pylint: disable=R0902
    """ KV v2 (cas_required) + JWT/kubernetes login; policy: only t/<tenant>/cred/<name>, no list """

    def __init__(self, tenant="local", mount="kv-elitea", auth_mount="aks-elitea", lease=3600):
        super().__init__()
        self.tenant, self.mount, self.auth_mount, self.lease = tenant, mount, auth_mount, lease
        self.kv = {}  # path -> {"current": n, "versions": {n: {field: value}}}
        self.seen = []  # SimpleNamespace(method, url, headers, kwargs, body)
        self.logins = 0
        self.valid_tokens = set()
        self.faults = []  # callables(request) -> Response | raises; applied to the next non-login request
        self.login_fault = None  # callable(request) -> Response | raises; replaces the login reply
        self.kv[f"t/{tenant}/cred/canary-shared"] = {"current": 1, "versions": {1: {"canary": "fixture"}}}

    def close(self):
        pass

    def fail_next(self, status=None, errors=None, exc=None, headers=None):
        def fault(request):
            if exc is not None:
                raise exc
            return response(status, {"errors": errors or []}, request.url, headers)
        self.faults.append(fault)

    def requests_to(self, fragment):
        return [item for item in self.seen if fragment in item.url]

    def send(self, request, **kwargs):  # pylint: disable=R0911,R0912
        url = urlparse(request.url)
        body = json.loads(request.body) if request.body else {}
        self.seen.append(SimpleNamespace(
            method=request.method, url=request.url, headers=dict(request.headers), kwargs=kwargs, body=body))
        #
        if url.path == f"/v1/auth/{self.auth_mount}/login":
            if self.login_fault is not None:
                return self.login_fault(request)
            self.logins += 1
            token = f"token-fixture-{self.logins}"
            self.valid_tokens.add(token)
            return response(200, {"request_id": f"req-login-{self.logins}",
                                   "auth": {"client_token": token, "lease_duration": self.lease}}, request.url)
        #
        if self.faults:
            return self.faults.pop(0)(request)
        if request.headers.get("X-Vault-Token") not in self.valid_tokens:
            return response(403, {"errors": ["permission denied"]}, request.url)
        #
        kind, _, path = url.path[len(f"/v1/{self.mount}/"):].partition("/")
        if not url.path.startswith(f"/v1/{self.mount}/") or not path.startswith(f"t/{self.tenant}/cred/") \
                or request.method == "LIST":
            return response(403, {"errors": ["permission denied"]}, request.url)
        entry = self.kv.get(path)
        #
        if kind == "data" and request.method == "GET":
            wanted = int(parse_qs(url.query).get("version", [entry["current"] if entry else 0])[0])
            if entry is None or wanted not in entry["versions"]:
                return response(404, {"errors": []}, request.url)
            return response(200, {"request_id": "req-read", "data": {
                "data": dict(entry["versions"][wanted]),
                "metadata": {"version": wanted, "deletion_time": "", "destroyed": False}}}, request.url)
        if kind == "data" and request.method == "POST":
            cas = (body.get("options") or {}).get("cas")
            current = entry["current"] if entry else 0
            if cas is None:
                return response(400, {"errors": ["check-and-set parameter required for this call"]}, request.url)
            if cas != current:
                return response(
                    400, {"errors": ["check-and-set parameter did not match the current version"]}, request.url)
            entry = self.kv.setdefault(path, {"current": 0, "versions": {}})
            entry["current"] += 1
            entry["versions"][entry["current"]] = dict(body["data"])
            return response(200, {"request_id": "req-write", "data": {"version": entry["current"]}}, request.url)
        if kind == "metadata" and request.method == "GET":
            if entry is None:
                return response(404, {"errors": []}, request.url)
            return response(200, {"request_id": "req-meta", "data": {
                "current_version": entry["current"],
                "versions": {str(n): {"deletion_time": "", "destroyed": False} for n in entry["versions"]}}},
                request.url)
        if kind == "destroy" and request.method == "POST":
            if entry is None:
                return response(404, {"errors": []}, request.url)
            for number in body.get("versions") or ():
                entry["versions"].pop(int(number), None)
            return response(204, None, request.url)
        if kind == "metadata" and request.method == "DELETE":
            if entry is None:
                return response(404, {"errors": []}, request.url)
            del self.kv[path]
            return response(204, None, request.url)
        return response(404, {"errors": []}, request.url)


def install_fake_vault(monkeypatch, vault):
    """ Make every requests.Session() (and the shared HTTPAdapter) created by the adapter talk to `vault`; returns sessions """
    sessions = []
    real_session = requests.Session
    # the adapter mounts its own shared pool adapter on every session: make that one the fake too
    monkeypatch.setattr(requests.adapters, "HTTPAdapter", lambda *args, **kwargs: vault)

    def factory():
        session = real_session()
        session.mount("http://", vault)
        session.mount("https://", vault)
        sessions.append(session)
        return session

    monkeypatch.setattr(requests, "Session", factory)
    return sessions


def vault_config(tmp_path, **overrides):
    """ A complete CORPORATE_VAULT_* configuration object with a readable (fake) JWT file """
    jwt_file = tmp_path / "jwt"
    jwt_file.write_text("jwt-fixture-not-a-credential")
    values = {
        "ADDR": "https://vault.example.test", "TENANT_SEGMENT": "local", "AUTH_METHOD": "jwt",
        "JWT_PATH": str(jwt_file),
    }
    values.update(overrides)
    return SimpleNamespace(**{f"CORPORATE_VAULT_{key}": value for key, value in values.items()})


def new_ref(package, project_id=1, kind="database"):
    return package.StoreRef(ref_id=uuid.uuid4(), project_id=project_id, store_kind=kind, locator={"x": "restricted"})


def mint(package, purpose, ref, decision_id=None, actor_ref="user:1"):
    return package.CredentialStoreProvider.mint(
        purpose, decision_id=decision_id or str(uuid.uuid4()), actor_ref=actor_ref,
        project_id=ref.project_id, ref_id=ref.ref_id)
