#   Copyright 2026 EPAM Systems
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" SecretStore adapter for a customer-operated Vault (KV v2, one path per credential reference).

Imported lazily by get_store(); never imported when governance is off. This module only
reads and writes secret versions: it has no init/unseal/seal/root/policy/mount/auth-enable paths.
"""

import os
import re
import threading
import time
from urllib.parse import urlparse

import hvac  # pylint: disable=E0401
import requests  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0401

from . import SecretMetadata, SecretValue, StoreError, check_context, plan_read_many
from .authority import AuthorizedStoreContext

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_ROLE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_NAMESPACE_RE = re.compile(r"^[A-Za-z0-9/_-]{1,128}$")
_CANARY_RE = re.compile(r"^canary-[a-z0-9-]{1,32}$")
_LOCAL_HOSTS = ("localhost", "127.0.0.1")
_AUTH_METHODS = ("jwt", "kubernetes")
_RELOGIN_MARGIN_S = 60

_DEFAULTS = {
    "MOUNT": "kv-elitea",
    "AUTH_MOUNT": "aks-elitea",
    "ROLE": "elitea-main",
    "JWT_PATH": "/var/run/secrets/vault/token",
    "TIMEOUT_S": 5,
    "POOL_SIZE": 8,
}


def _is_local_host(host):
    return host in _LOCAL_HOSTS or host.endswith(".localhost")


class CorporateVaultSecretStore:  # pylint: disable=R0902
    """ KV v2 at <mount>/t/<tenant>/cred/<ref_id>: one KV version per generation, CAS on every write """

    def __init__(self, cfg=None):
        if cfg is None:
            from tools import config as cfg  # pylint: disable=E0401,C0415
        #
        def get(name):
            value = getattr(cfg, f"CORPORATE_VAULT_{name}", None)
            return _DEFAULTS.get(name) if value in (None, "") else value
        #
        def invalid(key):
            log.warning("corporate_vault configuration invalid: %s", key)  # key name only, never a value
            return StoreError("UNAVAILABLE")
        #
        parsed = urlparse(str(get("ADDR") or ""))
        host = parsed.hostname or ""
        if not host or parsed.username or parsed.password:
            raise invalid("ADDR")
        if parsed.scheme != "https":
            if not (parsed.scheme == "http" and get("INSECURE_DEV_HTTP") and _is_local_host(host)):
                log.warning("corporate_vault configuration invalid: ADDR must be https")
                raise StoreError("TLS_INVALID")
        self._addr = f"{parsed.scheme}://{parsed.netloc}"
        #
        self._tenant = str(get("TENANT_SEGMENT") or "")
        self._mount = str(get("MOUNT"))
        self._auth_mount = str(get("AUTH_MOUNT"))
        self._role = str(get("ROLE"))
        self._auth_method = get("AUTH_METHOD")
        self._namespace = get("NAMESPACE")
        for key, ok in (
                ("TENANT_SEGMENT", _NAME_RE.match(self._tenant)),
                ("MOUNT", _NAME_RE.match(self._mount)),
                ("AUTH_MOUNT", _NAME_RE.match(self._auth_mount)),
                ("ROLE", _ROLE_RE.match(self._role)),
                ("AUTH_METHOD", self._auth_method in _AUTH_METHODS),
                ("NAMESPACE", self._namespace is None or _NAMESPACE_RE.match(str(self._namespace))),
        ):
            if not ok:
                raise invalid(key)
        #
        self._jwt_path = str(get("JWT_PATH"))
        if not os.path.isfile(self._jwt_path) or not os.access(self._jwt_path, os.R_OK):
            raise invalid("JWT_PATH")
        #
        try:
            self._timeout = int(get("TIMEOUT_S"))
        except (TypeError, ValueError):
            raise invalid("TIMEOUT_S") from None
        if not 0 < self._timeout <= 60:
            raise invalid("TIMEOUT_S")
        self._verify = get("CA_BUNDLE") or True
        try:
            pool_size = int(get("POOL_SIZE"))
        except (TypeError, ValueError):
            raise invalid("POOL_SIZE") from None
        if not 1 <= pool_size <= 64:
            raise invalid("POOL_SIZE")
        # one adapter = one urllib3 pool for the process: keep-alive and TLS sessions survive across calls
        # (sessions stay per call for header isolation and must never be close()d: that closes this pool)
        self._adapter = requests.adapters.HTTPAdapter(
            pool_connections=1, pool_maxsize=pool_size, max_retries=0, pool_block=False,
        )
        #
        self._lock = threading.Lock()
        self._token = None
        self._token_expires = 0.0
        log.info("corporate_vault adapter loaded")

    # -- transport ------------------------------------------------------------------------------

    def _session(self, ctx):
        session = requests.Session()  # one per call (headers are per decision); the pool is shared
        for prefix in ("https://", "http://"):
            session.mount(prefix, self._adapter)
        session.trust_env = False
        session.max_redirects = 0
        session.proxies = {}
        session.verify = self._verify
        session.headers["X-Correlation-Id"] = ctx.decision_id
        return session

    def _client(self, session):
        return hvac.Client(
            url=self._addr, verify=self._verify, timeout=self._timeout, allow_redirects=False,
            session=session, namespace=self._namespace,
        )

    def _login(self, session):
        try:
            with open(self._jwt_path, encoding="utf-8") as jwt_file:
                jwt = jwt_file.read().strip()
        except OSError:
            raise StoreError("UNAVAILABLE") from None
        if not jwt:
            raise StoreError("UNAVAILABLE")
        client = self._client(session)
        if self._auth_method == "jwt":
            reply = client.auth.jwt.jwt_login(
                role=self._role, jwt=jwt, use_token=False, path=self._auth_mount,
            )
        else:
            reply = client.auth.kubernetes.login(
                role=self._role, jwt=jwt, use_token=False, mount_point=self._auth_mount,
            )
        auth = _body(reply)["auth"]
        with self._lock:
            self._token = auth["client_token"]
            self._token_expires = time.monotonic() + int(auth.get("lease_duration") or 0)
            return self._token

    def _cached_token(self):
        with self._lock:
            if self._token and self._token_expires - time.monotonic() > _RELOGIN_MARGIN_S:
                return self._token
        return None

    def _forget_token(self):
        with self._lock:
            self._token = None

    def _call(self, ctx, operation, relogin=True, details=None):
        """ Run operation(client) with a session-scoped client; maps every failure to StoreError.

        details is an optional dict the operation keeps current (e.g. the ref_id in flight): it rides on the error.
        """
        session = self._session(ctx)
        try:
            fresh = False
            token = self._cached_token()
            if token is None:
                token, fresh = self._login(session), True
            for attempt in (0, 1):
                client = self._client(session)
                client.token = token
                try:
                    return operation(client)
                except hvac.exceptions.Forbidden:
                    if fresh or attempt or not relogin:
                        raise
                    self._forget_token()
                    token, fresh = self._login(session), True
        except StoreError:
            raise
        except Exception as exc:  # pylint: disable=W0703
            code = _error_code(exc)
        # no session.close(): it would close the shared adapter's pool; the session is simply dropped
        raise StoreError(code, details) from None

    def _path(self, ref_id):
        return f"t/{self._tenant}/cred/{ref_id}"

    # -- port -----------------------------------------------------------------------------------

    def read(self, ref, generation, ctx):
        return self.read_many([ref], [generation], ctx)[(ref.ref_id, int(generation))]

    def read_many(self, refs, generations, ctx):
        """ N KV GETs over ONE session, client and token check; all-or-nothing """
        planned = plan_read_many(refs, generations, ctx)
        if not planned:
            return {}
        details = {}
        #
        def operation(client):
            found = {}
            for ref, generation, item_ctx in planned:
                details["ref_id"] = str(ref.ref_id)
                client.adapter.session.headers["X-Correlation-Id"] = item_ctx.decision_id
                found[(ref.ref_id, generation)] = self._read_version(client, ref, generation)
            return found
        #
        return self._call(planned[0][2], operation, details=details)

    def _read_version(self, client, ref, generation):
        reply = client.secrets.kv.v2.read_secret_version(
            path=self._path(ref.ref_id), version=generation, mount_point=self._mount,
            raise_on_deleted_version=True,
        )
        data = _body(reply).get("data") or {}
        bundle = data.get("data")
        if bundle is None:
            raise StoreError("NOT_FOUND", {"ref_id": str(ref.ref_id)})
        if (data.get("metadata") or {}).get("version") != generation or not all(
                isinstance(value, str) for value in bundle.values()):
            raise StoreError("UNAVAILABLE", {"ref_id": str(ref.ref_id)})
        return SecretValue(bundle, generation)

    def write(self, ref, value, *, expected_version, ctx):
        check_context(ctx, ref, "write")
        expected_version = int(expected_version)
        bundle = {name: secret.get_secret_value() for name, secret in value.fields.items()}
        reply = self._call(ctx, lambda client: client.secrets.kv.v2.create_or_update_secret(
            path=self._path(ref.ref_id), secret=bundle, cas=expected_version, mount_point=self._mount,
        ))
        body = _body(reply)
        if (body.get("data") or {}).get("version") != expected_version + 1:
            raise StoreError("VERSION_CONFLICT")
        return SecretMetadata(
            current_version=expected_version + 1, versions=frozenset({expected_version + 1}),
            request_id=body.get("request_id"),
        )

    def metadata(self, ref, ctx):
        check_context(ctx, ref, "metadata")
        try:
            reply = self._call(ctx, lambda client: client.secrets.kv.v2.read_secret_metadata(
                path=self._path(ref.ref_id), mount_point=self._mount,
            ))
        except StoreError as exc:
            if exc.code == "NOT_FOUND":
                return SecretMetadata(current_version=0, versions=frozenset())
            raise
        body = _body(reply)
        data = body.get("data") or {}
        versions = frozenset(
            int(number) for number, info in (data.get("versions") or {}).items()
            if not info.get("destroyed") and not info.get("deletion_time")
        )
        return SecretMetadata(
            current_version=int(data.get("current_version") or 0), versions=versions,
            request_id=body.get("request_id"),
        )

    def prune(self, ref, keep_generations, ctx):
        """ Destroy all but the newest keep_generations (>= 1) KV versions (needs update on <mount>/destroy/...) """
        check_context(ctx, ref, "prune")
        if isinstance(keep_generations, bool) or not isinstance(keep_generations, int) or keep_generations < 1:
            raise ValueError("keep_generations must be an integer >= 1")
        #
        def operation(client):
            kv2 = client.secrets.kv.v2
            data = _body(kv2.read_secret_metadata(path=self._path(ref.ref_id), mount_point=self._mount)).get("data") or {}
            present = sorted(
                int(number) for number, info in (data.get("versions") or {}).items()
                if not info.get("destroyed") and not info.get("deletion_time")
            )
            doomed = present[:-keep_generations]
            if doomed:
                reply = kv2.destroy_secret_versions(
                    path=self._path(ref.ref_id), versions=doomed, mount_point=self._mount)
                if getattr(reply, "status_code", 204) not in (200, 204):  # e.g. an unfollowed redirect
                    raise StoreError("UNAVAILABLE")
            return int(data.get("current_version") or 0), frozenset(present[-keep_generations:])
        #
        try:
            current, versions = self._call(ctx, operation)
        except StoreError as exc:
            if exc.code == "NOT_FOUND":  # nothing stored: nothing to prune
                return SecretMetadata(current_version=0, versions=frozenset())
            raise
        return SecretMetadata(current_version=current, versions=versions)

    def delete_all(self, ref, ctx):
        check_context(ctx, ref, "delete_all")
        try:
            reply = self._call(ctx, lambda client: client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=self._path(ref.ref_id), mount_point=self._mount,
            ))
        except StoreError as exc:
            if exc.code == "NOT_FOUND":  # already gone: idempotent
                return
            raise
        if getattr(reply, "status_code", 204) not in (200, 204):  # e.g. an unfollowed redirect
            raise StoreError("UNAVAILABLE")

    # -- operator smoke test ------------------------------------------------------------------------

    def smoke(self, ctx, canary="canary-shared"):
        """ Verify the customer policy shape; returns {check: passed}. Operator only, purpose 'smoke' """
        if type(ctx) is not AuthorizedStoreContext or ctx.purpose != "smoke":  # pylint: disable=C0123
            raise StoreError("DENIED")
        if not _CANARY_RE.match(str(canary)):
            raise StoreError("DENIED")
        kv2 = lambda client: client.secrets.kv.v2  # noqa: E731
        foreign = "other-tenant" if self._tenant != "other-tenant" else "another-tenant"
        results = {}
        reply = self._call(ctx, lambda client: kv2(client).read_secret_version(
            path=f"t/{self._tenant}/cred/{canary}", mount_point=self._mount, raise_on_deleted_version=True,
        ))
        results["read_canary"] = isinstance(reply, dict)
        results["list_denied"] = self._denied(ctx, lambda client: kv2(client).list_secrets(
            path=f"t/{self._tenant}/cred", mount_point=self._mount,
        ))
        results["foreign_tenant_denied"] = self._denied(ctx, lambda client: kv2(client).read_secret_version(
            path=f"t/{foreign}/cred/{canary}", mount_point=self._mount, raise_on_deleted_version=True,
        ))
        results["write_without_cas_refused"] = self._refused(ctx, lambda client: kv2(client).create_or_update_secret(
            path=f"t/{self._tenant}/cred/canary-smoke-nocas", secret={"smoke": "1"}, mount_point=self._mount,
        ))
        return results

    def _denied(self, ctx, operation):
        try:
            self._call(ctx, operation, relogin=False)
        except StoreError as exc:
            if exc.code in ("DENIED", "NOT_FOUND"):  # NOT_FOUND: the call was allowed, only empty
                return exc.code == "DENIED"
            raise
        return False

    def _refused(self, ctx, operation):
        try:
            self._call(ctx, operation, relogin=False)
        except StoreError as exc:
            if exc.code in ("DENIED", "VERSION_CONFLICT"):  # 403 / "check-and-set required" (400)
                return True
            raise
        return False


def _body(reply):
    """ hvac returns a dict for 200 JSON and a Response otherwise (redirects, 204): only dicts are valid here """
    if not isinstance(reply, dict):
        raise StoreError("UNAVAILABLE")
    return reply


def _error_code(exc):
    """ Map a client/transport failure to a StoreCode; the exception text is never propagated """
    if isinstance(exc, hvac.exceptions.Forbidden):
        return "DENIED"
    if isinstance(exc, hvac.exceptions.VaultDown):
        return "SEALED"
    if isinstance(exc, hvac.exceptions.InvalidPath):
        return "NOT_FOUND"
    if isinstance(exc, hvac.exceptions.InvalidRequest):
        if "check-and-set" in " ".join(exc.errors or ()).lower():
            return "VERSION_CONFLICT"
        return "UNAVAILABLE"
    if isinstance(exc, requests.exceptions.SSLError):
        return "TLS_INVALID"
    return "UNAVAILABLE"


_STORE = None
_STORE_LOCK = threading.Lock()


def get_store():
    """ Process-wide instance (keeps the in-process Vault token); built and validated on first use """
    global _STORE  # pylint: disable=W0603
    with _STORE_LOCK:
        if _STORE is None:
            _STORE = CorporateVaultSecretStore()
        return _STORE
