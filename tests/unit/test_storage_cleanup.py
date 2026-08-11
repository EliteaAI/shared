"""Unit tests for the gevent-ThreadPool storage retention cleanup RPC (P0 fix)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fixtures.storage_cleanup_loader import load_storage_cleanup  # noqa: E402  pylint: disable=C0413

storage_cleanup = load_storage_cleanup()


class _FakeTimeoutRpc:
    """Stand-in for `self.context.rpc_manager.timeout(n)`."""

    def __init__(self, project_list):
        self._project_list = project_list

    def artifacts_check_bucket_expiration_notifications(self, buckets_by_project=None, projects=None):
        return None

    def project_list(self, filter_=None):  # pylint: disable=unused-argument
        return self._project_list


class _FakeRpcManager:
    def __init__(self, project_list):
        self._project_list = project_list

    def timeout(self, _seconds):
        return _FakeTimeoutRpc(self._project_list)


class _FakeContext:
    def __init__(self, project_list):
        self.rpc_manager = _FakeRpcManager(project_list)


def _make_rpc(project_list):
    rpc = storage_cleanup.RPC()
    rpc.context = _FakeContext(project_list)
    return rpc


def _projects(n):
    return [{"id": i, "name": f"project_{i}"} for i in range(n)]


def test_aggregation_sums_success_skips_error_and_none(monkeypatch):
    monkeypatch.setattr(storage_cleanup, "MinioClient", storage_cleanup.ManualCleanupMixin)

    def fake_process(project, buckets=None):  # pylint: disable=unused-argument
        if project["id"] == 1:
            return {"project_id": 1, "name": "p1", "buckets_cleaned": 2, "files_deleted": 5, "buckets": {}}
        if project["id"] == 2:
            return {"project_id": 2, "name": "p2", "error": "boom"}
        return None  # project_id == 3, nothing to clean

    monkeypatch.setattr(storage_cleanup, "_process_project", fake_process)

    rpc = _make_rpc(_projects(3))
    result = rpc.storage_cleanup()

    assert result["success"] is True
    assert len(result["results"]) == 2
    assert result["total_files_deleted"] == 5
    assert result["total_buckets_cleaned"] == 2
    assert result["projects_with_cleanups"] == 1


def test_skips_when_engine_handles_lifecycle_natively(monkeypatch):
    class _S3Like:  # not a ManualCleanupMixin subclass
        pass

    monkeypatch.setattr(storage_cleanup, "MinioClient", _S3Like)

    called = []
    monkeypatch.setattr(storage_cleanup, "_process_project", lambda p: called.append(p))

    rpc = _make_rpc(_projects(3))
    result = rpc.storage_cleanup()

    assert result == {"skipped": True, "reason": "Storage engine handles lifecycle natively"}
    assert called == []


def test_processes_in_multiple_batches(monkeypatch):
    monkeypatch.setattr(storage_cleanup, "MinioClient", storage_cleanup.ManualCleanupMixin)
    monkeypatch.setattr(storage_cleanup, "CLEANUP_BATCH_SIZE", 2)

    seen_batches = []

    def fake_process(project, buckets=None):  # pylint: disable=unused-argument
        return None

    monkeypatch.setattr(storage_cleanup, "_process_project", fake_process)

    original_batch_list = storage_cleanup._batch_list

    def recording_batch_list(items, batch_size):
        for batch in original_batch_list(items, batch_size):
            seen_batches.append(batch)
            yield batch

    monkeypatch.setattr(storage_cleanup, "_batch_list", recording_batch_list)

    rpc = _make_rpc(_projects(3))  # batch size 2 -> batches of [2, 1]
    rpc.storage_cleanup()

    assert len(seen_batches) == 2
    assert [len(b) for b in seen_batches] == [2, 1]


def test_process_project_shields_exceptions_from_pool_map():
    class _RaisingMinioClient:
        def __init__(self, project):
            raise RuntimeError("cannot construct engine")

    original = storage_cleanup.MinioClient
    storage_cleanup.MinioClient = _RaisingMinioClient
    try:
        result = storage_cleanup._process_project({"id": 42, "name": "p42"})
    finally:
        storage_cleanup.MinioClient = original

    assert result == {"project_id": 42, "name": "p42", "error": "cannot construct engine"}


def test_single_global_walk_shared_between_notifier_and_deleter(monkeypatch):
    """P1: one list_all_buckets_by_project() call feeds both the notifier RPC
    and every _process_project() call, instead of each re-walking storage."""
    calls = []

    class _Engine(storage_cleanup.ManualCleanupMixin):
        def __init__(self, project):
            self.project = project

        def list_all_buckets_by_project(self):
            calls.append("walk")
            return {"1": ["b1"], "2": ["b2"]}

    monkeypatch.setattr(storage_cleanup, "MinioClient", _Engine)

    notifier_calls = []

    class _TimeoutRpc(_FakeTimeoutRpc):
        def artifacts_check_bucket_expiration_notifications(
                self, buckets_by_project=None, projects=None):
            notifier_calls.append(buckets_by_project)

    class _RpcManager(_FakeRpcManager):
        def timeout(self, _seconds):
            return _TimeoutRpc(self._project_list)

    process_calls = []
    monkeypatch.setattr(
        storage_cleanup, "_process_project",
        lambda p, buckets=None: process_calls.append((p["id"], buckets)),
    )

    projects = [{"id": 1, "name": "p1"}, {"id": 2, "name": "p2"}]
    rpc = storage_cleanup.RPC()
    rpc.context = _FakeContext(projects)
    rpc.context.rpc_manager = _RpcManager(projects)
    rpc.storage_cleanup()

    assert calls == ["walk"]
    assert notifier_calls == [{"1": ["b1"], "2": ["b2"]}]
    assert sorted(process_calls) == [(1, ["b1"]), (2, ["b2"])]


def test_per_project_storage_config_skips_global_walk(monkeypatch):
    """Review fix: with always_use_shared_storage=False a project can sit on a different
    backend, so one walk can't speak for all projects -- fall back to per-project walks
    rather than silently reporting zero buckets for the divergent project."""
    calls = []

    class _Engine(storage_cleanup.ManualCleanupMixin):
        def __init__(self, project):
            self.project = project

        def list_all_buckets_by_project(self):
            calls.append("walk")
            return {"1": ["b1"]}

    monkeypatch.setattr(storage_cleanup, "MinioClient", _Engine)
    monkeypatch.setattr(
        storage_cleanup.this, "descriptor",
        type("D", (), {"config": {"always_use_shared_storage": False}})(),
    )

    notified = []
    process_calls = []

    class _TimeoutRpc(_FakeTimeoutRpc):
        def artifacts_check_bucket_expiration_notifications(
                self, buckets_by_project=None, projects=None):
            notified.append(buckets_by_project)

    class _RpcManager(_FakeRpcManager):
        def timeout(self, _seconds):
            return _TimeoutRpc(self._project_list)

    monkeypatch.setattr(
        storage_cleanup, "_process_project",
        lambda p, buckets=None: process_calls.append((p["id"], buckets)),
    )

    projects = [{"id": 1, "name": "p1"}]
    rpc = storage_cleanup.RPC()
    rpc.context = _FakeContext(projects)
    rpc.context.rpc_manager = _RpcManager(projects)
    rpc.storage_cleanup()

    assert calls == []                      # no global walk taken
    assert notified == [None]               # notifier walks per project itself
    assert process_calls == [(1, None)]     # deleter walks per project itself


def test_notifier_payload_is_chunked_not_one_global_map(monkeypatch):
    """Review fix: the whole-deployment bucket map must not cross the RPC boundary in one
    argument, or the latency just moves into serialization/transport."""
    monkeypatch.setattr(storage_cleanup, "NOTIFY_BATCH_SIZE", 2)

    class _Engine(storage_cleanup.ManualCleanupMixin):
        def __init__(self, project):
            self.project = project

        def list_all_buckets_by_project(self):
            return {str(i): [f"b{i}"] for i in range(5)}

    monkeypatch.setattr(storage_cleanup, "MinioClient", _Engine)
    monkeypatch.setattr(storage_cleanup, "_process_project", lambda p, buckets=None: None)

    seen = []

    class _TimeoutRpc(_FakeTimeoutRpc):
        def artifacts_check_bucket_expiration_notifications(
                self, buckets_by_project=None, projects=None):
            seen.append((sorted(buckets_by_project), sorted(str(p['id']) for p in projects)))

    class _RpcManager(_FakeRpcManager):
        def timeout(self, _seconds):
            return _TimeoutRpc(self._project_list)

    projects = _projects(5)
    rpc = storage_cleanup.RPC()
    rpc.context = _FakeContext(projects)
    rpc.context.rpc_manager = _RpcManager(projects)
    rpc.storage_cleanup()

    assert [len(ids) for _, ids in seen] == [2, 2, 1]
    assert sorted(pid for _, ids in seen for pid in ids) == ["0", "1", "2", "3", "4"]
    # each chunk's bucket map covers exactly that chunk's projects, nothing wider
    for buckets, ids in seen:
        assert buckets == ids


def test_chunked_calls_pass_project_dicts_so_callee_need_not_refetch(monkeypatch):
    """Review fix: the notifier used to re-fetch the whole project table on every chunk just to
    discard everything outside it -- N/200 full scans per run. We hand it our own already-fetched
    project dicts instead."""
    monkeypatch.setattr(storage_cleanup, "NOTIFY_BATCH_SIZE", 2)

    class _Engine(storage_cleanup.ManualCleanupMixin):
        def __init__(self, project):
            self.project = project

        def list_all_buckets_by_project(self):
            return {str(i): [f"b{i}"] for i in range(3)}

    monkeypatch.setattr(storage_cleanup, "MinioClient", _Engine)
    monkeypatch.setattr(storage_cleanup, "_process_project", lambda p, buckets=None: None)

    passed = []

    class _TimeoutRpc(_FakeTimeoutRpc):
        def artifacts_check_bucket_expiration_notifications(
                self, buckets_by_project=None, projects=None):
            passed.append(projects)

    class _RpcManager(_FakeRpcManager):
        def timeout(self, _seconds):
            return _TimeoutRpc(self._project_list)

    projects = _projects(3)
    rpc = storage_cleanup.RPC()
    rpc.context = _FakeContext(projects)
    rpc.context.rpc_manager = _RpcManager(projects)
    rpc.storage_cleanup()

    # real project dicts, chunked, in order -- not None and not the full list every time
    assert passed == [projects[0:2], projects[2:3]]


def test_listing_without_project_list_never_sent_whole(monkeypatch):
    """Review fix: the unchunked branch must not be reachable with a populated listing. Called
    directly without the project list that listing was built from, the helper drops the listing
    rather than silently shipping a whole-deployment map in one RPC argument."""
    sent = []

    class _TimeoutRpc:
        def artifacts_check_bucket_expiration_notifications(
                self, buckets_by_project=None, projects=None):
            sent.append((buckets_by_project, projects))

    class _RpcManager:
        def timeout(self, _seconds):
            return _TimeoutRpc()

    storage_cleanup._notify_bucket_expiration(
        _RpcManager(), {str(i): [f"b{i}"] for i in range(500)}, [],
    )

    assert sent == [(None, None)]
