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

    def artifacts_check_bucket_expiration_notifications(self, buckets_by_project=None):
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
        def artifacts_check_bucket_expiration_notifications(self, buckets_by_project=None):
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
