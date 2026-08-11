"""
Unit tests for the prefetch paths added to ManualCleanupMixin (P1 Step 5):
cleanup_all_buckets(buckets=, metas=) and cleanup_expired_files(bucket, meta=).
Asserts the prefetched path produces identical results to (and skips the I/O
of) the original per-call list_bucket()/get_bucket_lifecycle() path.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fixtures.libcloud_engine_loader import load_libcloud_engine  # noqa: E402  pylint: disable=C0413

libcloud_engine = load_libcloud_engine()
ManualCleanupMixin = libcloud_engine.ManualCleanupMixin


class _FakeEngine(ManualCleanupMixin):
    """Records calls so tests can assert what I/O was (not) performed."""

    def __init__(self, bucket_files, bucket_lifecycles, bucket_names):
        self._bucket_files = bucket_files
        self._bucket_lifecycles = bucket_lifecycles
        self._bucket_names = bucket_names
        self.list_bucket_calls = 0
        self.get_bucket_lifecycle_calls = 0
        self.removed = []

    def list_bucket(self):
        self.list_bucket_calls += 1
        return list(self._bucket_names)

    def get_bucket_lifecycle(self, bucket):
        self.get_bucket_lifecycle_calls += 1
        return self._bucket_lifecycles.get(bucket, {})

    def format_bucket_name(self, bucket):
        return bucket

    def list_files(self, bucket, next_continuation_token=None):  # pylint: disable=unused-argument
        return self._bucket_files.get(bucket, [])

    def remove_file(self, bucket, file_name):
        self.removed.append((bucket, file_name))


def _old_file(days_ago=1000):
    import datetime
    return {
        "name": f"old-{days_ago}",
        "modified": (datetime.datetime.now() - datetime.timedelta(days=days_ago)).isoformat(),
    }


def _fresh_file():
    import datetime
    return {"name": "fresh", "modified": datetime.datetime.now().isoformat()}


def test_cleanup_all_buckets_prefetched_matches_non_prefetched():
    files = {"b1": [_old_file(), _fresh_file()], "b2": [_old_file()]}
    lifecycles = {"b1": {"Rules": [{"Expiration": {"Days": 30}}]}, "b2": {"Rules": [{"Expiration": {"Days": 30}}]}}

    engine_a = _FakeEngine(files, lifecycles, ["b1", "b2"])
    result_a = engine_a.cleanup_all_buckets()

    engine_b = _FakeEngine(files, lifecycles, ["b1", "b2"])
    metas = {"b1": {"lifecycle": 30}, "b2": {"lifecycle": 30}}
    result_b = engine_b.cleanup_all_buckets(buckets=["b1", "b2"], metas=metas)

    assert result_a == result_b == {"b1": 1, "b2": 1}
    assert sorted(engine_a.removed) == sorted(engine_b.removed)


def test_cleanup_all_buckets_prefetched_skips_list_bucket_and_get_lifecycle():
    files = {"b1": [_old_file()]}
    lifecycles = {"b1": {"Rules": [{"Expiration": {"Days": 30}}]}}

    engine = _FakeEngine(files, lifecycles, ["b1"])
    engine.cleanup_all_buckets(buckets=["b1"], metas={"b1": {"lifecycle": 30}})

    assert engine.list_bucket_calls == 0
    assert engine.get_bucket_lifecycle_calls == 0


def test_cleanup_all_buckets_without_prefetch_falls_back_to_per_call_io():
    files = {"b1": [_old_file()]}
    lifecycles = {"b1": {"Rules": [{"Expiration": {"Days": 30}}]}}

    engine = _FakeEngine(files, lifecycles, ["b1"])
    engine.cleanup_all_buckets()

    assert engine.list_bucket_calls == 1
    assert engine.get_bucket_lifecycle_calls == 1


def test_cleanup_expired_files_meta_none_lifecycle_matches_prefetched_meta():
    files = {"b1": [_old_file(), _fresh_file()]}
    lifecycles = {"b1": {"Rules": [{"Expiration": {"Days": 10}}]}}

    engine_a = _FakeEngine(files, lifecycles, ["b1"])
    deleted_a = engine_a.cleanup_expired_files("b1")

    engine_b = _FakeEngine(files, lifecycles, ["b1"])
    deleted_b = engine_b.cleanup_expired_files("b1", meta={"lifecycle": 10})

    assert deleted_a == deleted_b == 1
    assert engine_a.removed == engine_b.removed == [("b1", "old-1000")]


def test_cleanup_expired_files_no_lifecycle_in_meta_returns_zero():
    engine = _FakeEngine({"b1": [_old_file()]}, {}, ["b1"])
    assert engine.cleanup_expired_files("b1", meta={}) == 0
    assert engine.removed == []
