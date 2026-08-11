"""
Unit tests for the P1 batch paths added to storage_engines/libcloud.py:
load_metas() and list_all_buckets_by_project(). Focus areas per the plan:
  - encoding round-trip: load_metas() must return byte-identical meta to
    _load_meta() for the same bucket, including base64-encoder-stressing names
  - I/O count: exactly one iterate_containers() walk, one make_session() per
    load_metas() call (not one per bucket)
  - notifier/deleter share the same precomputed listing+metas (no re-walk)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fixtures.libcloud_engine_loader import (  # noqa: E402  pylint: disable=C0413
    FakeContext, FakeDriver, load_libcloud_engine,
)

libcloud_engine = load_libcloud_engine()


def _make_engine(project_id, driver, encoder, context, bucket_prefix=None):
    """Build an EngineBase subclass instance without running its real __init__
    (which would construct a real libcloud driver)."""
    prefix = bucket_prefix if bucket_prefix is not None else f"p--{project_id}."

    class _TestEngine(libcloud_engine.EngineBase):
        @property
        def bucket_prefix(self):
            return prefix

    engine = _TestEngine.__new__(_TestEngine)
    engine.driver = driver
    engine.storage_libcloud_encoder = encoder
    return engine


def test_load_metas_matches_load_meta_for_existing_bucket(monkeypatch):
    context = FakeContext(rows={})
    monkeypatch.setattr(libcloud_engine, "context", context)
    engine = _make_engine(1, driver=None, encoder=None, context=context)

    engine._save_meta("bucket-a", {"lifecycle": 30, "tags": {"env": "prod"}})

    single = engine._load_meta("bucket-a")
    batched = engine.load_metas(["bucket-a"])

    assert batched["bucket-a"] == single == {"lifecycle": 30, "tags": {"env": "prod"}}


def test_load_metas_missing_bucket_defaults_to_empty_dict_like_load_meta(monkeypatch):
    context = FakeContext(rows={})
    monkeypatch.setattr(libcloud_engine, "context", context)
    engine = _make_engine(1, driver=None, encoder=None, context=context)

    assert engine._load_meta("never-created") == {}
    assert engine.load_metas(["never-created"]) == {"never-created": {}}


def test_load_metas_encoding_round_trip_base64(monkeypatch):
    """HIGHEST-RISK case: base64-encoded meta keys must map back to the
    original (unencoded) bucket names in the returned dict, exactly like
    calling _load_meta() per bucket would."""
    context = FakeContext(rows={})
    monkeypatch.setattr(libcloud_engine, "context", context)
    engine = _make_engine(1, driver=None, encoder="base64", context=context)

    bucket_names = ["bucket-a", "weird/name with spaces", "unicode-éè", "b" * 200]
    for name in bucket_names:
        engine._save_meta(name, {"lifecycle": 7, "tags": {"name": name}})

    expected = {name: engine._load_meta(name) for name in bucket_names}
    batched = engine.load_metas(bucket_names)

    assert batched == expected
    for name in bucket_names:
        assert batched[name]["tags"]["name"] == name


def test_load_metas_uses_one_session_not_one_per_bucket(monkeypatch):
    context = FakeContext(rows={})
    monkeypatch.setattr(libcloud_engine, "context", context)
    engine = _make_engine(1, driver=None, encoder=None, context=context)

    buckets = [f"bucket-{i}" for i in range(10)]
    for b in buckets:
        engine._save_meta(b, {"lifecycle": 5})

    context.db.make_session_calls = 0
    engine.load_metas(buckets)

    assert context.db.make_session_calls == 1


def test_load_metas_chunks_large_bucket_lists(monkeypatch):
    context = FakeContext(rows={})
    monkeypatch.setattr(libcloud_engine, "context", context)
    engine = _make_engine(1, driver=None, encoder=None, context=context)

    buckets = [f"bucket-{i}" for i in range(2500)]
    for b in buckets[:5]:
        engine._save_meta(b, {"lifecycle": 5})

    context.db.make_session_calls = 0
    result = engine.load_metas(buckets)

    assert context.db.make_session_calls == 1
    assert len(result) == len(buckets)
    assert result["bucket-0"] == {"lifecycle": 5}
    assert result["bucket-100"] == {}


def test_list_all_buckets_by_project_single_walk(monkeypatch):
    context = FakeContext()
    monkeypatch.setattr(libcloud_engine, "context", context)
    driver = FakeDriver(container_names=["p--1.logs", "p--1.uploads", "p--2.logs", "not-a-project-bucket"])
    engine = _make_engine(1, driver=driver, encoder=None, context=context)

    result = engine.list_all_buckets_by_project()

    assert driver.iterate_containers_calls == 1
    assert sorted(result["1"]) == ["logs", "uploads"]
    assert result["2"] == ["logs"]
    assert "not-a-project-bucket" not in result


def test_list_all_buckets_by_project_decodes_names(monkeypatch):
    context = FakeContext()
    monkeypatch.setattr(libcloud_engine, "context", context)
    encoded_name = libcloud_engine.fs_encode_name(name="p--3.reports", kind="bucket", encoder="base64")
    driver = FakeDriver(container_names=[encoded_name])
    engine = _make_engine(1, driver=driver, encoder="base64", context=context)

    result = engine.list_all_buckets_by_project()

    assert result == {"3": ["reports"]}


def test_get_bucket_lifecycle_matches_lifecycle_from_meta_batch_path(monkeypatch):
    context = FakeContext(rows={})
    monkeypatch.setattr(libcloud_engine, "context", context)
    engine = _make_engine(1, driver=None, encoder=None, context=context)

    engine._save_meta("bucket-a", {"lifecycle": 14})

    via_single = engine.get_bucket_lifecycle("bucket-a")
    via_batch = libcloud_engine.lifecycle_from_meta(engine.load_metas(["bucket-a"])["bucket-a"])

    assert via_single == via_batch == {"Rules": [{"Expiration": {"Days": 14}}]}


def test_prefix_builder_and_splitter_round_trip():
    """Review fix: list_all_buckets_by_project() parses via split_project_bucket_name() rather
    than its own partition(), so both directions of the p--{id}. convention stay in step.
    Multi-dot bucket names must survive the round trip."""
    for project_id, bucket in (("7", "logs"), ("7", "foo.bar.baz"), ("12905", "a.b")):
        name = libcloud_engine.EngineBase.project_bucket_prefix(project_id) + bucket
        assert libcloud_engine.EngineBase.split_project_bucket_name(name) == (project_id, bucket)


def test_splitter_rejects_non_project_and_malformed_names():
    split = libcloud_engine.EngineBase.split_project_bucket_name
    assert split("not-a-project-bucket") is None
    assert split("p--7") is None       # no separator
    assert split("p--.logs") is None   # no project id


def test_list_all_buckets_by_project_keeps_multi_dot_bucket_names(monkeypatch):
    context = FakeContext()
    monkeypatch.setattr(libcloud_engine, "context", context)
    driver = FakeDriver(container_names=["p--4.foo.bar"])
    engine = _make_engine(4, driver=driver, encoder=None, context=context)

    assert engine.list_all_buckets_by_project() == {"4": ["foo.bar"]}
