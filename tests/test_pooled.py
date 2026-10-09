"""awrecover tree snapshots whose objects live in an object store, and sealed trees."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from awrecover.store import (
    MANIFEST_KEY,
    OBJECTS_KEY,
    RecoverError,
    RestoreFailedError,
    drop,
    list_snapshots,
    restore,
    snapshot,
    verify,
)
from awshare import RemoteObjectStore

awseal = pytest.importorskip("awseal")


class FakeTarget:
    def __init__(self) -> None:
        self.blobs: dict = {}
        self.uploads: list = []
        self.serve_rot = False

    def upload_verified(self, rel, data, sha256, metadata=None):
        self.blobs[rel] = bytes(data)
        self.uploads.append(rel)
        return {"bytes": len(data)}

    def stat_or_none(self, rel):
        if rel not in self.blobs:
            return None
        return {"size": len(self.blobs[rel]),
                "hash": hashlib.sha256(self.blobs[rel]).hexdigest()}

    def get(self, rel):
        return (b"rot" if self.serve_rot else b"") + self.blobs[rel]


def _work(root: Path) -> Path:
    (root / "data").mkdir(parents=True)
    (root / "data" / "day1.jsonl").write_bytes(b"x" * 5000)
    (root / "today.jsonl").write_bytes(b"y" * 10)
    return root


def _pool(t: FakeTarget, prefix: str = "__t__/acme/objects") -> RemoteObjectStore:
    return RemoteObjectStore(t, prefix, describe=f"pool:{prefix}")


def test_pooled_snapshot_round_trips_and_a_second_one_sends_nothing(tmp_path):
    t = FakeTarget()
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    s1 = snapshot(work, store, "s1", incremental=True, object_store=_pool(t))
    assert s1.meta[OBJECTS_KEY] == "pool:__t__/acme/objects"
    assert not (store / "objects").exists()
    sent = len(t.uploads)
    assert sent == 3  # two files + the manifest
    s2 = snapshot(work, store, "s2", incremental=True, object_store=_pool(t))
    assert s2.meta["new_objects"] == 0 and s2.meta["new_bytes"] == 0
    assert len(t.uploads) == sent + 1  # only s2's own manifest
    (work / "today.jsonl").write_bytes(b"broken")
    r = restore(store, "s2", work, keep_replaced=False, object_store=_pool(t))
    assert r["files"] == 2 and (work / "today.jsonl").read_bytes() == b"y" * 10
    assert (work / "data" / "day1.jsonl").read_bytes() == b"x" * 5000


def test_a_pooled_snapshot_is_refused_without_its_store_or_against_another(tmp_path):
    t = FakeTarget()
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    snapshot(work, store, "s1", incremental=True, object_store=_pool(t))
    with pytest.raises(RecoverError, match="keeps its objects in pool:"):
        verify(store, "s1")
    with pytest.raises(RecoverError, match="was taken into pool:"):
        verify(store, "s1", object_store=_pool(t, "__t__/other/objects"))
    assert verify(store, "s1", object_store=_pool(t))["restorable"] is True


def test_a_lost_local_manifest_comes_back_from_the_pool(tmp_path):
    t = FakeTarget()
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    s1 = snapshot(work, store, "s1", incremental=True, object_store=_pool(t))
    (store / "s1.awtree.json").unlink()
    assert s1.meta[MANIFEST_KEY] == s1.digest
    assert verify(store, "s1", object_store=_pool(t))["files"] == 2


def test_rot_in_the_pool_makes_verify_fail_and_restore_change_nothing(tmp_path):
    t = FakeTarget()
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    snapshot(work, store, "s1", incremental=True, object_store=_pool(t))
    t.serve_rot = True
    with pytest.raises(RestoreFailedError):
        verify(store, "s1", object_store=_pool(t))
    (work / "today.jsonl").write_bytes(b"current")
    with pytest.raises(RestoreFailedError):
        restore(store, "s1", work, object_store=_pool(t))
    assert (work / "today.jsonl").read_bytes() == b"current"


def test_an_object_store_needs_a_tree_snapshot(tmp_path):
    with pytest.raises(RecoverError):
        snapshot(_work(tmp_path / "w"), tmp_path / "store", "s1",
                 object_store=_pool(FakeTarget()))


class DeletingTarget(FakeTarget):
    """A target that CAN delete, so a drop that garbage-collects the pool would show."""

    def __init__(self) -> None:
        super().__init__()
        self.deleted: list = []

    def delete(self, rel):
        self.deleted.append(rel)
        self.blobs.pop(rel, None)


def test_drop_of_a_pooled_snapshot_keeps_the_pool(tmp_path, monkeypatch):
    import awshare.dedupe

    t = DeletingTarget()
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    snapshot(work, store, "s1", incremental=True, object_store=_pool(t))
    before = dict(t.blobs)

    def _no_local_gc(*_a, **_k):
        raise AssertionError("a pooled drop ran a garbage collection over the local "
                             "store; its objects are not there, so a GC judges the "
                             "wrong store")

    monkeypatch.setattr(awshare.dedupe, "drop_tree", _no_local_gc)
    monkeypatch.setattr(awshare.dedupe, "gc", _no_local_gc)
    drop(store, "s1")
    assert list_snapshots(store) == [] and t.deleted == [] and t.blobs == before
    assert not (store / "s1.awtree.json").exists()


# ------------------------------------------------------------------ sealed trees

@pytest.fixture
def key(tmp_path) -> Path:
    return awseal.keygen(tmp_path / "keys" / "signer.key")


def test_a_sealed_pooled_tree_verifies_against_its_publisher(tmp_path, key):
    t = FakeTarget()
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    snapshot(work, store, "s1", incremental=True, seal=True, key_path=key,
             object_store=_pool(t))
    pub = awseal.public_key_hex(path=key)
    r = verify(store, "s1", expect_key=pub, object_store=_pool(t))
    assert r["sealed"] is True and r["seal"]["ok"] is True
    with pytest.raises(RestoreFailedError):
        verify(store, "s1", expect_key="ab" * 32, object_store=_pool(t))


def test_a_manifest_swapped_under_its_seal_is_refused(tmp_path, key):
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    snapshot(work, store, "s1", incremental=True, seal=True, key_path=key)
    other = _work(tmp_path / "o")
    (other / "today.jsonl").write_bytes(b"attacker")
    snapshot(other, store, "evil", incremental=True)
    # Swap the evil manifest in, and re-point the index digest at it.
    (store / "s1.awtree.json").write_bytes((store / "evil.awtree.json").read_bytes())
    idx = json.loads((store / "awrecover.index.json").read_text())
    idx["snapshots"]["s1"]["digest"] = idx["snapshots"]["evil"]["digest"]
    (store / "awrecover.index.json").write_text(json.dumps(idx))
    with pytest.raises(RestoreFailedError):
        verify(store, "s1")


def test_a_local_manifest_that_is_not_the_indexed_one_is_refused(tmp_path):
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    snapshot(work, store, "s1", incremental=True)
    other = _work(tmp_path / "o")
    (other / "today.jsonl").write_bytes(b"attacker")
    snapshot(other, store, "evil", incremental=True)
    (store / "s1.awtree.json").write_bytes((store / "evil.awtree.json").read_bytes())
    with pytest.raises(RestoreFailedError, match="does not match the digest"):
        verify(store, "s1")


def test_an_unsealed_tree_is_not_verified_when_a_key_is_asked_for(tmp_path):
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    snapshot(work, store, "s1", incremental=True)
    assert verify(store, "s1")["sealed"] is False
    with pytest.raises(RestoreFailedError):
        verify(store, "s1", expect_key="ab" * 32)


def test_sealing_without_a_key_refuses_before_storing_anything(tmp_path):
    t = FakeTarget()
    with pytest.raises(Exception):  # noqa: B017 - awseal's own missing-key error
        snapshot(_work(tmp_path / "w"), tmp_path / "store", "s1", incremental=True,
                 seal=True, key_path=tmp_path / "nope.key", object_store=_pool(t))
    assert t.uploads == []


def test_cli_objects_without_a_strata_credential_could_not_run(tmp_path, monkeypatch,
                                                               capsys):
    strata = pytest.importorskip("awstorage.strata")
    assert hasattr(strata, "strata_object_store"), "awstorage predates the pool store"
    from awrecover.cli import main

    for var in (strata.KEY_ENV, strata.BEARER_ENV):
        monkeypatch.delenv(var, raising=False)
    rc = main(["snapshot", str(_work(tmp_path / "w")), "--store", str(tmp_path / "s"),
               "--label", "s1", "--objects", "strata:warm", "--tenant", "acme"])
    assert rc == 2 and "COULD NOT RUN" in capsys.readouterr().err
    assert not (tmp_path / "s" / "awrecover.index.json").exists()
