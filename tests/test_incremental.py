"""awrecover incremental snapshots: unchanged files stored once, restore stays whole."""

from pathlib import Path

import pytest

from awrecover.store import RecoverError, drop, list_snapshots, restore, snapshot, verify


def _work(root: Path) -> Path:
    (root / "data").mkdir(parents=True)
    (root / "data" / "day1.jsonl").write_bytes(b"x" * 50_000)
    (root / "today.jsonl").write_bytes(b"y" * 10)
    return root


def test_second_snapshot_stores_only_what_changed(tmp_path):
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    s1 = snapshot(work, store, "s1", incremental=True)
    assert s1.meta["awrecover.kind"] == "tree" and s1.meta["new_bytes"] == 50_010
    (work / "today.jsonl").write_bytes(b"y" * 20)
    s2 = snapshot(work, store, "s2", incremental=True)
    assert s2.meta["new_bytes"] == 20 and s2.files == 2


def test_tree_snapshot_verifies_and_restores_atomically(tmp_path):
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    snapshot(work, store, "s1", incremental=True)
    assert verify(store, "s1")["restorable"] is True
    (work / "today.jsonl").write_bytes(b"broken")
    r = restore(store, "s1", work, keep_replaced=False)
    assert r["files"] == 2 and (work / "today.jsonl").read_bytes() == b"y" * 10


def test_verify_fails_on_a_corrupt_object(tmp_path):
    from awrecover.store import RestoreFailedError
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    snapshot(work, store, "s1", incremental=True)
    for obj in (store / "objects").glob("*/*"):
        obj.write_bytes(b"rot")
    with pytest.raises(RestoreFailedError):
        verify(store, "s1")


def test_drop_keeps_objects_another_snapshot_needs(tmp_path):
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    snapshot(work, store, "s1", incremental=True)
    (work / "today.jsonl").write_bytes(b"z")
    snapshot(work, store, "s2", incremental=True)
    drop(store, "s1")
    assert [s.label for s in list_snapshots(store)] == ["s2"]
    assert verify(store, "s2")["restorable"] is True


def test_seal_and_incremental_are_refused_together(tmp_path):
    work = _work(tmp_path / "w")
    with pytest.raises(RecoverError):
        snapshot(work, tmp_path / "store", "s1", incremental=True, seal=True)
