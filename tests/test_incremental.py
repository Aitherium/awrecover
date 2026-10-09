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


def test_seal_and_incremental_together_sign_the_tree_manifest(tmp_path):
    awseal = pytest.importorskip("awseal")
    work = _work(tmp_path / "w")
    key = awseal.keygen(tmp_path / "k" / "signer.key")
    snap = snapshot(work, tmp_path / "store", "s1", incremental=True, seal=True,
                    key_path=key)
    assert (tmp_path / "store" / "s1.awtree.seal.json").is_file()
    assert snap.meta["awrecover.seal_sha256"]
    r = verify(tmp_path / "store", "s1", expect_key=awseal.public_key_hex(path=key))
    assert r["sealed"] is True and r["seal"]["signature_ok"] is True


def test_an_object_store_without_incremental_is_refused(tmp_path):
    with pytest.raises(RecoverError):
        snapshot(_work(tmp_path / "w"), tmp_path / "store", "s1", object_store=object())


def test_history_marks_where_a_file_changed_and_find_globs(tmp_path):
    from awrecover.store import find, history
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    snapshot(work, store, "s1", incremental=True)
    snapshot(work, store, "s2", incremental=True)
    (work / "today.jsonl").write_bytes(b"new")
    snapshot(work, store, "s3", incremental=True)
    h = history(store, "today.jsonl")
    assert [(r["label"], r["changed"]) for r in h] == [("s1", True), ("s2", False), ("s3", True)]
    assert history(store, "nope.txt") == []
    assert {r["label"] for r in find(store, "data/*.jsonl")} == {"s1", "s2", "s3"}
