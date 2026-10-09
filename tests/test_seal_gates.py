"""The seal and manifest refusals of a tree snapshot, on the path that changes data.

Each test here was proven by mutation (review of PR #12313, 2026-10-08): with the
named line removed, every other suite stayed green. `restore()` is what overwrites a
user's directory, so its seal gate is tested through restore, not only verify.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from awrecover.store import (
    MANIFEST_KEY,
    SEAL_KEY,
    RestoreFailedError,
    restore,
    snapshot,
    verify,
)
from awshare import RemoteObjectStore, digest_bytes

awseal = pytest.importorskip("awseal")

from .test_pooled import FakeTarget  # noqa: E402 -- after the importorskip


def _work(root: Path) -> Path:
    (root / "data").mkdir(parents=True)
    (root / "data" / "day1.jsonl").write_bytes(b"x" * 500)
    (root / "today.jsonl").write_bytes(b"y" * 10)
    return root


def _pool(t: FakeTarget) -> RemoteObjectStore:
    return RemoteObjectStore(t, "__t__/acme/objects", describe="pool:acme")


@pytest.fixture
def key(tmp_path) -> Path:
    return awseal.keygen(tmp_path / "keys" / "signer.key")


@pytest.fixture
def pub(key) -> str:
    return awseal.public_key_hex(path=key)


def _index(store: Path) -> dict:
    return json.loads((store / "awrecover.index.json").read_text(encoding="utf-8"))


def _write_index(store: Path, idx: dict) -> None:
    (store / "awrecover.index.json").write_text(json.dumps(idx), encoding="utf-8")


def _swap_in_evil_manifest(tmp_path: Path, store: Path) -> None:
    """An attacker with write access to the store: another tree's manifest under
    s1's name, and the index digest re-pointed so the digest check passes."""
    other = _work(tmp_path / "o")
    (other / "today.jsonl").write_bytes(b"attacker")
    snapshot(other, store, "evil", incremental=True)
    (store / "s1.awtree.json").write_bytes((store / "evil.awtree.json").read_bytes())
    idx = _index(store)
    idx["snapshots"]["s1"]["digest"] = idx["snapshots"]["evil"]["digest"]
    _write_index(store, idx)


def _assert_untouched(dest: Path) -> None:
    assert (dest / "today.jsonl").read_bytes() == b"current"
    assert not any(p.name.startswith(".awrecover-") for p in dest.parent.iterdir())


# ------------------------------------------------------------- restore's seal gate

def test_restore_with_the_owner_key_lands_and_reports_the_seal(tmp_path, key, pub):
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    snapshot(work, store, "s1", incremental=True, seal=True, key_path=key)
    (work / "today.jsonl").write_bytes(b"current")
    r = restore(store, "s1", work, expect_key=pub, keep_replaced=False)
    assert r["seal"]["ok"] is True and r["seal"]["modes_ok"] is True
    assert (work / "today.jsonl").read_bytes() == b"y" * 10


def test_restore_refuses_a_swapped_manifest_and_changes_nothing(tmp_path, key, pub):
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    snapshot(work, store, "s1", incremental=True, seal=True, key_path=key)
    _swap_in_evil_manifest(tmp_path, store)
    (work / "today.jsonl").write_bytes(b"current")
    with pytest.raises(RestoreFailedError, match="fails its seal"):
        restore(store, "s1", work, expect_key=pub)
    _assert_untouched(work)


def test_restore_refuses_an_unsealed_tree_when_a_key_is_given(tmp_path, pub):
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    snapshot(work, store, "s1", incremental=True)
    (work / "today.jsonl").write_bytes(b"current")
    with pytest.raises(RestoreFailedError, match="unsealed"):
        restore(store, "s1", work, expect_key=pub)
    _assert_untouched(work)


def test_restore_refuses_a_seal_by_another_key(tmp_path, key, pub):
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    snapshot(work, store, "s1", incremental=True, seal=True, key_path=key)
    (work / "today.jsonl").write_bytes(b"current")
    with pytest.raises(RestoreFailedError, match="key_trusted=False"):
        restore(store, "s1", work, expect_key="ab" * 32)
    _assert_untouched(work)


# ------------------------------------------------------------- the modes are signed

def test_a_mode_changed_under_its_seal_is_refused(tmp_path, key, pub):
    """REGRESSION: the seal covered {path: sha256} only, and restore chmods each
    entry's mode -- a store writer could add setuid and keep `seal ok=True`."""
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    snapshot(work, store, "s1", incremental=True, seal=True, key_path=key)
    mp = store / "s1.awtree.json"
    m = json.loads(mp.read_text(encoding="utf-8"))
    m["files"]["today.jsonl"]["mode"] = 0o4777
    raw = json.dumps(m, indent=1, sort_keys=True).encode("utf-8")
    mp.write_bytes(raw)
    idx = _index(store)
    idx["snapshots"]["s1"]["digest"] = digest_bytes(raw)
    _write_index(store, idx)
    with pytest.raises(RestoreFailedError, match="modes_ok=False"):
        verify(store, "s1", expect_key=pub)
    (work / "today.jsonl").write_bytes(b"current")
    with pytest.raises(RestoreFailedError, match="modes_ok=False"):
        restore(store, "s1", work, expect_key=pub)
    _assert_untouched(work)


def test_a_seal_that_signs_no_modes_is_refused(tmp_path, key, pub):
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    snapshot(work, store, "s1", incremental=True, seal=True, key_path=key)
    m = json.loads((store / "s1.awtree.json").read_text(encoding="utf-8"))
    files = {rel: ent["sha256"] for rel, ent in m["files"].items()}
    old = awseal.sign_files(files, key_path=key, meta={"label": "s1"})  # no modes
    raw = json.dumps(old.to_dict(), sort_keys=True).encode("utf-8")
    (store / "s1.awtree.seal.json").write_bytes(raw)
    idx = _index(store)
    idx["snapshots"]["s1"]["meta"][SEAL_KEY] = digest_bytes(raw)
    _write_index(store, idx)
    with pytest.raises(RestoreFailedError, match="modes_ok=False"):
        verify(store, "s1", expect_key=pub)


# ------------------------------------------------------- the seal and manifest bindings

def test_a_sealed_tree_whose_seal_is_gone_is_refused_even_without_a_key(tmp_path, key):
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    snapshot(work, store, "s1", incremental=True, seal=True, key_path=key)
    (store / "s1.awtree.seal.json").unlink()
    with pytest.raises(RestoreFailedError, match="seal is missing"):
        verify(store, "s1")
    (work / "today.jsonl").write_bytes(b"current")
    with pytest.raises(RestoreFailedError, match="seal is missing"):
        restore(store, "s1", work)
    _assert_untouched(work)


def test_a_self_consistent_seal_by_another_key_is_not_the_recorded_one(tmp_path, key):
    """With no expect_key, a re-signed seal over the same map verifies against itself;
    only the digest the index recorded tells it apart."""
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    snapshot(work, store, "s1", incremental=True, seal=True, key_path=key)
    sp = store / "s1.awtree.seal.json"
    real = awseal.from_dict(json.loads(sp.read_text(encoding="utf-8")))
    other_key = awseal.keygen(tmp_path / "keys" / "attacker.key")
    forged = awseal.sign_files(real.files, key_path=other_key, meta=real.meta)
    sp.write_bytes(json.dumps(forged.to_dict(), sort_keys=True).encode("utf-8"))
    with pytest.raises(RestoreFailedError, match="not the one recorded"):
        verify(store, "s1")


def test_a_pooled_manifest_other_than_the_indexed_one_is_refused(tmp_path):
    t = FakeTarget()
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    snapshot(work, store, "s1", incremental=True, object_store=_pool(t))
    other = _work(tmp_path / "o")
    (other / "today.jsonl").write_bytes(b"attacker")
    evil = snapshot(other, store, "evil", incremental=True, object_store=_pool(t))
    (store / "s1.awtree.json").unlink()
    idx = _index(store)
    idx["snapshots"]["s1"]["meta"][MANIFEST_KEY] = evil.meta[MANIFEST_KEY]
    _write_index(store, idx)
    with pytest.raises(RestoreFailedError, match="not the one the index recorded"):
        verify(store, "s1", object_store=_pool(t))


# ------------------------------------------------------------------------ the CLI

def test_cli_objects_implies_incremental(tmp_path, monkeypatch):
    from awrecover import cli

    t = FakeTarget()
    monkeypatch.setattr(cli, "_object_store", lambda a: _pool(t))
    work, store = _work(tmp_path / "w"), tmp_path / "store"
    rc = cli.main(["snapshot", str(work), "--store", str(store), "--label", "s1",
                   "--objects", "strata:warm", "--tenant", "acme"])
    assert rc == 0
    row = _index(store)["snapshots"]["s1"]
    assert row["meta"]["awrecover.kind"] == "tree"
    assert row["meta"]["awrecover.objects"] == "pool:acme"
