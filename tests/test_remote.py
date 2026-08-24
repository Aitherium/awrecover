"""The remote half, proven against a real git repo rather than a mock.

The one assertion everything else is in service of: a secret that was in the
workspace must not be findable in the bytes that reach the remote.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from awrecover import remote as rremote
from awrecover import store as rstore
from awrecover.store import INDEX_NAME

SECRET = "sk-live-THIS-MUST-NEVER-REACH-THE-REMOTE"
PW = "a passphrase the owner holds"

crypto = pytest.importorskip  # noqa: F841


def _git(args, cwd):
    p = subprocess.run(args, cwd=str(cwd), capture_output=True, text=True)
    assert p.returncode == 0, f"{args} -> {p.stderr[:300]}"


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    (ws / "knowledge").mkdir(parents=True)
    (ws / "secrets").mkdir(parents=True)
    (ws / "knowledge" / "notes.md").write_text("tenant runbook\n", encoding="utf-8")
    (ws / "secrets" / "vault.env").write_text(f"API_KEY={SECRET}\n", encoding="utf-8")
    (ws / "users.json").write_text('{"users":["jason"]}', encoding="utf-8")
    return ws


@pytest.fixture()
def bare_remote(tmp_path: Path) -> Path:
    bare = tmp_path / "recovery.git"
    bare.mkdir()
    _git(["git", "init", "--bare", "-b", "main", "."], bare)
    seed = tmp_path / "seed"
    seed.mkdir()
    _git(["git", "init", "-b", "main", "."], seed)
    (seed / "README.md").write_text("recovery repo\n", encoding="utf-8")
    _git(["git", "add", "-A"], seed)
    _git(["git", "-c", "user.email=t@t", "-c", "user.name=t",
          "commit", "-m", "init"], seed)
    _git(["git", "remote", "add", "origin", str(bare)], seed)
    _git(["git", "push", "-u", "origin", "main"], seed)
    return bare


def test_selftest_arms_all_pass():
    assert rremote.selftest() == 0


def test_secret_never_reaches_the_remote(tmp_path, workspace, bare_remote):
    store = tmp_path / "snaps"
    rstore.snapshot(workspace, store, "ws")
    rremote.push(store, "ws", str(bare_remote), PW)

    chk = tmp_path / "chk"
    _git(["git", "clone", str(bare_remote), str(chk)], tmp_path)
    for f in chk.rglob("*"):
        if f.is_file() and ".git" not in f.parts:
            assert SECRET.encode() not in f.read_bytes(), f"secret leaked in {f.name}"

    blobs = list((chk / "snapshots").glob("*.enc"))
    assert blobs, "nothing landed in the remote"
    assert all(rremote.is_encrypted(b.read_bytes()) for b in blobs)


def test_fresh_machine_recovers_with_no_local_state(tmp_path, workspace, bare_remote):
    """boot -> pull -> restore. Nothing local is prepared by hand."""
    store = tmp_path / "snaps"
    rstore.snapshot(workspace, store, "ws")
    rremote.push(store, "ws", str(bare_remote), PW)

    fresh = tmp_path / "fresh"
    rremote.pull(str(bare_remote), "ws", fresh, PW)
    # pull must rebuild the index row too, or `restore` reports an unknown label
    # -- which reads as a corrupt backup rather than as missing local state.
    assert (fresh / INDEX_NAME).is_file()

    dest = tmp_path / "restored"
    rstore.restore(fresh, "ws", dest)
    assert (dest / "secrets" / "vault.env").read_text(encoding="utf-8").strip() == \
        f"API_KEY={SECRET}"
    assert (dest / "users.json").read_text(encoding="utf-8") == '{"users":["jason"]}'


def test_wrong_passphrase_refuses(tmp_path, workspace, bare_remote):
    store = tmp_path / "snaps"
    rstore.snapshot(workspace, store, "ws")
    rremote.push(store, "ws", str(bare_remote), PW)
    with pytest.raises(rremote.RemoteError):
        rremote.pull(str(bare_remote), "ws", tmp_path / "no", "wrong")


def test_push_refuses_half_a_bundle(tmp_path, workspace, bare_remote):
    """An archive with no manifest restores nowhere -- and only on the machine
    doing the recovery, which is the worst place to find out."""
    store = tmp_path / "snaps"
    rstore.snapshot(workspace, store, "ws")
    (store / "ws.awshare.json").unlink()
    with pytest.raises(rremote.RemoteError):
        rremote.push(store, "ws", str(bare_remote), PW)


def test_remote_list_reports_empty_as_empty(tmp_path, bare_remote):
    assert rremote.remote_list(str(bare_remote)) == []


def test_unpack_refuses_a_path_traversing_member(tmp_path):
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        ti = tarfile.TarInfo("../escaped.txt")
        data = b"x"
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    with pytest.raises(rremote.RemoteError):
        rremote._unpack(buf.getvalue(), tmp_path / "s", "ws")
