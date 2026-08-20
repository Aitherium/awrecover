"""Labelled snapshots of a directory, and getting one back.

Extracted from AitherOS's backup/recovery client. The internal version drives a
service over HTTP — backup_now, create_snapshot, restore_snapshot,
schedule_backups. What generalises is smaller and more useful on its own: take a
labelled snapshot of a directory, list what you have, and put one back without
leaving a half-restored tree behind.

WHY THIS IS THIN, AND WHY THAT IS THE POINT

A snapshot IS an `awshare` bundle. Rather than reimplementing archiving,
digesting, atomic writes and path containment — all of which awshare already
does, with the traversal bypasses as test cases — awrecover adds only the two
things awshare deliberately does not have: a LABEL index, and a restore that
either fully lands or does not land at all.

THE RULE THIS FAMILY EXISTS FOR

**A backup nobody has restored is not a backup, it is a hypothesis.** Every
restore path here is exercised by the self-test against real files, and
`verify()` restores a snapshot into a scratch directory and compares it, rather
than checking that a file of about the right size exists. The cheap version of
this check — "the archive is present and non-empty" — passes for a snapshot of
the wrong directory, a snapshot truncated mid-write, and a snapshot of nothing.

RESTORE IS ATOMIC OR IT IS NOTHING

A restore that copies half the files and then fails has destroyed the working
state AND not delivered the snapshot — strictly worse than refusing. So a
restore unpacks into a staging directory beside the target, verifies it, and
only then swaps. The window where neither is in place is one rename wide.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import awshare
    _HAVE_AWSHARE = True
except ImportError:  # pragma: no cover
    _HAVE_AWSHARE = False

INDEX_NAME = "awrecover.index.json"
INDEX_VERSION = 1


class RecoverError(RuntimeError):
    """Could not judge, or could not act. Never a silent partial success."""


class RestoreFailedError(RecoverError):
    """The snapshot was checked and it is not restorable."""


def _require_awshare() -> None:
    if not _HAVE_AWSHARE:
        raise RecoverError(
            "awrecover needs `awshare` for the archive/digest/atomic-write "
            "layer. It is a hard dependency rather than an optional one: a "
            "snapshot tool that degrades to 'archiving unavailable' produces "
            "records that look like backups and are not")


@dataclass
class Snapshot:
    label: str
    created: str
    digest: str
    files: int
    subject: str
    meta: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {"label": self.label, "created": self.created,
                "digest": self.digest, "files": self.files,
                "subject": self.subject, "meta": self.meta}


def _index_path(store: Path) -> Path:
    return store / INDEX_NAME


def load_index(store: Path) -> Dict[str, Snapshot]:
    p = _index_path(store)
    if not p.is_file():
        return {}
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RecoverError(f"snapshot index {p} is unreadable: {exc}") from exc
    if d.get("version") != INDEX_VERSION:
        raise RecoverError(
            f"{p} is index version {d.get('version')!r}, this is "
            f"{INDEX_VERSION}. Refusing rather than guessing — a misread index "
            f"points a restore at the wrong archive")
    return {k: Snapshot(**v) for k, v in (d.get("snapshots") or {}).items()}


def save_index(store: Path, snaps: Dict[str, Snapshot]) -> None:
    payload = {"version": INDEX_VERSION,
               "snapshots": {k: v.to_dict() for k, v in snaps.items()}}
    awshare.atomic_write(_index_path(store),
                         json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"))


def snapshot(root: Path, store: Path, label: str, *, seal: bool = False,
             key_path: Optional[Path] = None,
             meta: Optional[Dict[str, Any]] = None) -> Snapshot:
    """Take a labelled snapshot of `root` into `store`."""
    _require_awshare()
    if not label or "/" in label or "\\" in label or label.startswith("."):
        raise RecoverError(
            f"refusing label {label!r}: it becomes a filename, so a separator "
            f"or a leading dot lets a label write outside the store")
    store.mkdir(parents=True, exist_ok=True)
    snaps = load_index(store)
    if label in snaps:
        raise RecoverError(
            f"snapshot {label!r} already exists (taken {snaps[label].created}). "
            f"Overwriting it silently discards the state someone labelled, and "
            f"nothing downstream can tell that from the snapshot never having "
            f"been taken. Choose another label or drop this one explicitly")
    m = awshare.publish(root, store, name=label, seal=seal, key_path=key_path,
                        meta=dict(meta or {}))
    snap = Snapshot(label=label, created=m.created, digest=m.digest,
                    files=len(m.files), subject=root.name, meta=dict(meta or {}))
    snaps[label] = snap
    save_index(store, snaps)
    return snap


def list_snapshots(store: Path) -> List[Snapshot]:
    """Newest first."""
    return sorted(load_index(store).values(), key=lambda s: s.created, reverse=True)


def verify(store: Path, label: str, *, expect_key: Optional[str] = None) -> Dict[str, Any]:
    """Prove a snapshot is RESTORABLE by restoring it to a scratch directory.

    Not "does the archive exist" and not "is it the right size". Those pass for
    a snapshot of the wrong tree, a truncated one, and one taken of an empty
    directory. The only evidence that a backup works is a restore.
    """
    _require_awshare()
    snaps = load_index(store)
    if label not in snaps:
        raise RecoverError(f"no snapshot labelled {label!r} in {store}")
    manifest = store / f"{label}{awshare.MANIFEST_SUFFIX}"
    if not manifest.is_file():
        raise RecoverError(
            f"snapshot {label!r} is in the index but its manifest is missing at "
            f"{manifest}. The index is a claim; the archive is the backup")
    tmp = Path(tempfile.mkdtemp(prefix=f".awrecover-verify-{label}-"))
    try:
        r = awshare.fetch(manifest, tmp, expect_key=expect_key)
        return {"label": label, "restorable": True, "files": r["files"],
                "sealed": r["sealed"], "seal": r["seal"]}
    except awshare.ShareError as exc:
        raise RestoreFailedError(
            f"snapshot {label!r} is NOT restorable: {exc}") from exc
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def restore(store: Path, label: str, dest: Path, *,
            expect_key: Optional[str] = None, keep_replaced: bool = True) -> Dict[str, Any]:
    """Restore a snapshot over `dest`, atomically.

    Unpacks into a staging directory beside `dest`, verifies it, and only then
    swaps. A restore that copies half the files and fails has destroyed the
    working state AND not delivered the snapshot — strictly worse than refusing.
    """
    _require_awshare()
    snaps = load_index(store)
    if label not in snaps:
        raise RecoverError(f"no snapshot labelled {label!r} in {store}")
    manifest = store / f"{label}{awshare.MANIFEST_SUFFIX}"

    dest = dest.resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(dir=str(dest.parent),
                                    prefix=f".awrecover-{label}-"))
    replaced: Optional[Path] = None
    try:
        r = awshare.fetch(manifest, staging, expect_key=expect_key)
        if dest.exists():
            # Move the current tree ASIDE rather than deleting it. If the swap
            # fails halfway the old state still exists under a name someone can
            # find; deleting first makes the failure unrecoverable.
            replaced = dest.parent / f".awrecover-replaced-{label}-{os.getpid()}"
            os.replace(dest, replaced)
        os.replace(staging, dest)
        staging = None  # type: ignore[assignment]
    except awshare.ShareError as exc:
        raise RestoreFailedError(
            f"refusing to restore {label!r}: {exc}. Nothing was changed") from exc
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)

    out: Dict[str, Any] = {"label": label, "restored": str(dest),
                           "files": r["files"], "seal": r["seal"],
                           "replaced": None}
    if replaced is not None:
        if keep_replaced:
            out["replaced"] = str(replaced)
        else:
            shutil.rmtree(replaced, ignore_errors=True)
    return out


def drop(store: Path, label: str) -> None:
    """Remove a snapshot and its archive. Explicit, never implicit."""
    snaps = load_index(store)
    if label not in snaps:
        raise RecoverError(f"no snapshot labelled {label!r} in {store}")
    del snaps[label]
    save_index(store, snaps)
    for suffix in (awshare.MANIFEST_SUFFIX, awshare.ARCHIVE_SUFFIX):
        (store / f"{label}{suffix}").unlink(missing_ok=True)


def latest(store: Path) -> Optional[Snapshot]:
    snaps = list_snapshots(store)
    return snaps[0] if snaps else None
