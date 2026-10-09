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

INCREMENTAL SNAPSHOTS (0.2.0, 2026-10-03)

`snapshot(..., incremental=True)` stores the tree in awshare's content-addressed
object store (`<store>/objects/`) instead of a tar.gz: every file is kept once by
its sha256, so a second snapshot of a mostly unchanged tree costs only the files
that changed. Measured the day it landed: platform backups were full 35 GB copies
of mostly unchanged files, and deduplicating them freed 1.17 TiB. A tree snapshot
verifies and restores exactly like a bundle (every digest checked, restore staged
then swapped); `drop` collects objects no remaining snapshot references.
`remote push` still takes bundles.

OBJECTS SOMEWHERE ELSE, AND A SEAL OVER THE MANIFEST (0.3.0)

`snapshot(..., incremental=True, object_store=<store>)` keeps the objects in any
store with the `has`/`put`/`materialize` contract -- e.g. an
`awshare.RemoteObjectStore` over a storage service -- so the disk being backed up
is not the only place its backup lives. The manifest is pushed into that store
too, by its own digest, so losing the local manifest file does not lose the
snapshot. `verify`/`restore` must be handed the same store; a snapshot recorded
against one store is refused against another, never searched for locally.

`seal=True` on a tree snapshot signs the manifest's `{path: sha256}` map with
awseal (Ed25519), and the file modes in the seal's signed meta: a restore applies
each manifest entry's mode with chmod, so an unsigned mode is a setuid bit anyone
who can write the store could add. Every object is already verified by its digest on the way out;
the seal is what says WHO took the snapshot, so an object store that can be
written by someone else cannot swap in a different manifest. `verify`/`restore`
with `expect_key` refuse an unsealed tree, a signature that does not verify, a
manifest that no longer matches its seal, or a key that is not the expected one.

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
KIND_KEY = "awrecover.kind"  # in Snapshot.meta: "tree" for incremental, absent = bundle
OBJECTS_KEY = "awrecover.objects"  # where a tree's objects live, when not <store>/objects
MANIFEST_KEY = "awrecover.manifest_sha256"
SEAL_KEY = "awrecover.seal_sha256"
TREE_SEAL_SUFFIX = ".awtree.seal.json"
SEAL_MODES_KEY = "modes"  # in a tree seal's signed meta: {path: the mode restore applies}
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


def _is_tree(snap: Snapshot) -> bool:
    return (snap.meta or {}).get(KIND_KEY) == "tree"


def _tree_manifest_path(store: Path, label: str) -> Path:
    return store / f"{label}{awshare.TREE_MANIFEST_SUFFIX}"


def _tree_seal_path(store: Path, label: str) -> Path:
    return store / f"{label}{TREE_SEAL_SUFFIX}"


def _store_location(object_store: Any) -> str:
    loc = getattr(object_store, "location", None) or repr(object_store)
    return str(loc)


def _objects_for(snap: Snapshot, object_store: Any) -> Any:
    """The object store a tree snapshot must be read from, or a refusal."""
    recorded = (snap.meta or {}).get(OBJECTS_KEY)
    if recorded and object_store is None:
        raise RecoverError(
            f"snapshot {snap.label!r} keeps its objects in {recorded}; pass that "
            f"object store. Looking for them on the local disk would report a "
            f"backup that exists as missing")
    if object_store is not None and recorded != _store_location(object_store):
        raise RecoverError(
            f"snapshot {snap.label!r} was taken into {recorded or 'the local store'}, "
            f"not {_store_location(object_store)}")
    return object_store


def _tree_manifest(store: Path, snap: Snapshot, object_store: Any) -> Dict[str, Any]:
    """The tree manifest: the local file, else (for a pooled snapshot) the copy in
    the object store, checked against the digest the index recorded."""
    mp = _tree_manifest_path(store, snap.label)
    if mp.is_file():
        if awshare.digest_file(mp) != snap.digest:
            raise RestoreFailedError(
                f"manifest {mp} does not match the digest recorded for {snap.label!r}")
        return awshare.load_tree_manifest(mp)
    want = (snap.meta or {}).get(MANIFEST_KEY)
    if object_store is None or not want:
        raise RecoverError(f"snapshot {snap.label!r} is in the index but its manifest is "
                           f"missing at {mp}. The index is a claim; the manifest is the "
                           f"backup")
    data = object_store.get_bytes(str(want))
    if want != snap.digest:
        raise RestoreFailedError(f"the pooled manifest of {snap.label!r} is not the one "
                                 f"the index recorded")
    awshare.atomic_write(mp, data)
    return awshare.load_tree_manifest(mp)


def _tree_modes(manifest: Dict[str, Any]) -> Dict[str, int]:
    """{path: mode} exactly as awshare.restore_tree applies it -- what a seal signs."""
    return {rel: int(ent.get("mode") or 0o644)
            for rel, ent in dict(manifest.get("files") or {}).items()}


def _check_tree_seal(store: Path, snap: Snapshot, manifest: Dict[str, Any],
                     object_store: Any, expect_key: Optional[str]) -> Optional[Dict[str, Any]]:
    """Verify a sealed tree's manifest against its seal. None when unsealed and no key
    was asked for; raises when a key was asked for and the answer is not yes."""
    sp = _tree_seal_path(store, snap.label)
    seal_sha = (snap.meta or {}).get(SEAL_KEY)
    raw: Optional[bytes] = None
    if sp.is_file():
        raw = sp.read_bytes()
    elif seal_sha and object_store is not None:
        raw = object_store.get_bytes(str(seal_sha))
    if raw is None:
        if seal_sha:
            raise RestoreFailedError(f"snapshot {snap.label!r} was sealed and its seal "
                                     f"is missing")
        if expect_key is not None:
            raise RestoreFailedError(
                f"snapshot {snap.label!r} is unsealed; a key was given, and unsealed "
                f"is not the same as verified")
        return None
    if seal_sha and awshare.digest_bytes(raw) != seal_sha:
        raise RestoreFailedError(f"the seal of {snap.label!r} is not the one recorded")
    try:
        import awseal
    except ImportError as exc:
        raise RecoverError("this snapshot is sealed and `awseal` is not installed, so "
                           "its seal cannot be checked") from exc
    import json as _json
    try:
        seal = awseal.from_dict(_json.loads(raw.decode("utf-8")), where=str(sp))
    except ValueError as exc:
        raise RestoreFailedError(f"the seal of {snap.label!r} is unreadable: {exc}") from exc
    files = {rel: str(ent["sha256"])
             for rel, ent in dict(manifest.get("files") or {}).items()}
    res = awseal.verify_files(seal, files, expect_key=expect_key)
    sealed_modes = (seal.meta or {}).get(SEAL_MODES_KEY)
    modes = _tree_modes(manifest)
    res["modes_ok"] = (isinstance(sealed_modes, dict)
                       and {str(k): v for k, v in sealed_modes.items()} == modes)
    if not res["modes_ok"]:
        res["ok"] = False
    if not res["ok"]:
        raise RestoreFailedError(
            f"snapshot {snap.label!r} fails its seal: signature_ok={res['signature_ok']} "
            f"content_ok={res['content_ok']} key_trusted={res['key_trusted']} "
            f"modes_ok={res['modes_ok']} diff={res['diff']}")
    return res


def _latest_tree(store: Path, snaps: Dict[str, Snapshot]) -> Optional[Dict[str, Any]]:
    trees = sorted((s for s in snaps.values() if _is_tree(s)), key=lambda s: s.created)
    for s in reversed(trees):
        mp = _tree_manifest_path(store, s.label)
        if mp.is_file():
            return awshare.load_tree_manifest(mp)
    return None


def snapshot(root: Path, store: Path, label: str, *, seal: bool = False,
             key_path: Optional[Path] = None,
             meta: Optional[Dict[str, Any]] = None,
             incremental: bool = False,
             object_store: Any = None) -> Snapshot:
    """Take a labelled snapshot of `root` into `store`.

    `incremental=True` stores it in the shared object store: only files whose
    bytes the store does not already hold take space (see the module docstring).
    `object_store` keeps those objects elsewhere; `seal` signs the tree manifest.
    """
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
    if object_store is not None and not incremental:
        raise RecoverError("an object store holds tree snapshots: pass incremental=True")
    if incremental:
        from datetime import datetime, timezone
        if seal:
            try:
                import awseal  # checked BEFORE anything is stored
            except ImportError as exc:
                raise RecoverError("seal=True needs the `awseal` package; refusing to "
                                   "take a snapshot that claims a seal it cannot carry"
                                   ) from exc
            awseal.load_private_key(key_path)  # no key = refuse now, not half-way
        tm = awshare.snapshot_tree(root, store, label, previous=_latest_tree(store, snaps),
                                   meta=dict(meta or {}), object_store=object_store)
        mpath = _tree_manifest_path(store, label)
        tree_meta = dict(meta or {})
        tree_meta.update({KIND_KEY: "tree", "new_bytes": tm["new_bytes"],
                          "new_objects": tm["new_objects"],
                          "total_bytes": tm["total_bytes"]})
        if seal:
            files = {rel: str(ent["sha256"]) for rel, ent in tm["files"].items()}
            if not files:
                raise RecoverError(f"{root} holds no files; refusing to seal nothing")
            sealed = awseal.sign_files(files, key_path=key_path, subject=root.name,
                                       meta={"label": label,
                                             SEAL_MODES_KEY: _tree_modes(tm)})
            raw = json.dumps(sealed.to_dict(), indent=2, sort_keys=True).encode("utf-8")
            awshare.atomic_write(_tree_seal_path(store, label), raw)
            tree_meta[SEAL_KEY] = awshare.digest_bytes(raw)
            if object_store is not None:
                object_store.put_bytes(raw)
        if object_store is not None:
            tree_meta[OBJECTS_KEY] = _store_location(object_store)
            tree_meta[MANIFEST_KEY], _ = object_store.put_bytes(mpath.read_bytes())
        snap = Snapshot(label=label, created=datetime.now(timezone.utc).isoformat(),
                        digest=awshare.digest_file(mpath),
                        files=len(tm["files"]), subject=root.name, meta=tree_meta)
        snaps[label] = snap
        save_index(store, snaps)
        return snap
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


def verify(store: Path, label: str, *, expect_key: Optional[str] = None,
           object_store: Any = None) -> Dict[str, Any]:
    """Prove a snapshot is RESTORABLE by restoring it to a scratch directory.

    Not "does the archive exist" and not "is it the right size". Those pass for
    a snapshot of the wrong tree, a truncated one, and one taken of an empty
    directory. The only evidence that a backup works is a restore.
    """
    _require_awshare()
    snaps = load_index(store)
    if label not in snaps:
        raise RecoverError(f"no snapshot labelled {label!r} in {store}")
    if _is_tree(snaps[label]):
        snap = snaps[label]
        objs = _objects_for(snap, object_store)
        tmp = Path(tempfile.mkdtemp(prefix=f".awrecover-verify-{label}-"))
        try:
            tm = _tree_manifest(store, snap, objs)
            sealres = _check_tree_seal(store, snap, tm, objs, expect_key)
            r = awshare.restore_tree(tm, store, tmp, object_store=objs)
            return {"label": label, "restorable": True, "files": r["files"],
                    "sealed": sealres is not None, "seal": sealres}
        except awshare.ShareError as exc:
            raise RestoreFailedError(f"snapshot {label!r} is NOT restorable: {exc}") from exc
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
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
            expect_key: Optional[str] = None, keep_replaced: bool = True,
            object_store: Any = None) -> Dict[str, Any]:
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
    objs = _objects_for(snaps[label], object_store) if _is_tree(snaps[label]) else None
    tm: Optional[Dict[str, Any]] = None
    sealres: Optional[Dict[str, Any]] = None
    if _is_tree(snaps[label]):
        try:
            # Judged BEFORE the staging dir exists: a refused seal changes nothing.
            tm = _tree_manifest(store, snaps[label], objs)
            sealres = _check_tree_seal(store, snaps[label], tm, objs, expect_key)
        except awshare.ShareError as exc:
            raise RestoreFailedError(
                f"refusing to restore {label!r}: {exc}. Nothing was changed") from exc

    dest = dest.resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(dir=str(dest.parent),
                                    prefix=f".awrecover-{label}-"))
    replaced: Optional[Path] = None
    try:
        if tm is not None:
            r = dict(awshare.restore_tree(tm, store, staging, object_store=objs),
                     seal=sealres)
        else:
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
    """Remove a snapshot and its archive. Explicit, never implicit.

    A snapshot whose objects live in an object store loses its index row, its
    manifest and its seal here; its objects stay in that store, which other
    snapshots -- on other machines -- may share and this one cannot see."""
    snaps = load_index(store)
    if label not in snaps:
        raise RecoverError(f"no snapshot labelled {label!r} in {store}")
    was_tree = _is_tree(snaps[label])
    pooled = bool((snaps[label].meta or {}).get(OBJECTS_KEY))
    del snaps[label]
    save_index(store, snaps)
    _tree_seal_path(store, label).unlink(missing_ok=True)
    if was_tree and pooled:
        _tree_manifest_path(store, label).unlink(missing_ok=True)
        return
    if was_tree:
        # Objects shared with other snapshots stay; only what this one alone held goes.
        awshare.dedupe.drop_tree(store, label)
        return
    for suffix in (awshare.MANIFEST_SUFFIX, awshare.ARCHIVE_SUFFIX):
        (store / f"{label}{suffix}").unlink(missing_ok=True)


def latest(store: Path) -> Optional[Snapshot]:
    snaps = list_snapshots(store)
    return snaps[0] if snaps else None


def history(store: Path, path: str) -> List[Dict[str, Any]]:
    """Every incremental snapshot holding `path`, oldest first, marking where it changed.

    Answers "when did this file change, and which snapshot has the version I want"
    from the manifests alone -- nothing is restored to find out."""
    _require_awshare()
    rows: List[Dict[str, Any]] = []
    prev = None
    for s in sorted((s for s in load_index(store).values() if _is_tree(s)),
                    key=lambda s: s.created):
        mp = _tree_manifest_path(store, s.label)
        if not mp.is_file():
            continue
        ent = (awshare.load_tree_manifest(mp).get("files") or {}).get(path)
        if ent is None:
            continue
        rows.append({"label": s.label, "created": s.created, "sha256": ent["sha256"],
                     "size": ent["size"], "changed": ent["sha256"] != prev})
        prev = ent["sha256"]
    return rows


def find(store: Path, pattern: str) -> List[Dict[str, Any]]:
    """Paths matching the glob `pattern` across every incremental snapshot."""
    import fnmatch
    _require_awshare()
    out: List[Dict[str, Any]] = []
    for s in sorted((s for s in load_index(store).values() if _is_tree(s)),
                    key=lambda s: s.created):
        mp = _tree_manifest_path(store, s.label)
        if not mp.is_file():
            continue
        for rel, ent in sorted((awshare.load_tree_manifest(mp).get("files") or {}).items()):
            if fnmatch.fnmatch(rel, pattern):
                out.append({"label": s.label, "path": rel, "size": ent["size"],
                            "sha256": ent["sha256"]})
    return out
