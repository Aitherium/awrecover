"""awrecover — snapshot a directory, and get it back.

Extracted from AitherOS's backup/recovery client. The internal version drives a
service over HTTP; what generalises is smaller and useful on its own: take a
labelled snapshot, prove it restores, and put it back atomically.

    import awrecover
    from pathlib import Path

    awrecover.snapshot(Path("run"), Path(".snaps"), "pre-finetune")
    awrecover.verify(Path(".snaps"), "pre-finetune")     # RESTORES it
    awrecover.restore(Path(".snaps"), "pre-finetune", Path("run"))

Deliberately thin. A snapshot IS an `awshare` bundle, so archiving, digesting,
atomic writes and path containment are not reimplemented here. awrecover adds
only what awshare does not have: a label index, and a restore that either fully
lands or does not land at all.

Two rules it exists to enforce:

**A backup nobody has restored is a hypothesis.** `verify` restores into a
scratch directory and compares. The cheap check — "the archive exists and is
non-empty" — passes for a snapshot of the wrong directory, a truncated one, and
one taken of nothing.

**A half-restore is worse than no restore.** It destroys the working state AND
fails to deliver the snapshot. So a restore stages, verifies, then swaps, and
moves the previous tree aside instead of deleting it.
"""

from __future__ import annotations

from .store import (
    INDEX_VERSION,
    RecoverError,
    RestoreFailedError,
    Snapshot,
    drop,
    latest,
    list_snapshots,
    load_index,
    restore,
    snapshot,
    verify,
)

__version__ = "0.1.0"

__all__ = [
    "INDEX_VERSION",
    "RecoverError",
    "RestoreFailedError",
    "Snapshot",
    "drop",
    "latest",
    "list_snapshots",
    "load_index",
    "restore",
    "snapshot",
    "verify",
]
