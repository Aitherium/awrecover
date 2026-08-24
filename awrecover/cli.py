"""`awrecover` — snapshot a directory, and get it back.

    awrecover snapshot <dir> --store <dir> --label pre-finetune [--seal]
    awrecover list --store <dir>
    awrecover verify --store <dir> --label pre-finetune
    awrecover restore --store <dir> --label pre-finetune --dest <dir>
    awrecover drop --store <dir> --label pre-finetune
    awrecover --self-test

`verify` restores into a scratch directory rather than checking that a file of
about the right size exists. A backup nobody has restored is a hypothesis.

Exit 1 when a snapshot is checked and found unrestorable; exit 2 when it could
not be checked at all.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .store import (
    RecoverError,
    RestoreFailedError,
    drop,
    list_snapshots,
    restore,
    snapshot,
    verify,
)


def _cmd_snapshot(a) -> int:
    s = snapshot(Path(a.directory), Path(a.store), a.label, seal=a.seal,
                 key_path=Path(a.key_path) if a.key_path else None)
    print(f"snapshot {s.label}: {s.files} file(s) from {s.subject}")
    print(f"digest: {s.digest}")
    print("NOTE: taken, not proven. Run `awrecover verify --label "
          f"{s.label}` — a backup nobody has restored is a hypothesis.")
    return 0


def _cmd_list(a) -> int:
    snaps = list_snapshots(Path(a.store))
    if not snaps:
        print("no snapshots")
        return 0
    for s in snaps:
        print(f"{s.created}  {s.label:24} {s.files:5} file(s)  {s.subject}")
    return 0


def _cmd_verify(a) -> int:
    r = verify(Path(a.store), a.label, expect_key=a.key)
    print(f"{a.label}: restorable={r['restorable']} files={r['files']} "
          f"sealed={r['sealed']}")
    if r["seal"]:
        s = r["seal"]
        print(f"  seal: signature_ok={s['signature_ok']} "
              f"content_ok={s['content_ok']} key_trusted={s['key_trusted']}")
    return 0


def _cmd_restore(a) -> int:
    r = restore(Path(a.store), a.label, Path(a.dest), expect_key=a.key,
                keep_replaced=not a.discard_replaced)
    print(f"restored {r['label']} -> {r['restored']} ({r['files']} file(s))")
    if r["replaced"]:
        print(f"previous tree moved aside: {r['replaced']}")
        print("It is kept on purpose. Delete it once you are sure — a restore "
              "that deletes first cannot be undone if the swap fails.")
    return 0


def _cmd_drop(a) -> int:
    drop(Path(a.store), a.label)
    print(f"dropped {a.label}")
    return 0


def self_test() -> int:
    import shutil
    import tempfile
    ok = True

    def chk(label, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(f"  {'PASS' if good else 'FAIL'}  {label} -> {got!r} (want {want!r})")

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        work = d / "work"
        work.mkdir()
        (work / "adapter.bin").write_text("v1", encoding="utf-8")
        (work / "config.json").write_text('{"r":16}', encoding="utf-8")
        store = d / "snaps"

        s = snapshot(work, store, "pre-finetune")
        chk("snapshot records the file count", s.files, 2)
        chk("it appears in the listing",
            [x.label for x in list_snapshots(store)], ["pre-finetune"])

        # The rule: verification means RESTORING, not looking at the archive.
        chk("verify proves restorability by restoring",
            verify(store, "pre-finetune")["restorable"], True)

        # Simulate a fine-tune that made things worse.
        (work / "adapter.bin").write_text("v2-worse", encoding="utf-8")
        (work / "junk.tmp").write_text("debris", encoding="utf-8")
        r = restore(store, "pre-finetune", work)
        chk("restore returns the file count", r["files"], 2)
        chk("  the regression is undone",
            (work / "adapter.bin").read_text(encoding="utf-8"), "v1")
        chk("  and files added after the snapshot are gone",
            (work / "junk.tmp").exists(), False)
        chk("  the replaced tree is kept, not deleted",
            Path(r["replaced"]).exists(), True)
        shutil.rmtree(r["replaced"], ignore_errors=True)

        # A label that would escape the store must be refused: it becomes a
        # filename, and a separator or leading dot writes outside.
        for bad in ("../evil", "a/b", "", ".hidden"):
            try:
                snapshot(work, store, bad)
                chk(f"refuses label {bad!r}", "no raise", "raise")
            except RecoverError:
                chk(f"refuses label {bad!r}", "raise", "raise")

        # Re-using a label must refuse. Overwriting silently discards state
        # someone deliberately labelled.
        try:
            snapshot(work, store, "pre-finetune")
            chk("refuses to overwrite an existing label", "no raise", "raise")
        except RecoverError:
            chk("refuses to overwrite an existing label", "raise", "raise")

        # A snapshot whose ARCHIVE is gone must fail verification, not pass on
        # the strength of the index. The index is a claim; the archive is the
        # backup.
        import awshare
        (store / f"pre-finetune{awshare.ARCHIVE_SUFFIX}").unlink()
        try:
            verify(store, "pre-finetune")
            chk("a missing archive fails verification", "no raise", "raise")
        except RecoverError:
            chk("a missing archive fails verification", "raise", "raise")

        # ...and restoring it must change NOTHING.
        before = (work / "adapter.bin").read_text(encoding="utf-8")
        try:
            restore(store, "pre-finetune", work)
            chk("an unrestorable snapshot refuses", "no raise", "raise")
        except RecoverError:
            chk("an unrestorable snapshot refuses", "raise", "raise")
        chk("  and the working tree is untouched",
            (work / "adapter.bin").read_text(encoding="utf-8"), before)

        # Unknown label.
        try:
            restore(store, "never-taken", work)
            chk("refuses an unknown label", "no raise", "raise")
        except RecoverError:
            chk("refuses an unknown label", "raise", "raise")

    print("\nself-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def _passphrase() -> str:
    """Read the recovery passphrase WITHOUT it touching argv.

    There is deliberately no --passphrase flag. A secret on a command line goes
    into shell history and is readable in the process list by any other user on
    the box for as long as the command runs -- and the one moment this command
    is run is on a fresh machine someone else may also be on.
    """
    import getpass
    pw = os.environ.get("AWRECOVER_PASSPHRASE")
    if pw:
        return pw
    return getpass.getpass("recovery passphrase: ")


def _cmd_push(a) -> int:
    from .remote import push
    snap = push(Path(a.store), a.label, a.remote, _passphrase(), message=a.message)
    print(f"pushed {snap.label} ({snap.size} bytes, encrypted) -> {a.remote}")
    return 0


def _cmd_pull(a) -> int:
    from .remote import pull
    out = pull(a.remote, a.label, Path(a.store), _passphrase())
    print(f"pulled {a.label} -> {out}")
    print("decrypted OK. `awrecover restore` puts it back on disk.")
    return 0


def _cmd_remote_list(a) -> int:
    from .remote import remote_list
    labels = remote_list(a.remote)
    if not labels:
        # An empty remote is a real, reportable state -- not an error, and not
        # something to print as though snapshots were found.
        print("(remote holds no snapshots)")
        return 0
    for label in labels:
        print(label)
    return 0


def main(argv=None) -> int:
    # GENERATED doctor intercept (gen_aw_doctor.py) -- do not edit
    _dv = locals().get("argv")
    if (_dv if _dv is not None else __import__("sys").argv[1:])[:1] == ["doctor"]:
        from ._doctor import report
        return report()
    ap = argparse.ArgumentParser(prog="awrecover", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    s = sub.add_parser("snapshot")
    s.add_argument("directory")
    s.add_argument("--store", required=True)
    s.add_argument("--label", required=True)
    s.add_argument("--seal", action="store_true")
    s.add_argument("--key-path")
    s.set_defaults(fn=_cmd_snapshot)

    ls = sub.add_parser("list")
    ls.add_argument("--store", required=True)
    ls.set_defaults(fn=_cmd_list)

    v = sub.add_parser("verify")
    v.add_argument("--store", required=True)
    v.add_argument("--label", required=True)
    v.add_argument("--key")
    v.set_defaults(fn=_cmd_verify)

    r = sub.add_parser("restore")
    r.add_argument("--store", required=True)
    r.add_argument("--label", required=True)
    r.add_argument("--dest", required=True)
    r.add_argument("--key")
    r.add_argument("--discard-replaced", action="store_true")
    r.set_defaults(fn=_cmd_restore)

    ph = sub.add_parser("push", help="encrypt a snapshot and commit it to a git remote")
    ph.add_argument("--store", required=True)
    ph.add_argument("--label", required=True)
    ph.add_argument("--remote", required=True,
                    help="git URL you control (a private GitHub repo)")
    ph.add_argument("--message")
    ph.set_defaults(fn=_cmd_push)

    pl = sub.add_parser("pull", help="fetch and decrypt a snapshot from a git remote")
    pl.add_argument("--store", required=True)
    pl.add_argument("--label", required=True)
    pl.add_argument("--remote", required=True)
    pl.set_defaults(fn=_cmd_pull)

    rl = sub.add_parser("remote-list", help="labels present in a git remote")
    rl.add_argument("--remote", required=True)
    rl.set_defaults(fn=_cmd_remote_list)

    dp = sub.add_parser("drop")
    dp.add_argument("--store", required=True)
    dp.add_argument("--label", required=True)
    dp.set_defaults(fn=_cmd_drop)

    a = ap.parse_args(argv)
    if a.self_test:
        rc = self_test()
        # The remote half has its own arms (encryption, authenticity, refusal).
        # Folding them in here means one --self-test covers the whole package;
        # a second entry point nobody runs is how a gate goes quietly dead.
        from .remote import selftest as _remote_selftest
        rc2 = _remote_selftest()
        return rc or rc2
    if not getattr(a, "fn", None):
        ap.print_help()
        return 2
    try:
        return a.fn(a)
    except RestoreFailedError as exc:
        print(f"NOT RESTORABLE: {exc}", file=sys.stderr)
        return 1
    except RecoverError as exc:
        print(f"COULD NOT RUN: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
