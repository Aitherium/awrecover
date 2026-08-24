"""Push a snapshot to a git remote you control, encrypted, and get it back.

awrecover's local half answers "can I restore this tree". This half answers the
question a dead machine asks: **the disk is gone -- where is the snapshot?**

The destination is an ordinary git repository the owner controls (a private
GitHub repo is the intended one). That choice is deliberate: it is somewhere the
owner already has, already authenticates to, and that survives this platform
being down -- which is the whole point of a recovery path. A backup that can
only be fetched from the thing that just died is not a backup.

WHY THE ENCRYPTION IS NOT OPTIONAL, AND NOT `awseal`

`awseal` SIGNS. It answers "did this key produce these bytes, and do the bytes
still match" -- integrity and authenticity. It does not answer "can the person
holding these bytes read them", and `awseal.keys` explicitly serialises with
`NoEncryption()`. A sealed bundle pushed to a git host is *plaintext with a
signature on it*.

That distinction is the entire safety of this module. A workspace snapshot
carries the directory, sessions, knowledge and secrets. Pushing it to a hosting
provider unencrypted -- even a private repo -- puts all of it on someone else's
disk, in a place designed to be cloned. So:

  * every artifact this module writes to a remote is AES-256-GCM sealed,
  * the envelope is checked for its magic before any git add, and
  * there is NO plaintext fallback. If encryption cannot be performed the push
    FAILS. A "we could not encrypt so we pushed it anyway" branch is the one
    behaviour that would make this module worse than having no module.

WHERE THE KEY LIVES, AND WHY NOT IN THE VAULT

The key is derived from a passphrase the OWNER holds (scrypt), never stored
beside the ciphertext. It is deliberately not fetched from the platform vault at
restore time: the scenario this exists for is "the platform is down", so a
recovery path that must call the platform to decrypt is circular. GitHub plus a
passphrase is sufficient to rebuild a workspace on any laptop, VM, WSL2 or cloud
box, with nothing of ours reachable.

The cost is real and is the correct trade: **lose the passphrase and the backup
is gone.** That is a property of encryption, not a defect, and it is stated at
the point of use rather than discovered later.

EXIT DISCIPLINE

Callers get exceptions; the CLI maps them. `RemoteError` means it failed.
Anything this module cannot judge it raises rather than returning a cheerful
empty result -- a recovery tool that reports success on silence is the failure
mode it exists to prevent.
"""

from __future__ import annotations

import os
import re
import secrets
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .store import RecoverError

#: Envelope magic. Version is IN the magic so a future format change cannot be
#: silently misread as this one -- a decryptor that guesses at layout produces
#: garbage plaintext rather than an error.
MAGIC = b"AWRECOVER-ENC1\n"

#: scrypt cost. n=2**15 keeps an interactive derive well under a second on the
#: kind of laptop this is meant to be recovered onto, while making an offline
#: guess against a stolen repo expensive.
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1

SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32

ARCHIVE_SUFFIX = ".tar.gz"
MANIFEST_SUFFIX = ".awshare.json"
ENC_SUFFIX = ".awrecover.enc"

#: The index entry, carried INSIDE the artifact.
#:
#: A snapshot is not one file. It is the archive, the awshare manifest beside it,
#: and awrecover's own index row. Pushing only the archive produces a remote that
#: looks complete and cannot be restored from -- the failure lands on a fresh
#: machine, at recovery time, which is the worst possible moment to discover it.
#: Measured while writing this module: the first version did exactly that and the
#: end-to-end test refused with "cannot read manifest".
SNAP_NAME = "snapshot.json"

#: Where encrypted snapshots live inside the remote repo. A fixed subdirectory
#: so a recovery repo can also hold a README explaining what it is -- a bare
#: directory of opaque blobs is indistinguishable from junk to whoever inherits
#: the account.
REMOTE_DIR = "snapshots"


class RemoteError(RecoverError):
    """A remote push or pull failed."""


class NotEncryptedError(RemoteError):
    """Refused to publish bytes that are not sealed."""


@dataclass
class RemoteSnapshot:
    label: str
    size: int


def _require_crypto():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RemoteError(
            "encryption needs the `cryptography` package. Refusing to push an "
            "UNENCRYPTED workspace snapshot to a remote under a request to "
            "protect it -- that is a silent downgrade of the one property this "
            "module exists to provide. Install it: pip install cryptography"
        ) from exc
    return AESGCM, Scrypt


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """scrypt(passphrase, salt) -> 32 bytes."""
    if not passphrase:
        raise RemoteError(
            "empty passphrase. An empty passphrase derives a key an attacker "
            "derives just as easily, which is encryption in shape only"
        )
    _, Scrypt = _require_crypto()
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def is_encrypted(blob: bytes) -> bool:
    """True only for an envelope this module produced."""
    return blob[: len(MAGIC)] == MAGIC


def encrypt(plaintext: bytes, passphrase: str) -> bytes:
    """MAGIC | salt | nonce | AES-256-GCM(plaintext)."""
    AESGCM, _ = _require_crypto()
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = derive_key(passphrase, salt)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return MAGIC + salt + nonce + ct


def decrypt(blob: bytes, passphrase: str) -> bytes:
    """Inverse of `encrypt`. Wrong passphrase raises rather than returning junk."""
    if not is_encrypted(blob):
        raise NotEncryptedError(
            "this artifact carries no awrecover envelope. Refusing to treat it "
            "as a snapshot: it was written by something else, or by a version "
            "whose layout this decryptor does not know"
        )
    AESGCM, _ = _require_crypto()
    body = blob[len(MAGIC):]
    if len(body) < SALT_LEN + NONCE_LEN + 16:
        raise RemoteError("envelope is truncated -- the transfer did not complete")
    salt = body[:SALT_LEN]
    nonce = body[SALT_LEN:SALT_LEN + NONCE_LEN]
    ct = body[SALT_LEN + NONCE_LEN:]
    key = derive_key(passphrase, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception as exc:
        raise RemoteError(
            "could not decrypt: wrong passphrase, or the artifact was modified "
            "in the remote. GCM cannot tell those apart on purpose -- both mean "
            "these bytes are not the snapshot you took"
        ) from exc


def seal_roundtrip(plaintext: bytes, passphrase: str) -> bytes:
    """Encrypt, then immediately decrypt and compare, before anything is shipped.

    awrecover's founding rule is that a backup nobody has restored is a
    hypothesis. The same applies one layer down: an encrypt whose output nobody
    has decrypted is a hypothesis about a key. Doing it here costs one in-memory
    pass and converts "the push succeeded" into "the push succeeded AND the
    bytes come back", which are otherwise indistinguishable until the day the
    machine is already gone.
    """
    blob = encrypt(plaintext, passphrase)
    if not is_encrypted(blob):  # pragma: no cover - defensive
        raise NotEncryptedError("encrypt() produced no envelope")
    if decrypt(blob, passphrase) != plaintext:  # pragma: no cover - defensive
        raise RemoteError("encrypt/decrypt round-trip did not reproduce the input")
    return blob


def _git(args: List[str], cwd: Path, *, allow_fail: bool = False) -> str:
    proc = subprocess.run(
        ["git"] + args, cwd=str(cwd),
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if proc.returncode != 0 and not allow_fail:
        raise RemoteError(
            f"git {' '.join(args)} failed ({proc.returncode}): "
            f"{(proc.stderr or proc.stdout or '').strip()[:400]}"
        )
    return proc.stdout or ""


def _redact(url: str) -> str:
    """Never echo an embedded token back into a log or a traceback."""
    return re.sub(r"//[^/@]*@", "//<redacted>@", url)


def _clone(remote: str, into: Path) -> Path:
    work = into / "repo"
    out = subprocess.run(
        ["git", "clone", "--depth", "1", remote, str(work)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if out.returncode != 0:
        err = (out.stderr or "").strip()[:400]
        raise RemoteError(f"could not clone {_redact(remote)}: {_redact(err)}")
    return work


def _pack(store: Path, label: str) -> bytes:
    """archive + manifest + index row -> one tar, so a pull is self-sufficient."""
    import io
    import json
    import tarfile
    from .store import load_index

    snaps = load_index(store)
    if label not in snaps:
        raise RemoteError(
            f"{label!r} is not in the index at {store}. The index row carries the "
            f"digest and file count a restore checks against"
        )

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name in (f"{label}{ARCHIVE_SUFFIX}", f"{label}{MANIFEST_SUFFIX}"):
            tf.add(store / name, arcname=name)
        row = json.dumps(snaps[label].to_dict(), indent=2).encode("utf-8")
        ti = tarfile.TarInfo(SNAP_NAME)
        ti.size = len(row)
        tf.addfile(ti, io.BytesIO(row))
    return buf.getvalue()


def _unpack(plaintext: bytes, dest_store: Path, label: str) -> None:
    """Inverse of `_pack`, and it also rebuilds the index row.

    Rebuilding the row is what makes a recovery need no local state at all:
    boot, pull, restore. Without it the archive lands and `restore` reports an
    unknown label, which reads as a corrupt backup rather than a missing index.
    """
    import io
    import json
    import tarfile
    from .store import Snapshot, load_index, save_index

    dest_store.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r:gz") as tf:
        members = tf.getnames()
        for required in (f"{label}{ARCHIVE_SUFFIX}", f"{label}{MANIFEST_SUFFIX}"):
            if required not in members:
                raise RemoteError(
                    f"artifact is missing {required} -- it was written by an "
                    f"older push that did not carry the whole bundle"
                )
        for m in tf.getmembers():
            # Containment: a member name is attacker-influenceable in the general
            # case, and this unpacks into a directory the caller named.
            if m.name != os.path.basename(m.name) or m.name.startswith("."):
                raise RemoteError(f"refusing member with a path component: {m.name!r}")
            if not m.isfile():
                continue
            data = tf.extractfile(m).read()
            if m.name == SNAP_NAME:
                snaps = load_index(dest_store)
                snaps[label] = Snapshot(**json.loads(data.decode("utf-8")))
                save_index(dest_store, snaps)
                continue
            out = dest_store / m.name
            tmp = out.with_name(out.name + ".part")
            tmp.write_bytes(data)
            os.replace(tmp, out)


def push(store: Path, label: str, remote: str, passphrase: str,
         *, message: Optional[str] = None) -> RemoteSnapshot:
    """Encrypt snapshot `label` from `store` and commit it to `remote`."""
    store = Path(store)
    archive = store / f"{label}{ARCHIVE_SUFFIX}"
    manifest = store / f"{label}{MANIFEST_SUFFIX}"
    if not archive.is_file():
        raise RemoteError(
            f"no local snapshot {label!r} in {store}. Take one first -- pushing "
            f"a snapshot that was never taken would create an empty recovery "
            f"point that reads as a real one"
        )
    if not manifest.is_file():
        raise RemoteError(
            f"snapshot {label!r} has an archive but no manifest "
            f"({manifest.name}). Refusing to push half a bundle: it would restore "
            f"nowhere, and only on the machine doing the recovery"
        )

    plaintext = _pack(store, label)
    blob = seal_roundtrip(plaintext, passphrase)

    with tempfile.TemporaryDirectory() as td:
        work = _clone(remote, Path(td))
        dest_dir = work / REMOTE_DIR
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / f"{label}{ENC_SUFFIX}"

        # Belt and braces: assert on the BYTES about to be added, not on the
        # variable we think holds them.
        dest.write_bytes(blob)
        if not is_encrypted(dest.read_bytes()):  # pragma: no cover - defensive
            raise NotEncryptedError(
                "refusing to commit: the staged artifact carries no envelope"
            )

        _git(["add", "--", f"{REMOTE_DIR}/{label}{ENC_SUFFIX}"], work)
        status = _git(["status", "--porcelain"], work).strip()
        if not status:
            return RemoteSnapshot(label=label, size=len(blob))
        _git(["-c", "user.email=awrecover@aitherium.com",
              "-c", "user.name=awrecover",
              "commit", "-m", message or f"awrecover: snapshot {label}"], work)
        _git(["push"], work)

    return RemoteSnapshot(label=label, size=len(blob))


def pull(remote: str, label: str, dest_store: Path, passphrase: str) -> Path:
    """Fetch and decrypt `label` from `remote` into `dest_store`. Returns the archive."""
    dest_store = Path(dest_store)
    dest_store.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        work = _clone(remote, Path(td))
        src = work / REMOTE_DIR / f"{label}{ENC_SUFFIX}"
        if not src.is_file():
            have = sorted(
                p.name[: -len(ENC_SUFFIX)]
                for p in (work / REMOTE_DIR).glob(f"*{ENC_SUFFIX}")
            ) if (work / REMOTE_DIR).is_dir() else []
            raise RemoteError(
                f"remote has no snapshot {label!r}. It holds: "
                f"{', '.join(have) if have else '(none)'}"
            )
        plaintext = decrypt(src.read_bytes(), passphrase)
        _unpack(plaintext, dest_store, label)
    return dest_store / f"{label}{ARCHIVE_SUFFIX}"


def remote_list(remote: str) -> List[str]:
    """Labels present in the remote. Empty list means empty remote, not failure."""
    with tempfile.TemporaryDirectory() as td:
        work = _clone(remote, Path(td))
        d = work / REMOTE_DIR
        if not d.is_dir():
            return []
        return sorted(p.name[: -len(ENC_SUFFIX)] for p in d.glob(f"*{ENC_SUFFIX}"))


def selftest() -> int:
    """Prove each guarantee can still FAIL. Returns 0 pass, 1 fail."""
    failures: List[str] = []
    pw = "correct horse battery staple"
    data = b"workspace bytes " * 1000

    try:
        blob = seal_roundtrip(data, pw)
    except RemoteError as exc:
        print(f"selftest: cannot run: {exc}")
        return 2

    if not is_encrypted(blob):
        failures.append("envelope magic missing")
    if data in blob:
        failures.append(
            "PLAINTEXT APPEARS IN CIPHERTEXT -- the encryption is not encrypting"
        )
    if decrypt(blob, pw) != data:
        failures.append("round-trip did not reproduce input")

    # wrong passphrase must RAISE, never return junk
    try:
        decrypt(blob, pw + "x")
        failures.append("a wrong passphrase did not raise")
    except RemoteError:
        pass

    # a tampered ciphertext must RAISE (GCM authenticity)
    bad = bytearray(blob)
    bad[-1] ^= 0x01
    try:
        decrypt(bytes(bad), pw)
        failures.append("a MODIFIED artifact decrypted -- authenticity is not checked")
    except RemoteError:
        pass

    # unenveloped input must be refused rather than guessed at
    try:
        decrypt(b"just a tarball", pw)
        failures.append("unenveloped bytes were accepted as a snapshot")
    except NotEncryptedError:
        pass

    # an empty passphrase must be refused
    try:
        encrypt(data, "")
        failures.append("an empty passphrase was accepted")
    except RemoteError:
        pass

    # two encryptions of one input must differ (fresh salt+nonce), or a reader
    # of the remote learns which snapshots are identical
    if encrypt(data, pw)[: len(MAGIC) + SALT_LEN] == blob[: len(MAGIC) + SALT_LEN]:
        failures.append("salt is not fresh per encryption")

    if _redact("https://user:tok@github.com/x/y.git") != "https://<redacted>@github.com/x/y.git":
        failures.append("token redaction does not redact")

    if failures:
        for f in failures:
            print(f"selftest FAIL: {f}")
        return 1
    print("selftest: PASS (8 arms -- encryption, authenticity, refusal, redaction)")
    return 0
