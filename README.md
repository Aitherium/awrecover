# awrecover

Snapshot a directory, and get it back.

```bash
pip install awrecover

awrecover snapshot ./run --store .snaps --label pre-finetune
awrecover verify   --store .snaps --label pre-finetune      # RESTORES it
awrecover restore  --store .snaps --label pre-finetune --dest ./run
```

Deliberately thin. A snapshot *is* an [`awshare`](https://github.com/Aitherium/awshare)
bundle, so archiving, digesting, atomic writes and path containment are not
reimplemented here. awrecover adds only what awshare does not have: a label
index, and a restore that either fully lands or does not land at all.

## Two rules it exists to enforce

**A backup nobody has restored is a hypothesis.** `verify` restores into a
scratch directory and compares. The cheap check — "the archive exists and is
non-empty" — passes for a snapshot of the wrong directory, a truncated one, and
one taken of nothing.

**A half-restore is worse than no restore.** It destroys the working state *and*
fails to deliver the snapshot. So a restore stages beside the target, verifies,
then swaps; the window where neither is in place is one rename wide. The tree it
replaced is moved aside, not deleted — if the swap fails, the old state is still
under a name you can find.

Exit 1 when a snapshot is checked and found unrestorable; exit 2 when it could
not be checked at all.

## Licence

Apache-2.0.

---

## The aw family

Standalone tools that share one idea: **replace something you would otherwise have to _trust_ with something you can _check_.**

Each installs on its own, works offline, and needs no account.

| | instead of trusting | you check |
|---|---|---|
| [awnix](https://github.com/Aitherium/awnix) | that the box is what you left it as | an immutable image you built, with atomic rollback |
| [awnode](https://github.com/Aitherium/awnode) | a vendor's cloud with every prompt | a local gateway routing to backends you chose |
| [awgit](https://github.com/Aitherium/awgit) | that no one else is editing this file | a lease, refused at commit time if you do not hold it |
| [awgraph](https://github.com/Aitherium/awgraph) | that grep found everything | an AST + tree-sitter call graph an agent can traverse |
| [awseal](https://github.com/Aitherium/awseal) | that the artifact came from who you think | an Ed25519 seal — the key that verifies is not the key that forges |
| [awshare](https://github.com/Aitherium/awshare) | that the download is intact | content-addressed bundles, verified on fetch |
| [awrelay](https://github.com/Aitherium/awrelay) | a SaaS in the middle of your agents | findings, alerts and coordination over your own transport |
| [awm](https://github.com/Aitherium/awm) | that memory stayed in its lane | tenant:user:project scopes, so a write cannot cross a boundary |
| **awrecover** _(you are here)_ | that the restore worked | a restore that fully lands or does not land at all |

[**awnix**](https://github.com/Aitherium/awnix) is the ground floor — a bootable, immutable Linux base for machines where software writes software.
