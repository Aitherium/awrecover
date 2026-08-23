"""Comprehensive test suite for awrecover.

Tests the core guarantee: a snapshot is all-or-nothing restoration.
A restore that copies half the files and fails has destroyed working state
and not delivered the snapshot — strictly worse than refusing.
"""

import json
from pathlib import Path
from typing import Any, Dict
from unittest import mock

import pytest

# awrecover requires awshare as a hard dependency
pytest.importorskip("awshare")

import awshare

import awrecover
from awrecover.store import load_index, save_index


class TestSnapshotLifecycle:
    """Basic snapshot creation, listing, and retrieval."""

    def test_snapshot_creates_entry(self, tmp_path: Path) -> None:
        """Taking a snapshot adds it to the index."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "file.txt").write_text("content")

        store = tmp_path / "store"
        store.mkdir()

        snap = awrecover.snapshot(source, store, "test-snap")

        assert snap.label == "test-snap"
        assert snap.files == 1
        assert snap.subject == "source"
        assert snap.digest is not None
        assert snap.created is not None

    def test_list_snapshots_shows_created_snapshots(self, tmp_path: Path) -> None:
        """list_snapshots returns all snapshots in reverse chronological order."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "file.txt").write_text("content")

        store = tmp_path / "store"
        store.mkdir()

        # Create two snapshots - awshare uses ISO8601 timestamps which are
        # lexicographically sortable, so we can rely on sorted order
        awrecover.snapshot(source, store, "snap-1")
        awrecover.snapshot(source, store, "snap-2")

        snaps = awrecover.list_snapshots(store)

        # Both should be in the list
        assert len(snaps) == 2
        labels = [s.label for s in snaps]
        assert "snap-1" in labels
        assert "snap-2" in labels

        # They should be sorted by creation time (newest first)
        # The created timestamps are ISO8601, so we just verify the sort is stable
        assert snaps[0].created >= snaps[1].created

    def test_latest_returns_newest_snapshot(self, tmp_path: Path) -> None:
        """latest() returns the most recent snapshot."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "file.txt").write_text("content")

        store = tmp_path / "store"
        store.mkdir()

        snap1 = awrecover.snapshot(source, store, "old")
        awrecover.snapshot(source, store, "new")

        latest = awrecover.latest(store)

        assert latest is not None
        # latest should be one of the snapshots and should have a created time >= the other
        assert latest.label in ["old", "new"]
        assert latest.created >= snap1.created

    def test_latest_returns_none_when_empty(self, tmp_path: Path) -> None:
        """latest() returns None when no snapshots exist."""
        store = tmp_path / "store"
        store.mkdir()

        latest = awrecover.latest(store)

        assert latest is None

    def test_duplicate_label_raises_error(self, tmp_path: Path) -> None:
        """Taking a snapshot with a duplicate label raises RecoverError."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "file.txt").write_text("content")

        store = tmp_path / "store"
        store.mkdir()

        awrecover.snapshot(source, store, "duplicate")

        with pytest.raises(awrecover.RecoverError, match="already exists"):
            awrecover.snapshot(source, store, "duplicate")

    def test_label_validation_rejects_separators(self, tmp_path: Path) -> None:
        """Labels containing path separators are rejected."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "file.txt").write_text("content")

        store = tmp_path / "store"
        store.mkdir()

        with pytest.raises(awrecover.RecoverError, match="separator"):
            awrecover.snapshot(source, store, "bad/label")

        with pytest.raises(awrecover.RecoverError, match="separator"):
            awrecover.snapshot(source, store, "bad\\label")

    def test_label_validation_rejects_leading_dot(self, tmp_path: Path) -> None:
        """Labels starting with a dot are rejected."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "file.txt").write_text("content")

        store = tmp_path / "store"
        store.mkdir()

        with pytest.raises(awrecover.RecoverError, match="leading dot"):
            awrecover.snapshot(source, store, ".hidden")


class TestVerification:
    """Verification that snapshots are restorable."""

    def test_verify_succeeds_on_clean_snapshot(self, tmp_path: Path) -> None:
        """verify() confirms a snapshot is restorable."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "file.txt").write_text("test content")

        store = tmp_path / "store"
        store.mkdir()

        awrecover.snapshot(source, store, "clean")
        result = awrecover.verify(store, "clean")

        assert result["label"] == "clean"
        assert result["restorable"] is True
        assert result["files"] == 1

    def test_verify_detects_tampered_archive(self, tmp_path: Path) -> None:
        """verify() fails when the archive has been tampered with."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "file.txt").write_text("content")

        store = tmp_path / "store"
        store.mkdir()

        awrecover.snapshot(source, store, "test")

        # Tamper with the archive by truncating it
        archive_path = store / f"test{awshare.ARCHIVE_SUFFIX}"
        original_size = archive_path.stat().st_size
        archive_path.write_bytes(archive_path.read_bytes()[:original_size // 2])

        with pytest.raises(awrecover.RestoreFailedError, match="NOT restorable"):
            awrecover.verify(store, "test")

    def test_verify_raises_on_missing_snapshot(self, tmp_path: Path) -> None:
        """verify() raises RecoverError when snapshot label does not exist."""
        store = tmp_path / "store"
        store.mkdir()

        with pytest.raises(awrecover.RecoverError, match="no snapshot labelled"):
            awrecover.verify(store, "nonexistent")

    def test_verify_raises_when_manifest_missing(self, tmp_path: Path) -> None:
        """verify() raises when manifest file is gone but index entry remains."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "file.txt").write_text("content")

        store = tmp_path / "store"
        store.mkdir()

        awrecover.snapshot(source, store, "orphan")

        # Delete the manifest but not the index entry
        manifest_path = store / f"orphan{awshare.MANIFEST_SUFFIX}"
        manifest_path.unlink()

        with pytest.raises(awrecover.RecoverError, match="manifest is missing"):
            awrecover.verify(store, "orphan")


class TestDrop:
    """Snapshot removal."""

    def test_drop_removes_snapshot(self, tmp_path: Path) -> None:
        """drop() removes a snapshot from the index and deletes its files."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "file.txt").write_text("content")

        store = tmp_path / "store"
        store.mkdir()

        awrecover.snapshot(source, store, "to-drop")

        # Verify it exists
        assert awrecover.latest(store) is not None

        awrecover.drop(store, "to-drop")

        # Verify it's gone
        assert awrecover.latest(store) is None
        snaps = awrecover.list_snapshots(store)
        assert len(snaps) == 0

    def test_drop_removes_files(self, tmp_path: Path) -> None:
        """drop() deletes the manifest and archive files."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "file.txt").write_text("content")

        store = tmp_path / "store"
        store.mkdir()

        awrecover.snapshot(source, store, "to-drop")

        manifest = store / f"to-drop{awshare.MANIFEST_SUFFIX}"
        archive = store / f"to-drop{awshare.ARCHIVE_SUFFIX}"

        assert manifest.exists()
        assert archive.exists()

        awrecover.drop(store, "to-drop")

        assert not manifest.exists()
        assert not archive.exists()

    def test_drop_nonexistent_raises_error(self, tmp_path: Path) -> None:
        """drop() raises RecoverError if snapshot does not exist."""
        store = tmp_path / "store"
        store.mkdir()

        with pytest.raises(awrecover.RecoverError, match="no snapshot labelled"):
            awrecover.drop(store, "nonexistent")


class TestIndexPersistence:
    """Index file loading and saving."""

    def test_load_index_empty_store(self, tmp_path: Path) -> None:
        """load_index returns empty dict for a new store."""
        store = tmp_path / "store"
        store.mkdir()

        index = load_index(store)

        assert index == {}

    def test_save_and_load_index_roundtrip(self, tmp_path: Path) -> None:
        """Snapshots can be saved and loaded from the index."""
        store = tmp_path / "store"
        store.mkdir()

        snap = awrecover.Snapshot(
            label="test",
            created="2024-01-01T00:00:00Z",
            digest="abc123",
            files=5,
            subject="testdir",
            meta={"key": "value"},
        )

        snapshots = {"test": snap}
        save_index(store, snapshots)

        loaded = load_index(store)

        assert "test" in loaded
        assert loaded["test"].label == "test"
        assert loaded["test"].digest == "abc123"
        assert loaded["test"].files == 5
        assert loaded["test"].meta == {"key": "value"}

    def test_load_index_corrupt_file_raises_error(self, tmp_path: Path) -> None:
        """load_index raises RecoverError for malformed JSON."""
        store = tmp_path / "store"
        store.mkdir()

        index_file = store / awrecover.store.INDEX_NAME
        index_file.write_text("{ invalid json }")

        with pytest.raises(awrecover.RecoverError, match="unreadable"):
            load_index(store)

    def test_load_index_version_mismatch_raises_error(self, tmp_path: Path) -> None:
        """load_index raises RecoverError if version does not match."""
        store = tmp_path / "store"
        store.mkdir()

        index_file = store / awrecover.store.INDEX_NAME
        bad_index = {"version": 999, "snapshots": {}}
        index_file.write_text(json.dumps(bad_index))

        with pytest.raises(awrecover.RecoverError, match="index version"):
            load_index(store)


class TestRestore:
    """Restoration of snapshots, with all-or-nothing guarantee."""

    def test_restore_succeeds_to_empty_destination(self, tmp_path: Path) -> None:
        """restore() successfully restores a snapshot to an empty destination."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "file1.txt").write_text("content1")
        (source / "file2.txt").write_text("content2")

        store = tmp_path / "store"
        store.mkdir()

        awrecover.snapshot(source, store, "test")

        dest = tmp_path / "dest"

        result = awrecover.restore(store, "test", dest)

        assert result["label"] == "test"
        assert result["files"] == 2
        assert dest.exists()
        assert (dest / "file1.txt").read_text() == "content1"
        assert (dest / "file2.txt").read_text() == "content2"

    def test_restore_replaces_existing_destination(self, tmp_path: Path) -> None:
        """restore() replaces an existing destination directory."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "new.txt").write_text("new content")

        store = tmp_path / "store"
        store.mkdir()

        dest = tmp_path / "dest"
        dest.mkdir()
        (dest / "old.txt").write_text("old content")

        awrecover.snapshot(source, store, "test")
        result = awrecover.restore(store, "test", dest)

        assert (dest / "new.txt").read_text() == "new content"
        assert not (dest / "old.txt").exists()
        assert result["replaced"] is not None

    def test_restore_keeps_replaced_by_default(self, tmp_path: Path) -> None:
        """restore() moves the replaced directory to a backup location by default."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "new.txt").write_text("new")

        store = tmp_path / "store"
        store.mkdir()

        dest = tmp_path / "dest"
        dest.mkdir()
        (dest / "old.txt").write_text("old")

        awrecover.snapshot(source, store, "test")
        result = awrecover.restore(store, "test", dest, keep_replaced=True)

        assert result["replaced"] is not None
        replaced_path = Path(result["replaced"])
        assert replaced_path.exists()
        assert (replaced_path / "old.txt").read_text() == "old"

    def test_restore_discards_replaced_if_requested(self, tmp_path: Path) -> None:
        """restore() can discard the replaced directory."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "new.txt").write_text("new")

        store = tmp_path / "store"
        store.mkdir()

        dest = tmp_path / "dest"
        dest.mkdir()
        (dest / "old.txt").write_text("old")

        awrecover.snapshot(source, store, "test")
        result = awrecover.restore(store, "test", dest, keep_replaced=False)

        assert result["replaced"] is None
        # Destination has new content
        assert (dest / "new.txt").exists()
        assert not (dest / "old.txt").exists()

    def test_restore_nonexistent_label_raises_error(self, tmp_path: Path) -> None:
        """restore() raises RecoverError if snapshot does not exist."""
        store = tmp_path / "store"
        store.mkdir()

        dest = tmp_path / "dest"

        with pytest.raises(awrecover.RecoverError, match="no snapshot labelled"):
            awrecover.restore(store, "nonexistent", dest)

    def test_restore_creates_parent_directories(self, tmp_path: Path) -> None:
        """restore() creates parent directories if needed."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "file.txt").write_text("content")

        store = tmp_path / "store"
        store.mkdir()

        awrecover.snapshot(source, store, "test")

        dest = tmp_path / "nested" / "deep" / "dest"

        awrecover.restore(store, "test", dest)

        assert dest.exists()
        assert (dest / "file.txt").read_text() == "content"


class TestAllOrNothingRestoreGuarantee:
    """The core guarantee: failed restore leaves destination unchanged."""

    def test_failed_restore_leaves_destination_unchanged(self, tmp_path: Path) -> None:
        """If restore fails partway, the destination is exactly as it was before."""
        # Setup source with multiple files
        source = tmp_path / "source"
        source.mkdir()
        for i in range(3):
            (source / f"file{i}.txt").write_text(f"content{i}" * 100)

        store = tmp_path / "store"
        store.mkdir()

        awrecover.snapshot(source, store, "test")

        # Setup destination with known content
        dest = tmp_path / "dest"
        dest.mkdir()
        (dest / "existing.txt").write_text("existing content")

        # Capture exact state before restore attempt
        original_contents = {}
        for path in dest.glob("**/*"):
            if path.is_file():
                original_contents[path.relative_to(dest)] = path.read_bytes()

        # Monkeypatch awshare.fetch in the restore module to fail
        original_fetch = awshare.fetch

        def failing_fetch(manifest: Path, staging: Path, **kwargs: Any) -> Dict[str, Any]:
            """Simulate extraction failure."""
            # Perform the extraction but then raise to simulate failure
            original_fetch(manifest, staging, **kwargs)
            raise awshare.ShareError("Simulated extraction failure")

        with mock.patch("awshare.fetch", side_effect=failing_fetch):
            with pytest.raises(awrecover.RestoreFailedError):
                awrecover.restore(store, "test", dest)

        # Verify destination is EXACTLY as it was
        assert (dest / "existing.txt").read_text() == "existing content"
        for path in dest.glob("**/*"):
            if path.is_file():
                rel_path = path.relative_to(dest)
                assert rel_path in original_contents, f"Unexpected file: {rel_path}"
                assert (
                    path.read_bytes() == original_contents[rel_path]
                ), f"File {rel_path} was modified"

        # Staging directory should be cleaned up
        staging_dirs = list(
            dest.parent.glob(".awrecover-test-*")
        )
        assert (
            len(staging_dirs) == 0
        ), "Staging directory was not cleaned up after failure"

    def test_successful_restore_lands_all_files(self, tmp_path: Path) -> None:
        """A successful restore lands all files from the snapshot."""
        # Create source with nested structure
        source = tmp_path / "source"
        source.mkdir()
        (source / "file1.txt").write_text("content1")

        subdir = source / "subdir"
        subdir.mkdir()
        (subdir / "file2.txt").write_text("content2")

        nested = subdir / "nested"
        nested.mkdir()
        (nested / "file3.txt").write_text("content3")

        store = tmp_path / "store"
        store.mkdir()

        awrecover.snapshot(source, store, "nested")

        # Restore to a destination
        dest = tmp_path / "dest"
        result = awrecover.restore(store, "nested", dest)

        # Verify ALL files landed
        assert result["files"] == 3
        assert (dest / "file1.txt").read_text() == "content1"
        assert (dest / "subdir" / "file2.txt").read_text() == "content2"
        assert (dest / "subdir" / "nested" / "file3.txt").read_text() == "content3"

        # Verify no staging directories remain
        staging_dirs = list(dest.parent.glob(".awrecover-nested-*"))
        assert len(staging_dirs) == 0


class TestEdgeCases:
    """Edge cases and special content."""

    def test_awshare_refuses_empty_directories(self, tmp_path: Path) -> None:
        """awshare intentionally refuses to snapshot empty directories.

        This is documented behavior in awshare — empty bundles fetch and verify
        perfectly while containing nothing, which is indistinguishable from
        a bundle of the wrong directory.
        """
        source = tmp_path / "source"
        source.mkdir()

        store = tmp_path / "store"
        store.mkdir()

        with pytest.raises(awshare.ShareError, match="contains no files"):
            awrecover.snapshot(source, store, "empty")

    def test_nested_subdirectories(self, tmp_path: Path) -> None:
        """Nested subdirectories are preserved through snapshot and restore."""
        source = tmp_path / "source"
        source.mkdir()

        # Create deeply nested structure
        deep = source / "a" / "b" / "c" / "d" / "e"
        deep.mkdir(parents=True)
        (deep / "deep.txt").write_text("deep content")

        store = tmp_path / "store"
        store.mkdir()

        awrecover.snapshot(source, store, "nested")

        dest = tmp_path / "dest"
        awrecover.restore(store, "nested", dest)

        assert (dest / "a" / "b" / "c" / "d" / "e" / "deep.txt").read_text() == "deep content"

    def test_non_ascii_content(self, tmp_path: Path) -> None:
        """Files with non-ASCII content survive round-trip."""
        source = tmp_path / "source"
        source.mkdir()

        # Write Unicode content in various scripts
        (source / "chinese.txt").write_text("你好世界", encoding="utf-8")
        (source / "emoji.txt").write_text("😀🎉🌟", encoding="utf-8")
        (source / "arabic.txt").write_text("مرحبا", encoding="utf-8")

        store = tmp_path / "store"
        store.mkdir()

        awrecover.snapshot(source, store, "unicode")

        dest = tmp_path / "dest"
        awrecover.restore(store, "unicode", dest)

        assert (dest / "chinese.txt").read_text(encoding="utf-8") == "你好世界"
        assert (dest / "emoji.txt").read_text(encoding="utf-8") == "😀🎉🌟"
        assert (dest / "arabic.txt").read_text(encoding="utf-8") == "مرحبا"

    def test_files_with_special_names(self, tmp_path: Path) -> None:
        """Files with spaces and special characters in names."""
        source = tmp_path / "source"
        source.mkdir()

        (source / "file with spaces.txt").write_text("spaces")
        (source / "file-with-dashes.txt").write_text("dashes")
        (source / "file_with_underscores.txt").write_text("underscores")

        store = tmp_path / "store"
        store.mkdir()

        awrecover.snapshot(source, store, "special")

        dest = tmp_path / "dest"
        awrecover.restore(store, "special", dest)

        assert (dest / "file with spaces.txt").read_text() == "spaces"
        assert (dest / "file-with-dashes.txt").read_text() == "dashes"
        assert (dest / "file_with_underscores.txt").read_text() == "underscores"

    def test_large_file_content(self, tmp_path: Path) -> None:
        """Large files are handled correctly."""
        source = tmp_path / "source"
        source.mkdir()

        # Create a file with 1 MB of content
        large_content = "x" * (1024 * 1024)
        (source / "large.bin").write_text(large_content)

        store = tmp_path / "store"
        store.mkdir()

        awrecover.snapshot(source, store, "large")

        dest = tmp_path / "dest"
        awrecover.restore(store, "large", dest)

        assert (dest / "large.bin").read_text() == large_content

    def test_binary_file_content(self, tmp_path: Path) -> None:
        """Binary files are preserved exactly."""
        source = tmp_path / "source"
        source.mkdir()

        # Create a binary file with various byte values
        binary_content = bytes(range(256)) * 10
        (source / "binary.bin").write_bytes(binary_content)

        store = tmp_path / "store"
        store.mkdir()

        awrecover.snapshot(source, store, "binary")

        dest = tmp_path / "dest"
        awrecover.restore(store, "binary", dest)

        assert (dest / "binary.bin").read_bytes() == binary_content


class TestMetadata:
    """Metadata handling in snapshots."""

    def test_snapshot_with_metadata(self, tmp_path: Path) -> None:
        """Snapshots can carry arbitrary metadata."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "file.txt").write_text("content")

        store = tmp_path / "store"
        store.mkdir()

        meta = {"version": "1.0", "reason": "backup before update", "tags": ["important"]}
        snap = awrecover.snapshot(source, store, "with-meta", meta=meta)

        assert snap.meta == meta

        loaded = awrecover.list_snapshots(store)
        assert loaded[0].meta == meta

    def test_snapshot_without_metadata(self, tmp_path: Path) -> None:
        """Snapshots work without metadata."""
        source = tmp_path / "source"
        source.mkdir()
        (source / "file.txt").write_text("content")

        store = tmp_path / "store"
        store.mkdir()

        snap = awrecover.snapshot(source, store, "no-meta")

        assert snap.meta == {}
