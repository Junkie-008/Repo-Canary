import hashlib
from pathlib import Path

from threat_intel import ThreatIntel


def test_matching_hash_returns_label(tmp_path: Path):
    sample = tmp_path / "sample.txt"
    sample.write_text("known payload", encoding="utf-8")
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()

    feed = tmp_path / "known_hashes.txt"
    feed.write_text(
        f"# comment\n{digest},test-ransomware\n{'b' * 64}\n",
        encoding="utf-8",
    )

    intel = ThreatIntel(feed)
    assert intel.load() == 2

    result = intel.check(str(sample))

    assert result.sha256 == digest
    assert result.label == "test-ransomware"
    assert result.matched is True


def test_unknown_hash_is_clean(tmp_path: Path):
    sample = tmp_path / "clean.txt"
    sample.write_text("clean", encoding="utf-8")

    feed = tmp_path / "known_hashes.txt"
    feed.write_text(f"{'a' * 64},other\n", encoding="utf-8")

    intel = ThreatIntel(feed)
    intel.load()

    result = intel.check(str(sample))

    assert result.sha256 is not None
    assert result.label is None
    assert result.matched is False


def test_invalid_lines_are_ignored(tmp_path: Path):
    feed = tmp_path / "known_hashes.txt"
    feed.write_text(
        "\n".join(
            [
                "",
                "# comment",
                "not-a-hash,label",
                "a" * 63,
                "f" * 64,
            ]
        ),
        encoding="utf-8",
    )

    intel = ThreatIntel(feed)
    assert intel.load() == 1
    assert intel.entries()[0][0] == "f" * 64


def test_missing_feed_is_empty(tmp_path: Path):
    intel = ThreatIntel(tmp_path / "absent.txt")
    assert intel.load() == 0
    assert intel.entries() == []


def test_size_limit_is_enforced(tmp_path: Path):
    sample = tmp_path / "large.bin"
    sample.write_bytes(b"x" * 2048)

    intel = ThreatIntel(None, max_bytes=1024)
    result = intel.check(str(sample))

    assert result.sha256 is None
    assert "limit" in result.error


def test_cache_avoids_rehashing(tmp_path: Path, monkeypatch):
    sample = tmp_path / "sample.txt"
    sample.write_text("cached", encoding="utf-8")

    intel = ThreatIntel(None)
    calls = {"count": 0}
    original = ThreatIntel._hash_file

    def counting(path):
        calls["count"] += 1
        return original(path)

    monkeypatch.setattr(ThreatIntel, "_hash_file", staticmethod(counting))

    intel.check(str(sample))
    intel.check(str(sample))

    assert calls["count"] == 1
