"""Unit tests for the per-account sync watermark store."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tfatp.sync_state import (
    SyncState,
    Watermark,
    default_state_dir,
    effective_resume_at,
    state_file_path,
    utc_today_midnight,
)


def test_load_returns_empty_state_when_file_missing(tmp_path: Path) -> None:
    s = SyncState.load(tmp_path / "sync_state.json")
    assert s.records == {}


def test_load_returns_empty_state_on_corrupt_file(tmp_path: Path) -> None:
    p = tmp_path / "sync_state.json"
    p.write_text("not json{{", encoding="utf-8")
    s = SyncState.load(p)
    assert s.records == {}


def test_update_then_save_then_reload_roundtrips(tmp_path: Path) -> None:
    p = tmp_path / "sync_state.json"
    s = SyncState.load(p)
    ts = datetime(2026, 6, 9, 8, 14, 23, tzinfo=UTC)
    s.update("alice@example.com", history_id="987", processed_at=ts)
    s.save()

    s2 = SyncState.load(p)
    wm = s2.get("alice@example.com")
    assert wm is not None
    assert wm.history_id == "987"
    assert wm.last_processed_at == ts


def test_update_merges_when_only_one_field_given(tmp_path: Path) -> None:
    s = SyncState(path=tmp_path / "x.json")
    ts1 = datetime(2026, 6, 9, 8, 0, tzinfo=UTC)
    s.update("alice@example.com", history_id="1", processed_at=ts1)
    # Bump only the timestamp; history_id must survive.
    ts2 = datetime(2026, 6, 9, 8, 5, tzinfo=UTC)
    s.update("alice@example.com", processed_at=ts2)
    wm = s.get("alice@example.com")
    assert wm.history_id == "1"
    assert wm.last_processed_at == ts2


def test_save_is_atomic_and_overwrites(tmp_path: Path) -> None:
    p = tmp_path / "sync_state.json"
    s = SyncState(path=p)
    s.update("alice@example.com", history_id="A", processed_at=datetime.now(UTC))
    s.save()
    s.update("alice@example.com", history_id="B", processed_at=datetime.now(UTC))
    s.save()
    s2 = SyncState.load(p)
    assert s2.get("alice@example.com").history_id == "B"
    # No stray temp files left behind on disk.
    leftovers = [pp for pp in tmp_path.iterdir() if pp.suffix == ".tmp"]
    assert leftovers == []


def test_reset_clears_records_and_removes_file(tmp_path: Path) -> None:
    p = tmp_path / "sync_state.json"
    s = SyncState(path=p)
    s.update("alice@example.com", history_id="1", processed_at=datetime.now(UTC))
    s.save()
    assert p.exists()
    s.reset()
    assert s.records == {}
    assert not p.exists()


def test_effective_resume_uses_stored_when_after_floor() -> None:
    floor = datetime(2026, 6, 9, 0, 0, tzinfo=UTC)
    wm = Watermark(history_id="x", last_processed_at=datetime(2026, 6, 9, 10, tzinfo=UTC))
    assert effective_resume_at(wm, floor=floor) == datetime(2026, 6, 9, 10, tzinfo=UTC)


def test_effective_resume_clamps_to_floor_when_stored_is_yesterday() -> None:
    floor = datetime(2026, 6, 9, 0, 0, tzinfo=UTC)
    wm = Watermark(history_id="x", last_processed_at=datetime(2026, 6, 8, 22, tzinfo=UTC))
    assert effective_resume_at(wm, floor=floor) == floor


def test_effective_resume_uses_floor_when_no_state() -> None:
    floor = datetime(2026, 6, 9, 0, 0, tzinfo=UTC)
    assert effective_resume_at(None, floor=floor) == floor


def test_effective_resume_override_wins() -> None:
    floor = datetime(2026, 6, 9, 0, 0, tzinfo=UTC)
    wm = Watermark(history_id="x", last_processed_at=datetime(2026, 6, 9, 10, tzinfo=UTC))
    # Override later than the watermark.
    override = datetime(2026, 6, 9, 14, tzinfo=UTC)
    assert effective_resume_at(wm, floor=floor, override=override) == override


def test_effective_resume_override_still_clamped_to_floor() -> None:
    floor = datetime(2026, 6, 9, 0, 0, tzinfo=UTC)
    # Operator asks to sync from yesterday — must still be clamped to today.
    override = datetime(2026, 6, 8, 12, tzinfo=UTC)
    assert effective_resume_at(None, floor=floor, override=override) == floor


def test_history_expiry_after_seven_days() -> None:
    now = datetime(2026, 6, 16, 9, 0, tzinfo=UTC)
    fresh = Watermark(
        history_id="x", last_processed_at=now - timedelta(days=1),
    )
    stale = Watermark(
        history_id="x", last_processed_at=now - timedelta(days=8),
    )
    assert not fresh.is_history_expired(now=now)
    assert stale.is_history_expired(now=now)


def test_history_expiry_is_false_when_no_timestamp() -> None:
    # Can't tell — be conservative and call it still valid.
    wm = Watermark(history_id="x", last_processed_at=None)
    assert not wm.is_history_expired()


def test_utc_today_midnight_zeroes_time() -> None:
    now = datetime(2026, 6, 9, 14, 32, 11, tzinfo=UTC)
    floor = utc_today_midnight(now=now)
    assert floor == datetime(2026, 6, 9, 0, 0, 0, tzinfo=UTC)


def test_default_state_dir_honours_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TFATP_STATE_DIR", "/var/lib/tfatp")
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    assert default_state_dir() == Path("/var/lib/tfatp")


def test_default_state_dir_falls_back_to_xdg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("TFATP_STATE_DIR", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert default_state_dir() == tmp_path / "tfatp"


def test_state_file_path_is_in_state_dir(tmp_path: Path) -> None:
    assert state_file_path(tmp_path) == tmp_path / "sync_state.json"
