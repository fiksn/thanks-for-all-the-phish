"""Per-account sync watermarks, persisted as JSON.

The state file records, per workspace user, the most recently observed
Gmail ``historyId`` and the wall-clock timestamp of the last successfully
processed message. Watchers consult the watermark on startup to resume
from where they left off; they update it after each message they hand to
the rewriter.

The lookback floor is UTC midnight of *today*. If a stored timestamp is
older than that — daemon was down across midnight, or for a long
outage — the resume point is clamped to that floor, so we never go back
into yesterday's inbox. Gmail's ``historyId`` also expires after ~7
days; when the stored id falls outside that window the watcher must
re-resolve a fresh one.

File format (schema version pinned for future migrations):

    {
        "schema_version": 1,
        "accounts": {
            "alice@example.com": {
                "history_id": "987654321",
                "last_processed_at": "2026-06-09T08:14:23Z"
            }
        }
    }

Writes are atomic (temp + rename) so a crash mid-write leaves the
previous good state intact.
"""

import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

_SCHEMA_VERSION = 1
_GMAIL_HISTORY_TTL_DAYS = 7
_FILENAME = "sync_state.json"


@dataclass
class Watermark:
    """The two values we persist per account.

    ``history_id`` is the Gmail change cursor; ``last_processed_at`` is
    the UTC wall-clock instant of the last message we successfully ran
    through the rewriter. Either may be missing when the account is
    fresh.
    """
    history_id: str | None = None
    last_processed_at: datetime | None = None

    def is_history_expired(self, now: datetime | None = None) -> bool:
        """Gmail expires history entries after ~7 days; older ids return
        404 from ``users.history.list``. Treat ours as expired one day
        early so a still-valid id never gets dropped mid-query."""
        if self.last_processed_at is None or self.history_id is None:
            return False
        cutoff = (now or datetime.now(UTC)) - timedelta(
            days=_GMAIL_HISTORY_TTL_DAYS - 1
        )
        return self.last_processed_at < cutoff


@dataclass
class SyncState:
    """In-memory view of the on-disk state file, loaded once at startup
    and re-saved after every checkpoint. The path is fixed at construction
    so ``save()`` is a no-arg call. ``records`` maps a workspace user
    primary email to that user's :class:`Watermark`.
    """
    path: Path
    records: dict[str, Watermark] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "SyncState":
        if not path.exists():
            return cls(path=path)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # Corrupt file shouldn't crash the daemon; start fresh and log
            # via stderr in the caller.
            return cls(path=path)
        records: dict[str, Watermark] = {}
        for user, fields_ in (raw.get("accounts") or {}).items():
            ts_raw = fields_.get("last_processed_at")
            ts = _parse_iso8601(ts_raw) if ts_raw else None
            records[user] = Watermark(
                history_id=fields_.get("history_id") or None,
                last_processed_at=ts,
            )
        return cls(path=path, records=records)

    def get(self, user: str) -> Watermark | None:
        return self.records.get(user)

    def update(
        self,
        user: str,
        *,
        history_id: str | None = None,
        processed_at: datetime | None = None,
    ) -> None:
        """Merge new values into the user's watermark. Existing fields
        survive when only one of the kwargs is provided."""
        wm = self.records.get(user, Watermark())
        if history_id is not None:
            wm.history_id = history_id
        if processed_at is not None:
            # Always store UTC so file contents survive timezone changes.
            wm.last_processed_at = processed_at.astimezone(UTC)
        self.records[user] = wm

    def save(self) -> None:
        """Atomic write: serialise into a sibling temp file and rename."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": _SCHEMA_VERSION,
            "accounts": {
                user: {
                    "history_id": wm.history_id,
                    "last_processed_at": (
                        wm.last_processed_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                        if wm.last_processed_at
                        else None
                    ),
                }
                for user, wm in sorted(self.records.items())
            },
        }
        body = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        # NamedTemporaryFile + rename gives us the atomic-write guarantee
        # without leaving stale .tmp files around on crash. dir= ensures
        # the tmp file is on the same filesystem so rename(2) is atomic.
        fd, tmp = tempfile.mkstemp(
            prefix=".sync_state.", suffix=".tmp", dir=self.path.parent
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(body)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except OSError:
            # Best-effort cleanup if the rename failed.
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def reset(self) -> None:
        """Forget every stored watermark and remove the on-disk file.
        Wired to the ``--reset-state`` CLI flag."""
        self.records.clear()
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def utc_today_midnight(now: datetime | None = None) -> datetime:
    """UTC 00:00:00 of *today*. The hard lookback floor — nothing older
    than this ever gets scanned, no matter how stale the watermark is."""
    n = now or datetime.now(UTC)
    return n.replace(hour=0, minute=0, second=0, microsecond=0)


def effective_resume_at(
    wm: Watermark | None,
    *,
    floor: datetime | None = None,
    override: datetime | None = None,
) -> datetime:
    """Resolve the resume timestamp for a user.

    Precedence: ``override`` (e.g. from ``--sync-from``) wins over the
    stored value. Either is clamped *up* to ``floor`` (default: UTC
    midnight today) so the daemon never reads mail from yesterday or
    earlier.
    """
    if floor is None:
        floor = utc_today_midnight()
    candidate = override if override is not None else (
        wm.last_processed_at if wm and wm.last_processed_at else floor
    )
    return max(candidate, floor)


def default_state_dir() -> Path:
    """Where state lives when no config or env var pins it.

    Priority:
    1. ``TFATP_STATE_DIR`` env var (set explicitly in the Dockerfile
       to ``/var/lib/tfatp`` so the container always writes to the
       declared volume regardless of XDG settings).
    2. ``XDG_DATA_HOME/tfatp`` if XDG_DATA_HOME is set.
    3. ``~/.local/share/tfatp``.
    """
    env = os.environ.get("TFATP_STATE_DIR", "").strip()
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_DATA_HOME", "").strip()
    if xdg:
        return Path(xdg) / "tfatp"
    return Path.home() / ".local" / "share" / "tfatp"


def state_file_path(state_dir: Path) -> Path:
    """Canonical filename inside the state dir. Kept here so callers don't
    fan out and disagree on the name later."""
    return state_dir / _FILENAME


def _parse_iso8601(s: str) -> datetime | None:
    """Tolerate both ``Z`` and ``+00:00`` UTC suffixes. Returns ``None``
    for unparseable strings rather than raising — corrupt state must
    never crash the daemon."""
    try:
        if s.endswith("Z"):
            return datetime.fromisoformat(s[:-1]).replace(tzinfo=UTC)
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except (TypeError, ValueError):
        return None
