import email
from email import policy

import pytest

from tfatp.cli import inject_eml


class _FakeClient:
    def __init__(self):
        self.user = "alice@example.com"
        self.inserted = []

    def insert_message(self, raw, label_ids=None):
        self.inserted.append((raw, label_ids))
        return "abc123"


@pytest.fixture
def patched(monkeypatch):
    fake = _FakeClient()
    monkeypatch.setattr(inject_eml, "GmailClient", lambda cfg: fake)
    monkeypatch.setattr(inject_eml, "load_config", lambda path: object())
    return fake


def _write_eml(tmp_path, body: bytes = b"From: a@b.c\nDate: Mon, 01 Jan 2020 00:00:00 +0000\nSubject: t\n\nbody"):
    p = tmp_path / "x.eml"
    p.write_bytes(body)
    return str(p)


def test_insert_is_default(patched, tmp_path, capsys):
    rc = inject_eml.main([_write_eml(tmp_path)])
    assert rc == 0
    assert len(patched.inserted) == 1
    raw, labels = patched.inserted[0]
    assert raw.startswith(b"From:")
    assert set(labels) == {"INBOX", "UNREAD"}
    assert capsys.readouterr().out.strip() == "abc123"


def test_dry_run_skips_insert(patched, tmp_path, capsys):
    rc = inject_eml.main([_write_eml(tmp_path), "--dry-run"])
    assert rc == 0
    assert patched.inserted == []
    err = capsys.readouterr().err
    assert "dry-run" in err and "INBOX" in err and "UNREAD" in err


def test_no_inbox_no_unread_with_extra_label(patched, tmp_path):
    rc = inject_eml.main([
        _write_eml(tmp_path), "--no-inbox", "--no-unread", "--label-id", "SPAM",
    ])
    assert rc == 0
    assert patched.inserted[0][1] == ["SPAM"]


def test_empty_input_errors(patched, tmp_path, capsys):
    rc = inject_eml.main([_write_eml(tmp_path, body=b"")])
    assert rc == 2
    assert "empty input" in capsys.readouterr().err


def test_bump_date_rewrites_date_header(patched, tmp_path):
    rc = inject_eml.main([_write_eml(tmp_path), "--bump-date"])
    assert rc == 0
    raw, _ = patched.inserted[0]
    msg = email.message_from_bytes(raw, policy=policy.default)
    # Original Date was 2020-01-01; bumped Date must NOT be that.
    assert "2020" not in msg.get("Date", "")


def test_bump_date_off_preserves_date(patched, tmp_path):
    rc = inject_eml.main([_write_eml(tmp_path)])
    assert rc == 0
    raw, _ = patched.inserted[0]
    msg = email.message_from_bytes(raw, policy=policy.default)
    assert "2020" in msg.get("Date", "")
