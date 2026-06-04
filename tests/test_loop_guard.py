import email
from email import policy

import pytest

from tfatp import loop_guard
from tfatp.analyze_eml import build_corrected_eml
from tfatp.config import load_config


_SECRET = "x" * 32


def test_is_own_rewrite_round_trips():
    raw = b"From: x@y\nMessage-Id: <abc@host>\nSubject: t\n\nbody"
    new_raw = build_corrected_eml(
        raw, "annotated body", [], loop_guard_secret=_SECRET
    )
    parsed = email.message_from_bytes(new_raw, policy=policy.default)
    assert loop_guard.is_own_rewrite(parsed, _SECRET)


def test_is_own_rewrite_fails_on_wrong_secret():
    raw = b"From: x@y\nMessage-Id: <abc@host>\nSubject: t\n\nbody"
    new_raw = build_corrected_eml(raw, "annotated", [], loop_guard_secret=_SECRET)
    parsed = email.message_from_bytes(new_raw, policy=policy.default)
    assert not loop_guard.is_own_rewrite(parsed, "different-secret-of-length-32xxx")


def test_attacker_cannot_forge_with_header_alone():
    """A sender adding X-Checked-By but no valid MAC must NOT pass."""
    raw = (
        b"From: attacker@evil.com\n"
        b"Message-Id: <evil@host>\n"
        b"X-Checked-By: thanks-for-all-the-phish\n"
        b"Subject: bypass attempt\n\nbody"
    )
    parsed = email.message_from_bytes(raw, policy=policy.default)
    assert not loop_guard.is_own_rewrite(parsed, _SECRET)


def test_attacker_cannot_forge_with_wrong_mac():
    raw = (
        b"From: attacker@evil.com\n"
        b"Message-Id: <evil@host>\n"
        b"X-Checked-By: thanks-for-all-the-phish\n"
        b"X-Checked-Mac: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
        b"Subject: bypass attempt\n\nbody"
    )
    parsed = email.message_from_bytes(raw, policy=policy.default)
    assert not loop_guard.is_own_rewrite(parsed, _SECRET)


def test_mac_binds_to_message_id():
    """A MAC valid for one Message-Id must not validate against another."""
    mac_a = loop_guard.compute_mac(_SECRET, "<a@host>")
    raw = (
        b"From: x@y\nMessage-Id: <b@host>\n"
        b"X-Checked-By: thanks-for-all-the-phish\n"
        b"X-Checked-Mac: " + mac_a.encode() + b"\n"
        b"Subject: t\n\nbody"
    )
    parsed = email.message_from_bytes(raw, policy=policy.default)
    assert not loop_guard.is_own_rewrite(parsed, _SECRET)


def test_is_own_rewrite_fails_closed_on_empty_secret():
    raw = b"From: x@y\nMessage-Id: <abc@host>\nSubject: t\n\nbody"
    new_raw = build_corrected_eml(raw, "annotated", [], loop_guard_secret=_SECRET)
    parsed = email.message_from_bytes(new_raw, policy=policy.default)
    # If the runtime has no secret configured, it can't validate ours either.
    assert not loop_guard.is_own_rewrite(parsed, "")


def test_config_requires_secret_when_rewrite_only_from_set(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text(
        'domain="x"\nuser="a@x"\nrewrite_only_from=[".*"]\nloop_guard_secret=""\n'
    )
    with pytest.raises(ValueError, match="loop_guard_secret"):
        load_config(p)


def test_config_accepts_short_secret_when_rewrite_only_from_empty(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text(
        'domain="x"\nuser="a@x"\nrewrite_only_from=[]\nloop_guard_secret=""\n'
    )
    cfg = load_config(p)
    assert cfg.loop_guard_secret == ""
