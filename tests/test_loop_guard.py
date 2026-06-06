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


def test_sender_supplied_x_checked_headers_are_stripped_before_rewrite():
    """A message arriving with sender-spoofed X-Checked-* headers must end up
    with exactly one set of X-Checked-* headers in the rewritten copy — ours
    — so loop_guard can't be tricked into skipping rewrites and downstream
    readers don't see a sender-controlled value alongside the real one.
    """
    raw = (
        b"From: attacker@evil.com\n"
        b"Message-Id: <evil@host>\n"
        b"X-Checked-By: thanks-for-all-the-phish\n"
        b"X-Checked-Findings: spoofed -> nothing\n"
        b"X-Checked-Sender-Lookalike: spoofed\n"
        b"X-Checked-External-Sender: no\n"
        b"X-Checked-Mac: deadbeef\n"
        b"X-Checked-SMTP: pass (fake)\n"
        b"Subject: t\n\nbody"
    )
    new_raw = build_corrected_eml(raw, "annotated", [], loop_guard_secret=_SECRET)
    parsed = email.message_from_bytes(new_raw, policy=policy.default)
    for header in (
        "X-Checked-By", "X-Checked-Findings", "X-Checked-Sender-Lookalike",
        "X-Checked-External-Sender", "X-Checked-Mac", "X-Checked-SMTP",
    ):
        values = parsed.get_all(header) or []
        assert len(values) <= 1, (
            f"{header}: expected at most one value, got {values}"
        )
    # The marker still resolves to ours and the HMAC is valid under the
    # current secret — i.e. the spoofed header didn't leak through.
    assert loop_guard.is_own_rewrite(parsed, _SECRET)
    # And the spoofed findings content is gone.
    assert "spoofed" not in (parsed.get("X-Checked-Findings", "") or "")


def test_findings_header_caps_at_budget_with_overflow_summary():
    """A pathological count of findings must produce a single bounded header
    value, with a ``+N more`` suffix telling consumers how many were elided.
    """
    from tfatp.analyze_eml import (
        _FINDINGS_HEADER_BUDGET,
        _render_findings_header,
    )
    from tfatp.link_analysis import LinkFinding, YoungDomain

    # 200 findings, each ~70 chars including its warning. Total well above 4 KB.
    findings = [
        LinkFinding(
            url=f"https://noisy-{i:03d}.example.com/path-here",
            host=f"noisy-{i:03d}.example.com",
            domain=f"noisy-{i:03d}.example.com",
            age_days=10, has_password_form=False,
            warnings=[YoungDomain(domain=f"noisy-{i:03d}.example.com", age_days=10)],
        )
        for i in range(200)
    ]
    header = _render_findings_header(findings)
    assert len(header) <= _FINDINGS_HEADER_BUDGET
    assert "+" in header and "more" in header  # overflow indicator present
    # At least *some* findings actually rendered.
    assert "noisy-000.example.com" in header


def test_findings_header_no_overflow_under_budget():
    from tfatp.analyze_eml import _render_findings_header
    from tfatp.link_analysis import LinkFinding, YoungDomain

    findings = [
        LinkFinding(
            url="https://one.example.com/x",
            host="one.example.com", domain="one.example.com",
            age_days=10, has_password_form=False,
            warnings=[YoungDomain(domain="one.example.com", age_days=10)],
        )
    ]
    header = _render_findings_header(findings)
    assert header == "https://one.example.com/x -> young (10d)"
    assert "more" not in header


def test_diff_finder_picks_outer_when_original_already_has_original_eml():
    """A sender attaching their own `original.eml` must not shadow ours.

    `Message.walk()` is depth-first and yields the outer ``message/rfc822``
    before recursing into its embedded payload. The diff CLI's finder
    returns on first hit, so our wrapper wins — but pin the behaviour with
    a test so future refactors don't reverse the order.
    """
    from email.message import EmailMessage

    from tfatp.analyze_eml import build_corrected_eml
    from tfatp.cli.diff_message import _find_original_attachment

    decoy = EmailMessage()
    decoy["From"] = "decoy@inner.example"
    decoy["Subject"] = "DECOY"
    decoy.set_content("DECOY-INNER-BODY")

    original = EmailMessage()
    original["From"] = "real-sender@example.com"
    original["Subject"] = "the real subject"
    original["Message-Id"] = "<real@host>"
    original.set_content("REAL ORIGINAL BODY")
    original.add_attachment(decoy, filename="original.eml", disposition="attachment")

    new_raw = build_corrected_eml(
        bytes(original), "rewritten body", [], body_subtype="plain",
    )
    new_msg = email.message_from_bytes(new_raw, policy=policy.default)
    found = _find_original_attachment(new_msg)
    assert found is not None
    parsed = email.message_from_bytes(found, policy=policy.default)
    assert parsed.get("Subject") == "the real subject"
    assert parsed.get("Message-Id") == "<real@host>"


def test_capped_helper_truncates_overlong_value():
    from tfatp.analyze_eml import _HEADER_BUDGET, _capped

    short = "all fine"
    assert _capped(short) == short
    long = "x" * (_HEADER_BUDGET * 2)
    out = _capped(long)
    assert len(out) == _HEADER_BUDGET
    assert out.endswith("…")


def test_findings_header_empty_for_no_warnings():
    from tfatp.analyze_eml import _render_findings_header
    from tfatp.link_analysis import LinkFinding

    findings = [
        LinkFinding(
            url="https://clean.example.com/x",
            host="clean.example.com", domain="clean.example.com",
            age_days=3650, has_password_form=False, warnings=[],
        )
    ]
    assert _render_findings_header(findings) == ""


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
