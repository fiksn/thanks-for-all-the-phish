"""Tests for internal/external sender classification + yellow-banner gating."""

from email.message import EmailMessage

from tfatp.analyze_eml import analyze_with_gate


def _eml(from_addr: str) -> bytes:
    m = EmailMessage()
    m["From"] = from_addr
    m["To"] = "alice@example.com"
    m["Subject"] = "t"
    m["Date"] = "Mon, 01 Jun 2026 10:00:00 +0000"
    m["Message-Id"] = "<abc@host>"
    m.set_content("hello")
    return bytes(m)


def _gate(raw, *, org_domains=frozenset(), check_phases=None, check_phases_internal=None):
    return analyze_with_gate(
        raw,
        mail_from="alice@example.com",
        helo_domain="example.com",
        do_smtp_verify=False,
        young_domain_days=365,
        sender_lookalike_max_distance=2,
        sender_min_domain_age_days=365,
        check_phases=check_phases,
        check_phases_internal=check_phases_internal,
        org_domains=org_domains,
    )


def test_external_warning_triggers_when_sender_outside_org():
    raw = _eml("eve@evil.example")
    *_, triggered = _gate(
        raw,
        org_domains=frozenset({"example.com"}),
        check_phases=(("external_warning",),),
    )
    assert triggered is True


def test_external_warning_skipped_for_internal_sender():
    raw = _eml("bob@example.com")
    *_, triggered = _gate(
        raw,
        org_domains=frozenset({"example.com"}),
        # Even if internal phases list it, an internal sender never trips it.
        check_phases_internal=(("external_warning",),),
    )
    assert triggered is False


def test_internal_phases_replace_external_when_sender_internal():
    # External phases include sender_domain_age, which would mark the gate
    # failed for an unknown-age sender. Internal phases skip it entirely.
    raw = _eml("bob@example.com")
    *_, gate_failed, _ = _gate(
        raw,
        org_domains=frozenset({"example.com"}),
        check_phases=(("sender_domain_age",),),
        check_phases_internal=(("check_password_form",),),
    )
    assert gate_failed is False


def test_no_org_domains_disables_classification():
    # With empty org_domains, no sender is classified — external_warning never
    # fires even when listed in the (always-applied) external phases.
    raw = _eml("eve@evil.example")
    *_, triggered = _gate(
        raw,
        org_domains=frozenset(),
        check_phases=(("external_warning",),),
    )
    assert triggered is False
