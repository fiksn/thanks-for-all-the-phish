"""Run DKIM + link analysis on an RFC822 message and emit a rewritten .eml.

Stdout: new .eml — original headers preserved, body replaced with an annotated
version, the original message attached as message/rfc822, plus an
`X-Checked-By: thanks-for-the-phish` header. Suitable to pipe into
`users.messages.insert` after deleting the original.

Stderr: human-readable analysis report.

Usage:
    cat suspicious.eml | python -m tfatp.cli.analyze_eml > corrected.eml
    python -m tfatp.cli.analyze_eml suspicious.eml > corrected.eml
    python -m tfatp.cli.analyze_eml suspicious.eml --young-domain-days 180 --quiet
"""

import argparse
import email
import sys
from email import policy
from email.message import EmailMessage

from tfatp import loop_guard
from tfatp.attachments import scan as scan_attachments
from tfatp.config import _DEFAULT_CHECK_PHASES
from tfatp.dkim_verify import verify as verify_dkim
from tfatp.link_analysis import (
    DEFAULT_YOUNG_DOMAIN_DAYS,
    LinkFinding,
    analyze,
    annotate,
    defang,
    domain_age_days,
    message_body_text,
    registrable_domain,
)
from tfatp.addr import extract_address
from tfatp.defang_policy import DefangPolicy, compute as compute_defang
from tfatp.lookalike import LookalikeResult, check as check_lookalike
from tfatp.smtp_verify import SmtpVerifyResult, verify_sender

X_CHECKED_BY = loop_guard.X_CHECKED_BY
# Content-Type, Content-Transfer-Encoding, etc. must be rewritten because the
# body changes; everything else (From/To/Subject/Date/Message-ID/References/...)
# is preserved verbatim so threading and identity stay intact.
_HEADERS_TO_REWRITE = {
    "content-type",
    "content-transfer-encoding",
    "content-disposition",
    "mime-version",
}


def _read_input(path: str | None) -> bytes:
    if path and path != "-":
        with open(path, "rb") as f:
            return f.read()
    return sys.stdin.buffer.read()


def _banner(
    smtp_result: SmtpVerifyResult | None,
    sender_lookalike: LookalikeResult | None,
    findings: list[LinkFinding],
    neutralize_all: bool = False,
) -> str:
    # DKIM is intentionally not surfaced: the signature belongs to the original
    # (attached) bytes and a reader can re-verify it independently.
    lines = ["=== thanks-for-the-phish analysis ==="]
    if sender_lookalike is not None and sender_lookalike.matched:
        lines.append(f"Sender impersonation: {sender_lookalike.detail}")
    if smtp_result is not None:
        suffix = " — all links defanged below" if neutralize_all else ""
        lines.append(f"SMTP: {smtp_result.status} ({smtp_result.detail}){suffix}")
    suspect = [f for f in findings if f.warnings]
    if suspect:
        lines.append("Warnings:")
        for f in suspect:
            shown = defang(f.url) if neutralize_all else f.url
            lines.append(f"  - {shown}  ({'; '.join(f.warnings)})")
    else:
        lines.append("Warnings: none")
    lines.append("=== end analysis ===")
    lines.append("")
    lines.append("")
    return "\n".join(lines)


def build_corrected_eml(
    raw: bytes,
    annotated_body: str,
    findings: list[LinkFinding],
    smtp_result: SmtpVerifyResult | None = None,
    sender_lookalike: LookalikeResult | None = None,
    neutralize_all: bool = False,
    loop_guard_secret: str = "",
) -> bytes:
    # DKIM is deliberately not propagated into the rewritten message — the
    # signature applies to the original (attached) bytes; recomputing it on
    # this synthesized message would be misleading and shouldn't drive
    # tool decisions.
    original = email.message_from_bytes(raw, policy=policy.default)

    new_msg = EmailMessage(policy=policy.SMTP)
    for k, v in original.items():
        if k.lower() not in _HEADERS_TO_REWRITE:
            new_msg[k] = v

    new_msg[loop_guard.HEADER_CHECKED_BY] = X_CHECKED_BY
    if loop_guard_secret:
        new_msg[loop_guard.HEADER_MAC] = loop_guard.compute_mac(
            loop_guard_secret, str(original.get("Message-Id", ""))
        )
    if smtp_result is not None:
        new_msg["X-Checked-SMTP"] = f"{smtp_result.status} ({smtp_result.detail})"
    if sender_lookalike is not None and sender_lookalike.matched:
        new_msg["X-Checked-Sender-Lookalike"] = sender_lookalike.detail
    suspect_summary = "; ".join(
        f"{f.url} -> {', '.join(f.warnings)}" for f in findings if f.warnings
    )
    if suspect_summary:
        new_msg["X-Checked-Findings"] = suspect_summary

    new_msg.set_content(
        _banner(smtp_result, sender_lookalike, findings, neutralize_all) + annotated_body
    )

    # Attach the original message as a real message/rfc822 part so any reader
    # can recover the unmodified bytes.
    new_msg.add_attachment(original)
    # Give the attachment a sensible filename.
    attachment = new_msg.get_payload()[-1]
    attachment.replace_header(
        "Content-Disposition", 'attachment; filename="original.eml"'
    )

    return bytes(new_msg)


def analyze_with_gate(
    raw: bytes,
    *,
    mail_from: str,
    helo_domain: str,
    do_smtp_verify: bool,
    young_domain_days: int,
    sender_lookalike_max_distance: int,
    sender_min_domain_age_days: int,
    check_phases: tuple[tuple[str, ...], ...] | None = None,
) -> tuple[
    list[LinkFinding],
    SmtpVerifyResult | None,
    LookalikeResult | None,
    str | None,
    dict[str, bool],
    bool,
]:
    """Run the phased gate over `raw` and return collected signals.

    Phases run in order; the first phase to surface a suspicious signal blocks
    every later phase. SMTP probe and link-fetching never execute past a
    failed phase. Returns:
      (findings, smtp_result, sender_lookalike, sender_age_warning,
       enabled_link_stages, gate_failed).
    """
    phases = check_phases if check_phases is not None else _DEFAULT_CHECK_PHASES
    body = message_body_text(raw)
    original = email.message_from_bytes(raw, policy=policy.default)
    sender_addr = extract_address(str(original.get("From", "")))
    sender_domain = (
        registrable_domain(sender_addr.split("@", 1)[1]) if "@" in sender_addr else ""
    )
    protected_domain = (
        registrable_domain(mail_from.split("@", 1)[1]) if "@" in mail_from else ""
    )

    smtp_result: SmtpVerifyResult | None = None
    sender_lookalike: LookalikeResult | None = None
    sender_age_warning: str | None = None
    enabled = {
        "check_link_domain_age": False,
        "check_link_lookalike": False,
        "check_password_form": False,
    }

    gate_failed = False
    for phase in phases:
        if gate_failed:
            break
        phase_failed = False
        for stage in phase:
            if stage == "sender_domain_age" and sender_domain:
                age = domain_age_days(sender_domain)
                if age is None:
                    sender_age_warning = (
                        f"sender domain age unknown for {sender_domain} "
                        "(treated as too young)"
                    )
                    phase_failed = True
                elif age < sender_min_domain_age_days:
                    sender_age_warning = (
                        f"sender domain age {age}d < {sender_min_domain_age_days}d "
                        f"for {sender_domain}"
                    )
                    phase_failed = True
            elif stage == "sender_lookalike" and sender_domain and protected_domain:
                sender_lookalike = check_lookalike(
                    sender_domain, protected_domain,
                    max_distance=sender_lookalike_max_distance,
                )
                if sender_lookalike.matched:
                    phase_failed = True
            elif stage == "smtp_verify":
                if do_smtp_verify and mail_from and sender_addr:
                    smtp_result = verify_sender(
                        sender_addr, mail_from, helo_domain or "localhost"
                    )
                    if not smtp_result.ok:
                        phase_failed = True
            elif stage in enabled:
                enabled[stage] = True
        if phase_failed:
            gate_failed = True

    def _apply_link_lookalike(items: list[LinkFinding]) -> None:
        if not (enabled["check_link_lookalike"] and protected_domain):
            return
        for item in items:
            if not item.domain or item.url.startswith("sender:"):
                continue
            res = check_lookalike(
                item.domain, protected_domain,
                max_distance=sender_lookalike_max_distance,
            )
            if res.matched:
                item.warnings.append(
                    f"link domain lookalike of {protected_domain} "
                    f"({item.domain}, distance {res.distance})"
                )

    # Per-phase model for link stages: only fetch URLs (check_password_form)
    # if it sits in a strictly later phase than the link-data checks AND no
    # link-data warning fired. Same-phase placement means "run together,
    # don't gate each other" — matches the cascade semantics for sender
    # stages.
    def _phase_index(stage: str) -> int:
        for i, phase in enumerate(phases):
            if stage in phase:
                return i
        return -1

    fetch_phase = _phase_index("check_password_form")
    age_phase = _phase_index("check_link_domain_age")
    lookalike_phase = _phase_index("check_link_lookalike")
    gates_before_fetch = [
        p for p in (age_phase, lookalike_phase) if 0 <= p < fetch_phase
    ]

    # First pass: link data only, no URL fetch. This always runs so we have
    # findings even when later phases are gated off entirely.
    findings = analyze(
        body,
        young_domain_days=young_domain_days,
        raw_rfc822=raw,
        check_link_domain_age=enabled["check_link_domain_age"],
        check_password_form=False,
    )
    _apply_link_lookalike(findings)

    # Second pass only if check_password_form is enabled, and either has no
    # gating data phases before it or those phases produced no warning.
    if enabled["check_password_form"]:
        if gates_before_fetch:
            link_data_failed = any(
                "young domain" in w or "link domain lookalike" in w
                for f in findings for w in f.warnings
            )
            if link_data_failed:
                gate_failed = True
                enabled["check_password_form"] = False
        if enabled["check_password_form"]:
            findings = analyze(
                body,
                young_domain_days=young_domain_days,
                raw_rfc822=raw,
                check_link_domain_age=enabled["check_link_domain_age"],
                check_password_form=True,
            )
            _apply_link_lookalike(findings)
    # Attachment scanning is always-on: local-only, fast, and a macro is a
    # high-confidence malicious signal that should reach the defang pipeline
    # the same way link warnings do.
    findings.extend(scan_attachments(raw))

    if sender_age_warning:
        findings.append(
            LinkFinding(
                url="sender:age",
                host="",
                domain=sender_domain,
                age_days=None,
                has_password_form=False,
                warnings=[sender_age_warning],
            )
        )
    return findings, smtp_result, sender_lookalike, sender_age_warning, enabled, gate_failed


def run(raw: bytes, young_domain_days: int, quiet: bool,
        mail_from: str, helo_domain: str, do_smtp_verify: bool,
        defang_policy: DefangPolicy | None = None,
        sender_lookalike_max_distance: int = 2,
        sender_min_domain_age_days: int = 365,
        check_phases: tuple[tuple[str, ...], ...] | None = None) -> int:
    defang_policy = defang_policy or DefangPolicy()
    phases = check_phases if check_phases is not None else _DEFAULT_CHECK_PHASES
    if not raw.strip():
        print("error: empty input — pipe an .eml file or pass a path", file=sys.stderr)
        return 2

    dkim_result = verify_dkim(raw)
    body = message_body_text(raw)
    original = email.message_from_bytes(raw, policy=policy.default)
    (
        findings,
        smtp_result,
        sender_lookalike,
        sender_age_warning,
        enabled,
        gate_failed,
    ) = analyze_with_gate(
        raw,
        mail_from=mail_from,
        helo_domain=helo_domain,
        do_smtp_verify=do_smtp_verify,
        young_domain_days=young_domain_days,
        sender_lookalike_max_distance=sender_lookalike_max_distance,
        sender_min_domain_age_days=sender_min_domain_age_days,
        check_phases=phases,
    )

    neutralize_all, per_url = compute_defang(
        findings, smtp_result, sender_lookalike, defang_policy
    )
    annotated = annotate(body, findings)
    if neutralize_all:
        annotated = defang(annotated)
    else:
        for url in per_url:
            annotated = annotated.replace(url, defang(url))

    if not quiet:
        print("=== message ===", file=sys.stderr)
        print(f"  date    : {original.get('Date', '')}", file=sys.stderr)
        print(f"  from    : {original.get('From', '')}", file=sys.stderr)
        print(f"  to      : {original.get('To', '')}", file=sys.stderr)
        print(f"  subject : {original.get('Subject', '')}", file=sys.stderr)
        print(f"  dkim    : {dkim_result.status} ({dkim_result.detail})", file=sys.stderr)
        if sender_age_warning:
            print(f"  sender-age: {sender_age_warning}", file=sys.stderr)
        if smtp_result is not None:
            print(f"  smtp    : {smtp_result.status} ({smtp_result.detail})", file=sys.stderr)
        if sender_lookalike is not None and sender_lookalike.matched:
            print(f"  lookalike: {sender_lookalike.detail}", file=sys.stderr)
        if gate_failed:
            # Only label a stage as gated-off if it was actually requested
            # (CLI/config wanted it) but didn't run because a phase failed.
            requested = {
                "smtp_verify": do_smtp_verify,
                "check_link_domain_age": True,
                "check_link_lookalike": True,
                "check_password_form": True,
            }
            ran = {
                "smtp_verify": smtp_result is not None,
                "check_link_domain_age": enabled["check_link_domain_age"],
                "check_link_lookalike": enabled["check_link_lookalike"],
                "check_password_form": enabled["check_password_form"],
            }
            skipped = [
                s for phase in phases for s in phase
                if s in ran and requested.get(s, False) and not ran[s]
            ]
            if skipped:
                print(f"  skipped : {', '.join(skipped)} (gated off by earlier phase)",
                      file=sys.stderr)
        if findings:
            print("  links   :", file=sys.stderr)
            for f in findings:
                age = f"{f.age_days}d" if f.age_days is not None else "unknown"
                flags = ", ".join(f.warnings) if f.warnings else "ok"
                print(f"    - {f.url}  (domain={f.domain}, age={age}, {flags})",
                      file=sys.stderr)
        else:
            print("  links   : (none)", file=sys.stderr)

    corrected = build_corrected_eml(
        raw, annotated, findings, smtp_result, sender_lookalike, neutralize_all,
    )
    sys.stdout.buffer.write(corrected)

    # DKIM intentionally excluded from the suspicious decision — see _banner().
    suspicious = (
        any(f.warnings for f in findings)
        or (smtp_result is not None and smtp_result.status == "rejected")
        or (sender_lookalike is not None and sender_lookalike.matched)
    )
    return 1 if suspicious else 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("path", nargs="?", help="Path to .eml file. Omit or use '-' for stdin.")
    p.add_argument(
        "--young-domain-days",
        type=int,
        default=DEFAULT_YOUNG_DOMAIN_DAYS,
        help=f"Warn when domain age is below this many days (default: {DEFAULT_YOUNG_DOMAIN_DAYS})",
    )
    p.add_argument("--quiet", action="store_true", help="Suppress the stderr analysis report.")
    p.add_argument(
        "--mail-from",
        default="",
        help="MAIL FROM identity for the SMTP RCPT-TO probe (your own address). "
        "Required for --smtp-verify. Falls back to the To: header if blank.",
    )
    p.add_argument(
        "--helo-domain",
        default="",
        help="Domain to advertise in HELO/EHLO. Defaults to the domain of --mail-from.",
    )
    p.add_argument(
        "--smtp-verify",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Probe the sender's MX with RCPT TO (no DATA). Default: on.",
    )
    p.add_argument(
        "--sender-lookalike-distance",
        type=int,
        default=2,
        help="Max edit distance for sender lookalike check (default: 2).",
    )
    p.add_argument(
        "--sender-min-domain-age-days",
        type=int,
        default=365,
        help="Reject sender domains younger than this many days; unknown age "
        "counts as too young (default: 365).",
    )
    args = p.parse_args(argv)
    raw = _read_input(args.path)

    mail_from = args.mail_from
    if not mail_from and args.smtp_verify:
        import email as _e
        parsed = _e.message_from_bytes(raw, policy=policy.default)
        mail_from = extract_address(str(parsed.get("To", "")))
    helo = args.helo_domain or (mail_from.split("@", 1)[1] if "@" in mail_from else "localhost")

    return run(
        raw,
        young_domain_days=args.young_domain_days,
        quiet=args.quiet,
        mail_from=mail_from,
        helo_domain=helo,
        do_smtp_verify=args.smtp_verify,
        sender_lookalike_max_distance=args.sender_lookalike_distance,
        sender_min_domain_age_days=args.sender_min_domain_age_days,
    )


