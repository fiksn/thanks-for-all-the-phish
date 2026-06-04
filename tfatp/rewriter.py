"""Delete + insert pipeline for replacing a Gmail message with a rewritten copy."""

import email
import sys
from email import policy

from tfatp import loop_guard
from tfatp.addr import extract_address, sender_allowed
from tfatp.analyze_eml import analyze_with_gate, build_corrected_eml, rewrite_body
from tfatp.client import GmailClient
from tfatp.defang_policy import DefangPolicy, compute as compute_defang
from tfatp.link_analysis import LinkFinding, message_body

__all__ = ["extract_address", "sender_allowed", "replace_message", "maybe_rewrite_new_mail"]


def replace_message(client: GmailClient, message_id: str, new_raw: bytes) -> str:
    """Permanently delete `message_id` and insert `new_raw`. Returns new id.

    This is destructive — the original is unrecoverable from Trash. The corrected
    message embeds the original as a message/rfc822 attachment, so the content is
    preserved inside the new message.
    """
    print(f"[rewrite] insert: {len(new_raw)} bytes", file=sys.stderr)
    new_id = client.insert_message(new_raw)
    print(f"[rewrite] inserted new_id={new_id}", file=sys.stderr)
    # Delete only after insert succeeds, so a failed insert doesn't lose the mail.
    print(f"[rewrite] delete: old_id={message_id}", file=sys.stderr)
    client.delete_message(message_id)
    print(f"[rewrite] deleted old_id={message_id}", file=sys.stderr)
    return new_id


def maybe_rewrite_new_mail(
    client: GmailClient, message_id: str, log_prefix: str = "[rewrite]"
) -> tuple[bool, list[LinkFinding], str | None]:
    """Inspect a freshly-arrived message and, if eligible, replace it in-place.

    Eligibility:
    - From: address must match a regex in config.rewrite_only_from
      (empty list disables rewriting; [".*"] enables it for every sender)
    - the message must have at least one warning (suspicious link)

    Returns (rewritten, findings, new_message_id).
    """
    cfg = client.config
    raw = client.get_raw_message(message_id)
    parsed = email.message_from_bytes(raw, policy=policy.default)
    # Loop guard: when the watcher dispatches a message we just inserted, the
    # HMAC stamp lets us recognize our own rewrite and short-circuit before
    # running the pipeline a second time. A header-only marker would be
    # trivially forged by any sender; the MAC binds it to the secret.
    if loop_guard.is_own_rewrite(parsed, cfg.loop_guard_secret):
        print(f"{log_prefix} id={message_id} own rewrite; skipping", file=sys.stderr)
        return False, [], None
    from_header = str(parsed.get("From", ""))

    body, body_subtype = message_body(raw)
    # HELO advertises a host on our side: use the domain of the recipient
    # mailbox we just received the message at, not the workspace-config knob.
    helo = client.user.split("@", 1)[1] if "@" in client.user else "localhost"
    org_domains = client.org_domains
    print(f"{log_prefix} id={message_id} analyze: running gate", file=sys.stderr)
    (
        findings, smtp_result, sender_lookalike, sender_age_warning,
        enabled, gate_failed, external_warning_triggered,
    ) = analyze_with_gate(
        raw,
        mail_from=client.user,
        helo_domain=helo,
        do_smtp_verify=cfg.smtp_verify,
        young_domain_days=cfg.young_domain_days,
        sender_lookalike_max_distance=cfg.sender_lookalike_max_distance,
        sender_min_domain_age_days=cfg.sender_min_domain_age_days,
        check_phases=cfg.check_phases,
        check_phases_internal=cfg.check_phases_internal,
        org_domains=org_domains,
        sender_whitelist=cfg.sender_whitelist,
    )

    def _phase(stage: str, outcome: str) -> None:
        print(f"{log_prefix} id={message_id} phase:{stage} {outcome}", file=sys.stderr)

    if sender_age_warning:
        _phase("sender_domain_age", f"FAIL ({sender_age_warning})")
    if sender_lookalike is not None:
        _phase(
            "sender_lookalike",
            "FAIL" if sender_lookalike.matched else "ok",
        )
    if smtp_result is not None:
        _phase("smtp_verify", f"{smtp_result.status} ({smtp_result.detail})")
    if enabled["check_link_domain_age"] or enabled["check_link_lookalike"]:
        link_warns = sum(1 for f in findings for w in f.warnings if "link" in w or "young" in w)
        _phase(
            "link_checks",
            f"{len(findings)} link(s), {link_warns} warning(s)",
        )
    if enabled["check_password_form"]:
        pw = sum(1 for f in findings if f.has_password_form)
        _phase("check_password_form", f"fetched URLs, {pw} with password form")
    if external_warning_triggered:
        _phase("external_warning", "sender external (yellow banner)")
    if gate_failed:
        _phase("gate", "tripped — later phases skipped")

    suspicious = (
        any(f.warnings for f in findings)
        or (smtp_result is not None and smtp_result.status == "rejected")
        or (sender_lookalike is not None and sender_lookalike.matched)
    )
    # External-sender warning is a legitimate reason to rewrite even when no
    # other check fired — otherwise a clean external mail never picks up the
    # yellow banner because the rewrite gate is closed.
    if not suspicious and not external_warning_triggered:
        print(f"{log_prefix} id={message_id} clean; no action", file=sys.stderr)
        return False, findings, None
    if not sender_allowed(from_header, cfg.rewrite_only_from):
        reason = (
            "rewrite_only_from is empty (rewriting disabled)"
            if not cfg.rewrite_only_from
            else f"sender {extract_address(from_header)!r} does not match rewrite_only_from"
        )
        print(f"{log_prefix} suspicious but {reason}; skipping", file=sys.stderr)
        return False, findings, None

    defang_policy = DefangPolicy(
        on_smtp_fail=cfg.defang_on_smtp_fail,
        on_password_form=cfg.defang_on_password_form,
        on_sender_lookalike=cfg.defang_on_sender_lookalike,
        on_sender_young_domain=cfg.defang_on_sender_young_domain,
        on_young_domain=cfg.defang_on_young_domain,
        on_link_lookalike=cfg.defang_on_link_lookalike,
        on_anchor_deception=cfg.defang_on_anchor_deception,
        on_macro=cfg.defang_on_macro,
        on_external_warning=cfg.defang_on_external,
    )
    neutralize_all, per_url = compute_defang(
        findings,
        smtp_result,
        sender_lookalike,
        defang_policy,
        external_warning=external_warning_triggered,
    )
    annotated = rewrite_body(body, body_subtype, findings, neutralize_all, per_url)
    intro_text = cfg.external_warning_text if external_warning_triggered else ""
    intro_html = cfg.external_warning_html if external_warning_triggered else ""
    new_raw = build_corrected_eml(
        raw, annotated, findings, smtp_result, sender_lookalike, neutralize_all,
        loop_guard_secret=cfg.loop_guard_secret,
        body_subtype=body_subtype,
        external_warning_text=intro_text,
        external_warning_html=intro_html,
    )

    print(
        f"{log_prefix} rewriting message id={message_id} from={extract_address(from_header)!r} "
        f"warnings={sum(len(f.warnings) for f in findings)}",
        file=sys.stderr,
    )
    new_id = replace_message(client, message_id, new_raw)
    print(f"{log_prefix} done: old_id={message_id} new_id={new_id}", file=sys.stderr)
    return True, findings, new_id
