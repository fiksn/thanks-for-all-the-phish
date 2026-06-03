"""Delete + insert pipeline for replacing a Gmail message with a rewritten copy."""

import email
import sys
from email import policy

from tfatp import loop_guard
from tfatp.addr import extract_address, sender_allowed
from tfatp.analyze_eml import analyze_with_gate, build_corrected_eml
from tfatp.client import GmailClient
from tfatp.defang_policy import DefangPolicy, compute as compute_defang
from tfatp.link_analysis import LinkFinding, annotate, defang, message_body_text

__all__ = ["extract_address", "sender_allowed", "replace_message", "maybe_rewrite_new_mail"]


def replace_message(client: GmailClient, message_id: str, new_raw: bytes) -> str:
    """Permanently delete `message_id` and insert `new_raw`. Returns new id.

    This is destructive — the original is unrecoverable from Trash. The corrected
    message embeds the original as a message/rfc822 attachment, so the content is
    preserved inside the new message.
    """
    new_id = client.insert_message(new_raw)
    # Delete only after insert succeeds, so a failed insert doesn't lose the mail.
    client.delete_message(message_id)
    return new_id


def maybe_rewrite_new_mail(
    client: GmailClient, message_id: str, log_prefix: str = "[rewrite]"
) -> tuple[bool, list[LinkFinding], str | None]:
    """Inspect a freshly-arrived message and, if eligible, replace it in-place.

    Eligibility:
    - config.auto_rewrite must be true
    - From: address must pass the rewrite_only_from allowlist
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
        return False, [], None
    from_header = str(parsed.get("From", ""))

    body = message_body_text(raw)
    # HELO advertises a host on our side: use the domain of the recipient
    # mailbox we just received the message at, not the workspace-config knob.
    helo = client.user.split("@", 1)[1] if "@" in client.user else "localhost"
    findings, smtp_result, sender_lookalike, _sender_age_warning, _enabled, _gate_failed = (
        analyze_with_gate(
            raw,
            mail_from=client.user,
            helo_domain=helo,
            do_smtp_verify=cfg.smtp_verify,
            young_domain_days=cfg.young_domain_days,
            sender_lookalike_max_distance=cfg.sender_lookalike_max_distance,
            sender_min_domain_age_days=cfg.sender_min_domain_age_days,
            check_phases=cfg.check_phases,
        )
    )

    suspicious = (
        any(f.warnings for f in findings)
        or (smtp_result is not None and smtp_result.status == "rejected")
        or (sender_lookalike is not None and sender_lookalike.matched)
    )

    if not suspicious:
        return False, findings, None
    if not cfg.auto_rewrite:
        print(f"{log_prefix} suspicious but auto_rewrite=false; skipping", file=sys.stderr)
        return False, findings, None
    if not sender_allowed(from_header, cfg.rewrite_only_from):
        print(
            f"{log_prefix} suspicious but sender {extract_address(from_header)!r} "
            f"not in rewrite_only_from allowlist; skipping",
            file=sys.stderr,
        )
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
    )
    neutralize_all, per_url = compute_defang(
        findings,
        smtp_result,
        sender_lookalike,
        defang_policy,
    )
    annotated = annotate(body, findings)
    if neutralize_all:
        annotated = defang(annotated)
    else:
        for url in per_url:
            annotated = annotated.replace(url, defang(url))
    new_raw = build_corrected_eml(
        raw, annotated, findings, smtp_result, sender_lookalike, neutralize_all,
        loop_guard_secret=cfg.loop_guard_secret,
    )

    print(
        f"{log_prefix} rewriting message id={message_id} from={extract_address(from_header)!r} "
        f"warnings={sum(len(f.warnings) for f in findings)}",
        file=sys.stderr,
    )
    new_id = replace_message(client, message_id, new_raw)
    print(f"{log_prefix} done: old_id={message_id} new_id={new_id}", file=sys.stderr)
    return True, findings, new_id
