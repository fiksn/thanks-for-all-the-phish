"""Configurable policy controlling when URLs get defanged in displayed bodies.

Each check answers the question "what does this trigger do?" with one of:

    "no"   — disable the check entirely
    "yes"  — defang only the URL that tripped the check (per-link)
    "all"  — escalate: defang every URL in the body (message-level)

For SMTP failure there is no specific URL to point at, so "yes" is treated
the same as "all" — the only meaningful distinction is on/off.
"""

from dataclasses import dataclass, fields

from tfatp.link_analysis import (
    AttachmentIssue,
    LinkFinding,
    LinkLookalike,
    LinkTextMismatch,
    PasswordForm,
    SenderDomainAge,
    YoungDomain,
)
from tfatp.lookalike import LookalikeResult
from tfatp.smtp_verify import SmtpVerifyResult

Action = str  # one of "no" | "yes" | "all"
_VALID = ("no", "yes", "all")


def validate(value: str, field: str) -> Action:
    v = (value or "").lower().strip()
    if v not in _VALID:
        raise ValueError(
            f"{field} must be one of {_VALID!r}, got {value!r}"
        )
    return v


@dataclass(frozen=True, slots=True)
class DefangPolicy:
    on_smtp_fail: Action = "all"
    on_password_form: Action = "all"
    on_sender_lookalike: Action = "all"
    on_sender_young_domain: Action = "all"
    on_young_domain: Action = "yes"
    on_link_lookalike: Action = "all"
    on_anchor_deception: Action = "yes"
    on_macro: Action = "all"
    on_external_warning: Action = "no"

    def __post_init__(self) -> None:
        # Canonicalize every field so callers can compare against literal
        # "no"/"yes"/"all" without worrying about case or whitespace, and
        # invalid values fail loud at construction time instead of silently
        # bypassing checks downstream.
        for f in fields(self):
            normalized = validate(getattr(self, f.name), f.name)
            object.__setattr__(self, f.name, normalized)


def _triggers_for(f: LinkFinding, policy: DefangPolicy) -> list[Action]:
    """Return the policy actions activated by each warning on this finding."""
    actions: list[Action] = []
    for w in f.warnings:
        if isinstance(w, PasswordForm) and policy.on_password_form != "no":
            actions.append(policy.on_password_form)
        elif isinstance(w, SenderDomainAge) and policy.on_sender_young_domain != "no":
            actions.append(policy.on_sender_young_domain)
        elif isinstance(w, YoungDomain) and policy.on_young_domain != "no":
            actions.append(policy.on_young_domain)
        elif isinstance(w, LinkLookalike) and policy.on_link_lookalike != "no":
            actions.append(policy.on_link_lookalike)
        elif isinstance(w, LinkTextMismatch) and policy.on_anchor_deception != "no":
            actions.append(policy.on_anchor_deception)
        elif (
            isinstance(w, AttachmentIssue)
            and w.kind in {"macro", "bomb", "encrypted"}
            and policy.on_macro != "no"
        ):
            actions.append(policy.on_macro)
    return actions


def compute(
    findings: list[LinkFinding],
    smtp_result: SmtpVerifyResult | None,
    sender_lookalike: LookalikeResult | None,
    policy: DefangPolicy,
    *,
    external_warning: bool = False,
) -> tuple[bool, set[str]]:
    """Return (neutralize_all, per_url_to_defang).

    If neutralize_all is True the caller should defang the whole body; the
    set is empty. Otherwise the set contains the specific URLs that should
    be defanged.
    """
    escalate = (
        policy.on_smtp_fail in ("yes", "all")
        and smtp_result is not None
        and not smtp_result.ok
    ) or (
        policy.on_sender_lookalike in ("yes", "all")
        and sender_lookalike is not None
        and sender_lookalike.matched
    ) or (
        # External-sender warning has no specific URL — both "yes" and "all"
        # behave like "all" (whole body defanged), same as on_smtp_fail.
        policy.on_external_warning in ("yes", "all")
        and external_warning
    )
    per_url: set[str] = set()
    for f in findings:
        for action in _triggers_for(f, policy):
            if action == "all":
                escalate = True
            elif action == "yes":
                per_url.add(f.url)
    if escalate:
        return True, set()
    return False, per_url
