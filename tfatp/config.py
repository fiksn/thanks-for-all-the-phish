import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

AuthMode = Literal["oauth", "service_account"]

_DEFANG_ACTIONS = ("no", "yes", "all")
CHECK_STAGES = (
    "sender_domain_age",
    "sender_lookalike",
    "smtp_verify",
    "check_link_domain_age",
    "check_link_lookalike",
    "check_password_form",
    "external_warning",
)
_DEFAULT_CHECK_PHASES: tuple[tuple[str, ...], ...] = (
    (
        "sender_domain_age", "sender_lookalike",
        "check_link_domain_age", "check_link_lookalike",
    ),
    ("smtp_verify",),
    ("check_password_form",),
)
# For mail whose sender domain is part of the workspace, the checks that
# probe a sender's MX or measure their domain age are pointless — we already
# know who they are. Lookalike checks (sender + link) also collapse to noise
# because the sender domain *is* the protected domain. Default leaves just
# the link-fetch step; ops can extend it via config.
_DEFAULT_CHECK_PHASES_INTERNAL: tuple[tuple[str, ...], ...] = (
    ("check_password_form",),
)
_DEFAULT_EXTERNAL_WARNING_TEXT = (
    "CAUTION: This email originated from outside of the organization. "
    "Do not click links or attachments unless you recognize the sender "
    "and know the content is safe."
)
# Outlook-style banner: pale yellow background, dark text, red "CAUTION:"
# prefix only — matches the appearance users already associate with this
# warning from Exchange.
_DEFAULT_EXTERNAL_WARNING_HTML = (
    '<div style="border:1px solid #d0c47a; background:#fff8c4; padding:10px; '
    'margin:0 0 16px 0; font-family:Roboto,Arial,Helvetica,sans-serif; '
    'font-size:14px; color:#222;">'
    '<span style="color:#c00; font-weight:bold;">CAUTION:</span> '
    "This email originated from outside of the organization. "
    "Do not click links or attachments unless you recognize the sender "
    "and know the content is safe."
    "</div>"
)
# Sender hosts matching any of these regexes (re.fullmatch) skip the
# sender-side checks (sender_domain_age, sender_lookalike, smtp_verify).
# Atlassian cloud tenants send from `*.atlassian.net` subdomains that are
# young and lookalike-ish by construction, so they trip every sender
# heuristic without being malicious.
_DEFAULT_SENDER_WHITELIST: tuple[str, ...] = (r".*\.atlassian\.net",)
_BOOL_STRINGS = {
    "true": True,
    "false": False,
    "yes": True,
    "no": False,
    "1": True,
    "0": False,
}


def _action(value: str | bool, field: str) -> str:
    v = (str(value) or "").lower().strip()
    if v not in _DEFANG_ACTIONS:
        raise ValueError(f"{field} must be one of {_DEFANG_ACTIONS!r}, got {value!r}")
    return v


def _check_phases(
    value: object,
    *,
    field: str = "check_phases",
    default: tuple[tuple[str, ...], ...] = _DEFAULT_CHECK_PHASES,
) -> tuple[tuple[str, ...], ...]:
    if value is None:
        return default
    if not isinstance(value, list) or not all(isinstance(p, list) for p in value):
        raise ValueError(f"{field} must be a list of lists, e.g. [[\"a\",\"b\"],[\"c\"]]")
    seen: set[str] = set()
    phases: list[tuple[str, ...]] = []
    for phase in value:
        stages: list[str] = []
        for stage in phase:
            if stage not in CHECK_STAGES:
                raise ValueError(
                    f"unknown check stage {stage!r}; valid stages: {CHECK_STAGES!r}"
                )
            if stage in seen:
                raise ValueError(f"check stage {stage!r} appears in multiple phases of {field}")
            seen.add(stage)
            stages.append(stage)
        phases.append(tuple(stages))
    return tuple(phases)


def _loop_guard_secret(value: object, *, rewrite_enabled: bool) -> str:
    """The rewrite pipeline needs a per-mailbox secret so it can stamp inserted
    copies with an HMAC that the watcher recognizes as its own. A header-only
    marker would be trivially forged by any sender — the secret is what binds
    the marker to *this* installation. Required when rewriting is enabled
    (i.e. `rewrite_only_from` is non-empty).
    """
    secret = str(value or "").strip()
    if rewrite_enabled and len(secret) < 16:
        raise ValueError(
            "loop_guard_secret must be set to at least 16 characters when "
            "rewrite_only_from is non-empty (used as the HMAC key that "
            "recognizes our own rewritten messages). Generate one with either "
            "`openssl rand -base64 32` or "
            "`python -c 'import secrets;print(secrets.token_urlsafe(32))'`."
        )
    return secret


def _rewrite_only_from(value: object, *, field: str = "rewrite_only_from") -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list of regex strings")
    out: list[str] = []
    for entry in value:
        if not isinstance(entry, str):
            raise ValueError(f"{field} must be a list of regex strings")
        pat = entry.strip()
        if not pat:
            continue
        try:
            re.compile(pat)
        except re.error as exc:
            raise ValueError(f"{field}: invalid regex {pat!r}: {exc}") from exc
        out.append(pat.lower())
    return tuple(out)


def _state_dir(value: object) -> Path:
    """Resolve the per-account state directory.

    A non-empty ``state_dir`` in ``config.toml`` wins. Otherwise we hand
    off to :func:`tfatp.sync_state.default_state_dir`, which prefers the
    ``TFATP_STATE_DIR`` env var (set in the Docker image to
    ``/var/lib/tfatp``) and falls back to XDG.
    """
    from tfatp.sync_state import default_state_dir
    if isinstance(value, str) and value.strip():
        return Path(value.strip())
    return default_state_dir()


def _user_patterns(value: object, *, field: str) -> tuple[str, ...]:
    """Parse a list of email-regex strings, validating each pattern.

    Same shape as ``rewrite_only_from``: every entry is a regex matched
    case-insensitively (we lower-case patterns and emails before fullmatch)
    against the workspace user's primary email. Empty / missing → ``()``.
    """
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list of regex strings")
    out: list[str] = []
    for entry in value:
        if not isinstance(entry, str):
            raise ValueError(f"{field} must be a list of regex strings")
        pat = entry.strip()
        if not pat:
            continue
        try:
            re.compile(pat)
        except re.error as exc:
            raise ValueError(f"{field}: invalid regex {pat!r}: {exc}") from exc
        out.append(pat.lower())
    return tuple(out)


def _sender_whitelist(value: object, *, field: str = "sender_whitelist") -> tuple[str, ...]:
    if value is None:
        return _DEFAULT_SENDER_WHITELIST
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list of regex strings")
    out: list[str] = []
    for entry in value:
        if not isinstance(entry, str):
            raise ValueError(f"{field} must be a list of regex strings")
        pat = entry.strip()
        if not pat:
            continue
        try:
            re.compile(pat)
        except re.error as exc:
            raise ValueError(f"{field}: invalid regex {pat!r}: {exc}") from exc
        out.append(pat.lower())
    return tuple(out)


def _bool(value: object, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.lower().strip()
        if normalized in _BOOL_STRINGS:
            return _BOOL_STRINGS[normalized]
    raise ValueError(f"{field} must be a boolean, got {value!r}")


@dataclass(frozen=True, slots=True)
class Config:
    domain: str
    user: str
    auth_mode: AuthMode
    client_secret_file: Path
    token_file: Path
    service_account_file: Path
    poll_interval: int
    young_domain_days: int
    smtp_verify: bool
    defang_on_smtp_fail: str
    defang_on_password_form: str
    defang_on_sender_lookalike: str
    defang_on_sender_young_domain: str
    defang_on_young_domain: str
    defang_on_link_lookalike: str
    defang_on_anchor_deception: str
    defang_on_macro: str
    defang_on_external: str
    sender_lookalike_max_distance: int
    sender_min_domain_age_days: int
    sender_whitelist: tuple[str, ...]
    check_phases: tuple[tuple[str, ...], ...]
    check_phases_internal: tuple[tuple[str, ...], ...]
    external_warning_text: str
    external_warning_html: str
    defang_url_suffix: str
    loop_guard_secret: str
    rewrite_only_from: tuple[str, ...]
    admin_user: str
    include_users: tuple[str, ...]
    exclude_users: tuple[str, ...]
    state_dir: Path
    pubsub_project_id: str
    pubsub_topic: str
    pubsub_subscription: str
    imap_host: str
    imap_port: int


def load_config(path: str | Path = "config.toml") -> Config:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(
            f"Config file not found at {p}. Copy config.example.toml to config.toml and edit."
        )
    raw = tomllib.loads(p.read_text(encoding="utf-8"))

    auth_mode = raw.get("auth_mode", "oauth")
    if auth_mode not in ("oauth", "service_account"):
        raise ValueError(f"auth_mode must be 'oauth' or 'service_account', got {auth_mode!r}")

    return Config(
        domain=raw["domain"],
        user=raw["user"],
        auth_mode=auth_mode,
        client_secret_file=Path(raw.get("client_secret_file", "client_secret.json")),
        token_file=Path(raw.get("token_file", "token.json")),
        service_account_file=Path(raw.get("service_account_file", "service_account.json")),
        poll_interval=int(raw.get("poll_interval", 15)),
        young_domain_days=int(raw.get("young_domain_days", 365)),
        smtp_verify=_bool(raw.get("smtp_verify", True), "smtp_verify"),
        defang_on_smtp_fail=_action(raw.get("defang_on_smtp_fail", "all"), "defang_on_smtp_fail"),
        defang_on_password_form=_action(
            raw.get("defang_on_password_form", "all"), "defang_on_password_form"
        ),
        defang_on_young_domain=_action(
            raw.get("defang_on_young_domain", "yes"), "defang_on_young_domain"
        ),
        defang_on_anchor_deception=_action(
            raw.get("defang_on_anchor_deception", "yes"), "defang_on_anchor_deception"
        ),
        defang_on_sender_lookalike=_action(
            raw.get("defang_on_sender_lookalike", "all"), "defang_on_sender_lookalike"
        ),
        defang_on_sender_young_domain=_action(
            raw.get("defang_on_sender_young_domain", "all"),
            "defang_on_sender_young_domain",
        ),
        defang_on_link_lookalike=_action(
            raw.get("defang_on_link_lookalike", "all"),
            "defang_on_link_lookalike",
        ),
        defang_on_macro=_action(
            raw.get("defang_on_macro", "all"),
            "defang_on_macro",
        ),
        defang_on_external=_action(
            raw.get("defang_on_external", "no"),
            "defang_on_external",
        ),
        sender_lookalike_max_distance=int(raw.get("sender_lookalike_max_distance", 2)),
        sender_min_domain_age_days=int(
            raw.get("sender_min_domain_age_days", 365)
        ),
        sender_whitelist=_sender_whitelist(raw.get("sender_whitelist")),
        check_phases=_check_phases(raw.get("check_phases")),
        check_phases_internal=_check_phases(
            raw.get("check_phases_internal"),
            field="check_phases_internal",
            default=_DEFAULT_CHECK_PHASES_INTERNAL,
        ),
        external_warning_text=str(
            raw.get("external_warning_text", _DEFAULT_EXTERNAL_WARNING_TEXT)
        ),
        external_warning_html=str(
            raw.get("external_warning_html", _DEFAULT_EXTERNAL_WARNING_HTML)
        ),
        defang_url_suffix=str(
            raw.get("defang_url_suffix", ".REMOVE-TO-VISIT.invalid")
        ),
        loop_guard_secret=_loop_guard_secret(
            raw.get("loop_guard_secret", ""),
            rewrite_enabled=bool(_rewrite_only_from(raw.get("rewrite_only_from"))),
        ),
        rewrite_only_from=_rewrite_only_from(raw.get("rewrite_only_from")),
        admin_user=str(raw.get("admin_user", "") or ""),
        include_users=_user_patterns(raw.get("include_users"), field="include_users"),
        exclude_users=_user_patterns(raw.get("exclude_users"), field="exclude_users"),
        state_dir=_state_dir(raw.get("state_dir")),
        pubsub_project_id=str(raw.get("pubsub_project_id", "") or ""),
        pubsub_topic=str(raw.get("pubsub_topic", "") or ""),
        pubsub_subscription=str(raw.get("pubsub_subscription", "") or ""),
        imap_host=str(raw.get("imap_host", "") or ""),
        imap_port=int(raw.get("imap_port", 0) or 0),
    )
