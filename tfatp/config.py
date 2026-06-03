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
)
_DEFAULT_CHECK_PHASES: tuple[tuple[str, ...], ...] = (
    ("sender_domain_age", "sender_lookalike"),
    ("smtp_verify",),
    ("check_link_domain_age", "check_link_lookalike"),
    ("check_password_form",),
)
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


def _check_phases(value: object) -> tuple[tuple[str, ...], ...]:
    if value is None:
        return _DEFAULT_CHECK_PHASES
    if not isinstance(value, list) or not all(isinstance(p, list) for p in value):
        raise ValueError("check_phases must be a list of lists, e.g. [[\"a\",\"b\"],[\"c\"]]")
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
                raise ValueError(f"check stage {stage!r} appears in multiple phases")
            seen.add(stage)
            stages.append(stage)
        phases.append(tuple(stages))
    return tuple(phases)


def _loop_guard_secret(value: object, *, auto_rewrite: bool) -> str:
    """The rewrite pipeline needs a per-mailbox secret so it can stamp inserted
    copies with an HMAC that the watcher recognizes as its own. A header-only
    marker would be trivially forged by any sender — the secret is what binds
    the marker to *this* installation. Required iff auto_rewrite is on.
    """
    secret = str(value or "").strip()
    if auto_rewrite and len(secret) < 16:
        raise ValueError(
            "loop_guard_secret must be set to at least 16 characters when "
            "auto_rewrite is true (used as the HMAC key that recognizes our "
            "own rewritten messages). Generate one with either "
            "`openssl rand -base64 32` or "
            "`python -c 'import secrets;print(secrets.token_urlsafe(32))'`."
        )
    return secret


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
    sender_lookalike_max_distance: int
    sender_min_domain_age_days: int
    check_phases: tuple[tuple[str, ...], ...]
    auto_rewrite: bool
    loop_guard_secret: str
    rewrite_only_from: tuple[str, ...]
    admin_user: str
    pubsub_project_id: str
    pubsub_topic: str
    pubsub_subscription: str


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
        sender_lookalike_max_distance=int(raw.get("sender_lookalike_max_distance", 2)),
        sender_min_domain_age_days=int(
            raw.get("sender_min_domain_age_days", 365)
        ),
        check_phases=_check_phases(raw.get("check_phases")),
        auto_rewrite=_bool(raw.get("auto_rewrite", False), "auto_rewrite"),
        loop_guard_secret=_loop_guard_secret(
            raw.get("loop_guard_secret", ""),
            auto_rewrite=_bool(raw.get("auto_rewrite", False), "auto_rewrite"),
        ),
        rewrite_only_from=tuple(raw.get("rewrite_only_from", []) or []),
        admin_user=str(raw.get("admin_user", "") or ""),
        pubsub_project_id=str(raw.get("pubsub_project_id", "") or ""),
        pubsub_topic=str(raw.get("pubsub_topic", "") or ""),
        pubsub_subscription=str(raw.get("pubsub_subscription", "") or ""),
    )
