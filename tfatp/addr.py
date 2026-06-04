"""Tiny address-handling helpers shared across modules."""

import re

_ADDR_RE = re.compile(r"<([^>]+)>")


def extract_address(header_value: str) -> str:
    """Return the bare email address from a header value, lowercased."""
    if not header_value:
        return ""
    m = _ADDR_RE.search(header_value)
    addr = m.group(1) if m else header_value
    return addr.strip().lower()


def sender_allowed(from_header: str, allowlist: tuple[str, ...]) -> bool:
    """Match the From: address against the allowlist of regexes (re.fullmatch).

    Empty allowlist means rewriting is disabled (no sender matches). Use
    `[".*"]` to allow every sender. Patterns are matched against the bare,
    lowercased address.
    """
    if not allowlist:
        return False
    addr = extract_address(from_header)
    if not addr:
        return False
    return any(re.fullmatch(p, addr) for p in allowlist)
