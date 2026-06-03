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
    """True if the empty allowlist (= any sender) or the From address matches."""
    if not allowlist:
        return True
    addr = extract_address(from_header)
    return addr in {a.strip().lower() for a in allowlist}
