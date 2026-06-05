"""Show what tfatp did to a Gmail message.

Downloads a message by id, verifies it carries the tfatp marker header,
extracts the embedded original.eml attachment, verifies its DKIM signature,
and prints the diff between the original body and the current (rewritten)
body (with the embedded original.eml attachment excluded from the comparison).

Usage:
    python -m tfatp.cli.diff_message <message-id>
    python -m tfatp.cli.diff_message <message-id> --as alice@example.com  # DWD only

The diff is always shown when an original.eml is present; the exit code reflects
DKIM trust so scripts can gate on it.

Exit codes:
    0 — diff produced, DKIM on original.eml passed
    1 — message exists but was not processed by tfatp
    2 — processed but the embedded original.eml is missing / unreadable
    3 — diff produced, but DKIM on original.eml did not pass (untrusted)
"""

import argparse
import difflib
import email
import sys
from email import policy
from email.message import Message

from tfatp import loop_guard
from tfatp.client import GmailClient
from tfatp.config import load_config
from tfatp.dkim_verify import verify as verify_dkim


def _find_original_attachment(msg: Message) -> bytes | None:
    """Return the raw bytes of the embedded message/rfc822 part named original.eml."""
    for part in msg.walk():
        if part.get_content_type() != "message/rfc822":
            continue
        filename = (part.get_filename() or "").lower()
        if filename and filename != "original.eml":
            continue
        payload = part.get_payload()
        if isinstance(payload, list) and payload:
            inner = payload[0]
            if isinstance(inner, Message):
                return bytes(inner)
        if isinstance(payload, bytes):
            return payload
        if isinstance(payload, str):
            return payload.encode("utf-8", errors="ignore")
    return None


def _strip_original_attachment(raw: bytes) -> Message:
    """Return the rewritten message with its original.eml attachment removed."""
    msg = email.message_from_bytes(raw, policy=policy.default)
    if not msg.is_multipart():
        return msg
    payload = msg.get_payload()
    if not isinstance(payload, list):
        return msg
    filtered = [
        part for part in payload
        if not (
            part.get_content_type() == "message/rfc822"
            and (part.get_filename() or "").lower() == "original.eml"
        )
    ]
    msg.set_payload(filtered)
    return msg


def _text_body(msg: Message) -> str:
    """Pick the best textual representation: prefer text/plain, fall back to text/html."""
    if not msg.is_multipart():
        if msg.get_content_maintype() == "text":
            return msg.get_content()
        return ""
    plain = ""
    html = ""
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain" and not plain:
            plain = part.get_content()
        elif ctype == "text/html" and not html:
            html = part.get_content()
    return plain or html


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(__doc__.splitlines()[2:]),
    )
    p.add_argument("message_id",
                   help="Gmail hex id (as the watcher prints) or RFC 822 Message-ID "
                        "(e.g. <abc@mail.gmail.com>, with or without angle brackets).")
    p.add_argument("--as", dest="subject", default=None,
                   help="Impersonate this user (service_account / DWD only).")
    p.add_argument("--config", default="config.toml", help="Path to config.toml.")
    args = p.parse_args(argv)

    cfg = load_config(args.config)
    client = (
        GmailClient.for_user(cfg, args.subject) if args.subject
        else GmailClient(cfg)
    )

    try:
        message_id = client.resolve_message_id(args.message_id)
    except LookupError as exc:
        print(f"ERROR — {exc}")
        return 1
    if message_id != args.message_id:
        print(f"resolved Message-ID → hex id {message_id}")
    raw = client.get_raw_message(message_id)
    current = email.message_from_bytes(raw, policy=policy.default)

    checked_by = (current.get(loop_guard.HEADER_CHECKED_BY, "") or "").strip().lower()
    if checked_by != loop_guard.X_CHECKED_BY:
        print(f"NOT PROCESSED — message {message_id} has no "
              f"'{loop_guard.HEADER_CHECKED_BY}: {loop_guard.X_CHECKED_BY}' header.")
        return 1
    print(f"processed by tfatp — {loop_guard.HEADER_CHECKED_BY}: {checked_by}")

    if cfg.loop_guard_secret:
        if loop_guard.is_own_rewrite(current, cfg.loop_guard_secret):
            print(f"{loop_guard.HEADER_MAC}: valid HMAC")
        else:
            print(f"{loop_guard.HEADER_MAC}: MISSING or INVALID for current secret")

    original_bytes = _find_original_attachment(current)
    if original_bytes is None:
        print("ERROR — no message/rfc822 attachment named original.eml found.")
        return 2
    print(f"original.eml: {len(original_bytes)} bytes")

    dkim_res = verify_dkim(original_bytes)
    print(f"DKIM on original: {dkim_res.status} ({dkim_res.detail})")
    if not dkim_res.ok:
        print("WARNING — DKIM on original.eml did not pass; diff below is UNTRUSTED.")

    original = email.message_from_bytes(original_bytes, policy=policy.default)
    stripped_current = _strip_original_attachment(raw)

    print()
    print("--- headers added by tfatp ---")
    orig_header_keys = {k.lower() for k in original.keys()}
    for k, v in stripped_current.items():
        kl = k.lower()
        if kl.startswith("x-checked-") or kl not in orig_header_keys:
            print(f"  + {k}: {v}")

    orig_text = _text_body(original)
    new_text = _text_body(stripped_current)

    print()
    print("--- body diff (original → rewritten, excluding original.eml attachment) ---")
    diff = list(difflib.unified_diff(
        orig_text.splitlines(keepends=True),
        new_text.splitlines(keepends=True),
        fromfile="original",
        tofile=f"id={args.message_id}",
        n=3,
    ))
    if not diff:
        print("(no body changes)")
    else:
        sys.stdout.writelines(diff)
        if diff and not diff[-1].endswith("\n"):
            print()
    return 0 if dkim_res.ok else 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
