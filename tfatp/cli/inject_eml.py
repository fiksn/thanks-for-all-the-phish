"""Inject a raw .eml into the configured Gmail mailbox.

Simulates the arrival of a message: the bytes are pushed straight to
`users.messages.insert` with the INBOX and UNREAD labels, mirroring the way
SMTP-delivered mail lands. Useful for end-to-end testing of the analyzer
without involving any real sender or MX. Nothing is sent over SMTP — the
message materializes inside the recipient's mailbox only.

Usage:
    cat suspicious.eml | python -m tfatp.cli.inject_eml
    python -m tfatp.cli.inject_eml suspicious.eml
    python -m tfatp.cli.inject_eml suspicious.eml --label-id SPAM --no-unread
    python -m tfatp.cli.inject_eml suspicious.eml --as alice@example.com  # DWD only
    python -m tfatp.cli.inject_eml suspicious.eml --dry-run

Insert is the default — the operation is non-destructive (purely additive)
and the injected message can be deleted manually if unwanted. Use --dry-run
to print the plan to stderr without contacting Gmail.
"""

import argparse
import email
import sys
from email import policy
from email.utils import formatdate

from tfatp.client import GmailClient
from tfatp.config import load_config


def _read_input(path: str | None) -> bytes:
    if path and path != "-":
        with open(path, "rb") as f:
            return f.read()
    return sys.stdin.buffer.read()


def _bump_date(raw: bytes) -> bytes:
    """Rewrite the Date: header to now. internalDateSource="dateHeader" then
    places the injected message at the top of the inbox view — convenient when
    you're staring at the UI to verify a flow. Detection is unaffected either
    way (watchers key off historyId / UID, not Date)."""
    msg = email.message_from_bytes(raw, policy=policy.default)
    if "Date" in msg:
        del msg["Date"]
    msg["Date"] = formatdate(localtime=True)
    return bytes(msg)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "path", nargs="?",
        help="Path to .eml file. Omit or use '-' to read from stdin.",
    )
    p.add_argument("--config", default="config.toml", help="Path to config.toml.")
    p.add_argument(
        "--as", dest="as_user", default="",
        help="Inject into this user's mailbox via domain-wide delegation "
        "(requires service_account auth_mode). Defaults to config.user.",
    )
    p.add_argument(
        "--label-id", action="append", default=[],
        help="Additional Gmail label id to apply. Repeatable. "
        "INBOX is always added unless --no-inbox.",
    )
    p.add_argument(
        "--no-inbox", action="store_true",
        help="Do not apply the INBOX label.",
    )
    p.add_argument(
        "--no-unread", action="store_true",
        help="Do not apply the UNREAD label (default applies it).",
    )
    p.add_argument(
        "--bump-date", action="store_true",
        help="Rewrite the Date: header to now before inserting, so the "
        "message lands at the top of the inbox view. Detection fires either "
        "way; this is purely cosmetic.",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Print the insertion plan to stderr without contacting Gmail.",
    )
    args = p.parse_args(argv)

    raw = _read_input(args.path)
    if not raw.strip():
        print("error: empty input — pipe an .eml or pass a path", file=sys.stderr)
        return 2
    if args.bump_date:
        raw = _bump_date(raw)

    labels: list[str] = list(args.label_id)
    if not args.no_inbox and "INBOX" not in labels:
        labels.append("INBOX")
    if not args.no_unread and "UNREAD" not in labels:
        labels.append("UNREAD")

    cfg = load_config(args.config)
    client = (
        GmailClient.for_user(cfg, args.as_user) if args.as_user else GmailClient(cfg)
    )

    if args.dry_run:
        print(
            f"[dry-run] would insert {len(raw)} bytes into user={client.user} "
            f"with labels={labels}.",
            file=sys.stderr,
        )
        return 0

    new_id = client.insert_message(raw, label_ids=labels)
    print(new_id)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
