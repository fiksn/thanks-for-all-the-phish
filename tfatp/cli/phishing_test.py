"""Inject the same .eml into every workspace user's mailbox (DWD).

A bulk version of `inject_eml`: read one phishing-test .eml, list users in
the workspace via the Admin SDK, filter with include/exclude regexes, and
insert the message into each remaining user's mailbox via domain-wide
delegation. Use this to run scheduled phish drills, validate the rewrite
pipeline across the org, or simulate a campaign without involving SMTP.

Filter semantics match the DWD watcher: empty include = every user; non-
empty include narrows the set; exclude trims what's left. CLI flags
override the matching settings in config.toml when provided; otherwise
the config defaults apply.

Usage:
    python -m tfatp.cli.phishing_test suspicious.eml
    cat suspicious.eml | python -m tfatp.cli.phishing_test
    python -m tfatp.cli.phishing_test suspicious.eml \\
        --include '.*@finance\\.example\\.com' --exclude 'cfo@.*'
    python -m tfatp.cli.phishing_test suspicious.eml --dry-run
    python -m tfatp.cli.phishing_test suspicious.eml --limit 5 --bump-date

The operation is purely additive — injected messages can be deleted later
if unwanted — but landing it in many mailboxes at once is a high-impact
event. Always run with `--dry-run` first to confirm the user list.
"""

import argparse
import sys

from googleapiclient.errors import HttpError

from tfatp.cli.inject_eml import _bump_date, _read_input
from tfatp.client import GmailClient
from tfatp.config import load_config
from tfatp.directory import filter_users, list_workspace_users


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(__doc__.splitlines()[2:]),
    )
    p.add_argument(
        "path", nargs="?",
        help="Path to .eml file. Omit or use '-' to read from stdin.",
    )
    p.add_argument("--config", default="config.toml", help="Path to config.toml.")
    p.add_argument(
        "--include", action="append", default=[],
        help="Regex matched (re.fullmatch, case-insensitive) against each user's "
        "primary email. Repeatable. Overrides include_users in config when given.",
    )
    p.add_argument(
        "--exclude", action="append", default=[],
        help="Regex matched against each user's primary email. Repeatable. "
        "Overrides exclude_users in config when given.",
    )
    p.add_argument(
        "--label-id", action="append", default=[],
        help="Additional Gmail label id to apply. Repeatable.",
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
        help="Rewrite the Date: header to now so the injected mail lands at "
        "the top of each inbox.",
    )
    p.add_argument(
        "--limit", type=int, default=0,
        help="Stop after injecting into N users (0 = all). Useful for "
        "incremental rollout.",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="List the matched users and what would be inserted, contact "
        "no mailbox. Run this first.",
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
    if cfg.auth_mode != "service_account":
        print(
            "error: phishing_test requires auth_mode='service_account' (DWD).",
            file=sys.stderr,
        )
        return 2

    # CLI patterns override config; missing CLI flag falls back to config.
    include = tuple(p.lower() for p in args.include) or cfg.include_users
    exclude = tuple(p.lower() for p in args.exclude) or cfg.exclude_users

    try:
        users = list_workspace_users(cfg)
    except HttpError as exc:
        print(
            f"error: directory listing failed ({exc}). Check admin_user and the "
            f"admin.directory.user.readonly DWD scope.",
            file=sys.stderr,
        )
        return 2

    filtered = filter_users(users, include=include, exclude=exclude)
    if args.limit and len(filtered) > args.limit:
        filtered = filtered[: args.limit]

    if not filtered:
        print(
            "error: no users matched after include/exclude. Adjust filters.",
            file=sys.stderr,
        )
        return 2

    print(
        f"[phish-test] {len(filtered)} of {len(users)} user(s) "
        f"in {cfg.domain} matched (labels={labels}, bytes={len(raw)})",
        file=sys.stderr,
    )

    if args.dry_run:
        for u in filtered:
            print(f"[dry-run] {u}")
        return 0

    failures: list[tuple[str, str]] = []
    for u in filtered:
        try:
            client = GmailClient.for_user(cfg, u)
            new_id = client.insert_message(raw, label_ids=labels)
        except Exception as exc:  # noqa: BLE001 — keep going across users
            print(f"[phish-test] FAILED {u}: {exc!r}", file=sys.stderr)
            failures.append((u, repr(exc)))
            continue
        print(f"{u} {new_id}")

    if failures:
        print(
            f"[phish-test] done with {len(failures)} failure(s) of {len(filtered)}",
            file=sys.stderr,
        )
        return 1
    print(
        f"[phish-test] done — {len(filtered)} mailbox(es) injected",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
