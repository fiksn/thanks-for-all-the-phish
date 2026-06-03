"""Manually replace a Gmail message by id with a rewritten copy from stdin.

Usage:
    python -m tfatp.cli.analyze_eml < original.eml > corrected.eml
    python -m tfatp.cli.replace_message <message-id> < corrected.eml

Requires `--yes` to actually delete. Without it, prints a dry-run plan only.
"""

import argparse
import sys

from tfatp.client import GmailClient
from tfatp.config import load_config
from tfatp.rewriter import replace_message


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("message_id", help="Gmail message id to delete and replace.")
    p.add_argument("--config", default="config.toml", help="Path to config.toml.")
    p.add_argument(
        "--yes", action="store_true",
        help="Actually perform the delete + insert (otherwise dry-run only).",
    )
    args = p.parse_args(argv)

    cfg = load_config(args.config)
    new_raw = sys.stdin.buffer.read()
    if not new_raw.strip():
        print("error: empty stdin — pipe a corrected .eml in", file=sys.stderr)
        return 2

    client = GmailClient(cfg)

    if not args.yes:
        print(
            f"[dry-run] would delete id={args.message_id} as user={client.user} "
            f"then insert {len(new_raw)} bytes. Re-run with --yes to commit.",
            file=sys.stderr,
        )
        return 0

    new_id = replace_message(client, args.message_id, new_raw)
    print(new_id)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
