"""Watch every user in a Workspace domain (DWD).

Strategy:
1. Enumerate users via Admin SDK Directory API.
2. Try Cloud Pub/Sub: call users.watch(...) per user. Users where watch is
   forbidden are queued for polling.
3. If at least one user has Pub/Sub, run the PubSubWatcher in the main thread
   and a DomainPollingWatcher in a background thread for the rejected ones.
4. If Pub/Sub config is missing, or every watch was denied, fall back entirely
   to the polling loop.

For each new message we print a one-line summary and call
`maybe_rewrite_new_mail`, which is itself gated by config.rewrite_only_from
(empty list disables rewriting; [".*"] enables it for every sender).
"""

import argparse
import sys
import threading

from googleapiclient.errors import HttpError

from tfatp.client import GmailClient
from tfatp.config import load_config
from tfatp.directory import list_workspace_users
from tfatp.domain_watcher import DomainPollingWatcher
from tfatp.rewriter import maybe_rewrite_new_mail


def _on_new_mail(client: GmailClient, message_id: str) -> None:
    try:
        msg = client.get_message(message_id)
        print(
            f"[mail] user={client.user} id={message_id} "
            f"from={msg.sender!r} subject={msg.subject!r}"
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[mail] fetch failed user={client.user} id={message_id}: {exc!r}")
    try:
        maybe_rewrite_new_mail(client, message_id)
    except Exception as exc:  # noqa: BLE001
        print(f"[rewrite] failed for id={message_id}: {exc!r}")


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--config", default="config.toml")
    p.add_argument(
        "--force-polling",
        action="store_true",
        help="Skip Pub/Sub even if configured; useful for testing the fallback.",
    )
    args = p.parse_args(argv)

    cfg = load_config(args.config)
    if cfg.auth_mode != "service_account":
        print("error: watch_domain requires auth_mode='service_account' (DWD).",
              file=sys.stderr)
        return 2

    try:
        users = list_workspace_users(cfg)
    except HttpError as exc:
        print(f"error: directory listing failed ({exc}). Check admin_user and the "
              f"admin.directory.user.readonly DWD scope.", file=sys.stderr)
        return 2

    print(f"[domain] discovered {len(users)} user(s) in {cfg.domain}")

    pubsub_configured = bool(
        cfg.pubsub_project_id and cfg.pubsub_topic and cfg.pubsub_subscription
    )
    if args.force_polling or not pubsub_configured:
        if pubsub_configured:
            print("[domain] --force-polling set; ignoring Pub/Sub config")
        else:
            print("[domain] Pub/Sub not configured; using polling loop")
        DomainPollingWatcher(cfg, users=users).run(_on_new_mail)
        return 0

    # Try Pub/Sub for everyone; collect rejections.
    from tfatp.pubsub_watcher import PubSubWatcher
    pw = PubSubWatcher(cfg, users=users)
    try:
        watched, unwatched = pw.install_watches()
    except HttpError as exc:
        print(f"[domain] Pub/Sub watch setup failed ({exc}); falling back to polling")
        DomainPollingWatcher(cfg, users=users).run(_on_new_mail)
        return 0

    if not watched:
        print("[domain] no user could be watched via Pub/Sub; falling back to polling")
        DomainPollingWatcher(cfg, users=users).run(_on_new_mail)
        return 0

    # Mixed: Pub/Sub for `watched`, polling thread for `unwatched`.
    if unwatched:
        print(f"[domain] {len(unwatched)} user(s) on polling fallback: {unwatched}")
        poller = DomainPollingWatcher(cfg, users=unwatched)
        threading.Thread(
            target=poller.run, args=(_on_new_mail,), daemon=True
        ).start()

    pw.run(_on_new_mail, watched_users=watched)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
