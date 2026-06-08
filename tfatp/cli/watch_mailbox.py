import dataclasses
import email
import sys
from email import policy

from tfatp import loop_guard
from tfatp.client import GmailClient, Message
from tfatp.config import load_config
from tfatp.idle_watcher import IdleWatcher
from tfatp.rewriter import maybe_rewrite_new_mail
from tfatp.smtp_verify import can_smtp_callout
from tfatp.watcher import MailWatcher


def _print_message(prefix: str, client: GmailClient, msg: Message) -> bool:
    """Identity-only watcher log: print the message's From / Subject /
    Message-Id / Date / Gmail id. Returns True if the caller should
    continue with the rewriter, False if the message is our own rewrite
    and should be skipped end-to-end.

    Detection-side noise (DKIM verdict, link findings, phase outcomes)
    is the rewriter's job; surfacing it here too just doubled the API
    calls and the cognitive load. The rewritten message carries the same
    information in `X-Checked-*` headers and in the banner.
    """
    # Loop-guard FIRST. Skipping our own rewrites before the rewriter call
    # avoids re-fetching the raw bytes there and keeps the log honest —
    # "own rewrite, skipped" rather than treating it as fresh inbound.
    raw = client.get_raw_message(msg.id)
    parsed = email.message_from_bytes(raw, policy=policy.default)
    if loop_guard.is_own_rewrite(parsed, client.config.loop_guard_secret):
        print(f"[tfatp] {prefix}: own rewrite (id={msg.id}), skipped")
        return False

    print(f"\n=== {prefix} ===")
    print(f"  id      : {msg.id}")
    if msg.message_id:
        print(f"  mid     : {msg.message_id}")
    if msg.date:
        print(f"  date    : {msg.date}")
    print(f"  from    : {msg.sender}")
    print(f"  subject : {msg.subject}")
    return True


def main(argv: list[str]) -> int:
    args = argv[1:]
    mode = "idle"
    cfg_path = "config.toml"
    backfill = 0
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--idle", "--poll"):
            mode = a[2:]
        elif a == "--rewrite-latest":
            i += 1
            if i >= len(args):
                print("[tfatp] --rewrite-latest needs a count", file=sys.stderr)
                return 2
            backfill = int(args[i])
        elif a.startswith("--rewrite-latest="):
            backfill = int(a.split("=", 1)[1])
        else:
            cfg_path = a
        i += 1

    cfg = load_config(cfg_path)
    print(f"[tfatp] auth_mode={cfg.auth_mode} user={cfg.user} domain={cfg.domain} watcher={mode}")

    smtp_in_phases = any(
        "smtp_verify" in phase
        for phase in (*cfg.check_phases, *cfg.check_phases_internal)
    )
    if cfg.smtp_verify and smtp_in_phases:
        reachable, detail = can_smtp_callout()
        if reachable:
            print(f"[tfatp] smtp connectivity: ok on ports {sorted(reachable)}")
        else:
            print(
                f"[tfatp] outbound SMTP does not appear to work from this host "
                f"({detail}); disabling smtp_verify for this run. "
                "Set smtp_verify=false in config.toml to silence this."
            )
            cfg = dataclasses.replace(cfg, smtp_verify=False)

    client = GmailClient(cfg)

    if backfill > 0:
        ids = client.list_message_ids(max_results=backfill)
        print(f"[tfatp] backfilling {len(ids)} latest message(s) through the rewrite pipeline")
        for mid in ids:
            msg = client.get_message(mid)
            print(f"[tfatp] processing id={msg.id} from={msg.sender!r} subject={msg.subject!r}")
            if not _print_message("BACKFILL", client, msg):
                # Own rewrite — `_print_message` already reported it. Skip
                # the rewriter call so we don't repeat the loop-guard work
                # on the rewriter side.
                continue
            try:
                maybe_rewrite_new_mail(client, msg.id)
            except Exception as exc:  # noqa: BLE001
                print(f"[rewrite] failed for id={msg.id}: {exc!r}")
    else:
        latest = client.latest_message()
        if latest is None:
            print("[tfatp] mailbox is empty")
        else:
            _print_message("latest message", client, latest)

    if mode == "idle":
        idle = IdleWatcher(client)
        ok, detail = idle.probe()
        if ok:
            watcher: IdleWatcher | MailWatcher = idle
        else:
            print(
                f"[tfatp] IMAP IDLE unavailable ({detail}); falling back to history polling. "
                f"Enable IMAP at Settings → Forwarding and POP/IMAP to use IDLE."
            )
            watcher = MailWatcher(client, poll_interval=cfg.poll_interval)
    else:
        watcher = MailWatcher(client, poll_interval=cfg.poll_interval)

    @watcher.on_new_mail
    def show(msg: Message) -> None:
        print(f"[tfatp] processing id={msg.id} from={msg.sender!r} subject={msg.subject!r}")
        if not _print_message("NEW MAIL", client, msg):
            return
        # Best-effort: any failure here must not crash the watcher loop.
        try:
            maybe_rewrite_new_mail(client, msg.id)
        except Exception as exc:  # noqa: BLE001
            print(f"[rewrite] failed for id={msg.id}: {exc!r}")

    watcher.run()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
