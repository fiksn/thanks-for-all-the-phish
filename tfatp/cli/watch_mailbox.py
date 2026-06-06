import dataclasses
import sys

from tfatp.client import GmailClient, Message
from tfatp.config import load_config
from tfatp.dkim_verify import verify as verify_dkim
from tfatp.idle_watcher import IdleWatcher
from tfatp.link_analysis import analyze, annotate, message_body_text
from tfatp.rewriter import maybe_rewrite_new_mail
from tfatp.smtp_verify import can_smtp_callout
from tfatp.watcher import MailWatcher


def _print_message(prefix: str, client: GmailClient, msg: Message) -> None:
    """Print metadata + per-link findings to stdout. Body content is *not*
    echoed: a watcher daemon writes to whatever stdout the operator pointed
    it at, often a long-lived log file with weaker access controls than the
    mailbox itself. Leaking message bodies there would re-expose every
    rewritten phish (and every legitimate mail it processed alongside) to
    anyone with read on the log.
    """
    raw = client.get_raw_message(msg.id)
    dkim_result = verify_dkim(raw)
    body = message_body_text(raw)
    findings = analyze(
        body,
        young_domain_days=client.config.young_domain_days,
        raw_rfc822=raw,
    )

    print(f"\n=== {prefix} ===")
    print(f"  id      : {msg.id}")
    print(f"  date    : {msg.date}")
    print(f"  from    : {msg.sender}")
    print(f"  subject : {msg.subject}")
    print(f"  dkim    : {dkim_result.status} ({dkim_result.detail})")

    if findings:
        print("  links   :")
        for f in findings:
            age = f"{f.age_days}d" if f.age_days is not None else "unknown"
            flags = ", ".join(str(w) for w in f.warnings) if f.warnings else "ok"
            print(f"    - {f.url}  (domain={f.domain}, age={age}, {flags})")
    print(f"  body    : {len(body)} chars (not shown)")


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
            _print_message("BACKFILL", client, msg)
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
        _print_message("NEW MAIL", client, msg)
        # Best-effort: any failure here must not crash the watcher loop.
        try:
            maybe_rewrite_new_mail(client, msg.id)
        except Exception as exc:  # noqa: BLE001
            print(f"[rewrite] failed for id={msg.id}: {exc!r}")

    watcher.run()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
