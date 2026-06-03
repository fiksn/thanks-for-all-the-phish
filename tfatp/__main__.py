import sys

from tfatp.client import GmailClient, Message
from tfatp.config import load_config
from tfatp.dkim_verify import verify as verify_dkim
from tfatp.idle_watcher import IdleWatcher
from tfatp.link_analysis import analyze, annotate, message_body_text
from tfatp.lookalike import check as check_lookalike
from tfatp.rewriter import extract_address, maybe_rewrite_new_mail
from tfatp.smtp_verify import verify_sender
from tfatp.watcher import MailWatcher


def _print_message(prefix: str, client: GmailClient, msg: Message) -> None:
    raw = client.get_raw_message(msg.id)
    dkim_result = verify_dkim(raw)
    body = message_body_text(raw)
    findings = analyze(
        body,
        young_domain_days=client.config.young_domain_days,
        raw_rfc822=raw,
    )
    displayed = annotate(body, findings)

    print(f"\n=== {prefix} ===")
    print(f"  id      : {msg.id}")
    print(f"  date    : {msg.date}")
    print(f"  from    : {msg.sender}")
    print(f"  subject : {msg.subject}")
    print(f"  dkim    : {dkim_result.status} ({dkim_result.detail})")

    sender = extract_address(msg.sender)
    if sender and client.config.smtp_verify:
        smtp = verify_sender(sender, client.user, client.config.domain)
        print(f"  smtp    : {smtp.status} ({smtp.detail})")
    if sender and "@" in sender and "@" in client.user:
        la = check_lookalike(
            sender.split("@", 1)[1],
            client.user.split("@", 1)[1],
            max_distance=client.config.sender_lookalike_max_distance,
        )
        if la.matched:
            print(f"  lookalike: {la.detail}")

    if findings:
        print("  links   :")
        for f in findings:
            age = f"{f.age_days}d" if f.age_days is not None else "unknown"
            flags = ", ".join(f.warnings) if f.warnings else "ok"
            print(f"    - {f.url}  (domain={f.domain}, age={age}, {flags})")

    print("  --- body ---")
    print(displayed.strip() or msg.snippet)
    print("  ------------")


def main(argv: list[str]) -> int:
    args = argv[1:]
    mode = "idle"
    cfg_path = "config.toml"
    for a in args:
        if a in ("--idle", "--poll"):
            mode = a[2:]
        else:
            cfg_path = a

    cfg = load_config(cfg_path)
    print(f"[tfatp] auth_mode={cfg.auth_mode} user={cfg.user} domain={cfg.domain} watcher={mode}")

    client = GmailClient(cfg)

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
