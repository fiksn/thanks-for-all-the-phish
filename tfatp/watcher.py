import time
from collections.abc import Callable

from tfatp.client import GmailClient, Message

NewMailHook = Callable[[Message], None]


class MailWatcher:
    def __init__(self, client: GmailClient, poll_interval: int = 15) -> None:
        self._client = client
        self._poll_interval = poll_interval
        self._hooks: list[NewMailHook] = []

    def on_new_mail(self, hook: NewMailHook) -> NewMailHook:
        """Register a callback invoked once per newly arrived message.

        Usable as a decorator:

            @watcher.on_new_mail
            def notify(msg): ...
        """
        self._hooks.append(hook)
        return hook

    def _emit(self, msg: Message) -> None:
        for hook in self._hooks:
            try:
                hook(msg)
            except Exception as exc:  # noqa: BLE001 — hooks must not kill the watcher
                print(f"[watcher] hook {hook.__name__} raised: {exc!r}")

    def run(self) -> None:
        history_id = self._client.current_history_id()
        print(f"[watcher] starting at historyId={history_id}, polling every {self._poll_interval}s")
        while True:
            try:
                new_ids, history_id = self._client.history_since(history_id)
                for mid in new_ids:
                    msg = self._client.get_message(mid)
                    self._emit(msg)
            except KeyboardInterrupt:
                print("\n[watcher] stopped")
                return
            except Exception as exc:  # noqa: BLE001
                print(f"[watcher] poll failed: {exc!r}")
            time.sleep(self._poll_interval)
