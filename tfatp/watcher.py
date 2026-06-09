import time
from collections.abc import Callable

from tfatp.client import GmailClient, Message

NewMailHook = Callable[[Message], None]


class MailWatcher:
    def __init__(
        self,
        client: GmailClient,
        poll_interval: int = 15,
        initial_history_id: str | None = None,
    ) -> None:
        self._client = client
        self._poll_interval = poll_interval
        self._initial_history_id = initial_history_id
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
        # Resume from the persisted watermark when one was passed in; fall
        # back to the live current historyId otherwise. We try the stored
        # id first and let `history_since` decide whether it's still
        # valid — Gmail returns a clear error when the cursor has expired.
        history_id = self._initial_history_id or self._client.current_history_id()
        origin = "resumed" if self._initial_history_id else "current"
        print(
            f"[watcher] starting at historyId={history_id} ({origin}), "
            f"polling every {self._poll_interval}s"
        )
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
