"""Polling-loop watcher across every user in a Workspace domain (DWD only)."""

import time
from collections.abc import Callable

from tfatp.client import GmailClient
from tfatp.config import Config
from tfatp.directory import list_workspace_users

NewMailHandler = Callable[[GmailClient, str], None]


class DomainPollingWatcher:
    """Round-robin through every active user and pick up new mail via history API.

    Detection latency is roughly poll_interval seconds. No persistent connections.
    """

    def __init__(self, cfg: Config, users: list[str] | None = None) -> None:
        if cfg.auth_mode != "service_account":
            raise ValueError("DomainPollingWatcher requires DWD (service_account).")
        self._cfg = cfg
        self._clients: dict[str, GmailClient] = {}
        self._history: dict[str, str] = {}
        self._users = users

    def _client(self, user: str) -> GmailClient:
        if user not in self._clients:
            self._clients[user] = GmailClient.for_user(self._cfg, user)
        return self._clients[user]

    def _init_users(self) -> list[str]:
        users = self._users if self._users is not None else list_workspace_users(self._cfg)
        ready: list[str] = []
        for u in users:
            try:
                self._history[u] = self._client(u).current_history_id()
                ready.append(u)
            except Exception as exc:  # noqa: BLE001
                print(f"[poll] init failed for {u}: {exc!r}")
        return ready

    def run(self, on_new_mail: NewMailHandler) -> None:
        users = self._init_users()
        if not users:
            print("[poll] no users initialized; exiting")
            return
        print(f"[poll] watching {len(users)} user(s) every {self._cfg.poll_interval}s")
        try:
            while True:
                for u in users:
                    try:
                        new_ids, new_hid = self._client(u).history_since(self._history[u])
                        self._history[u] = new_hid
                        for mid in new_ids:
                            on_new_mail(self._client(u), mid)
                    except Exception as exc:  # noqa: BLE001 — one user must not kill the loop
                        print(f"[poll] {u}: {exc!r}")
                time.sleep(self._cfg.poll_interval)
        except KeyboardInterrupt:
            print("\n[poll] stopped")
