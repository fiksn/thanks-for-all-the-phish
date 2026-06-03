"""Push-based watcher using Gmail's Cloud Pub/Sub notifications.

Architecture:
- Per user: `users.watch(topicName=...)` once a day. Gmail publishes
  `{emailAddress, historyId}` to the topic on every mailbox change.
- One Pub/Sub streaming-pull subscriber processes events for the whole domain.
- For each event we look up the new messages via `users.history.list`.

Falls back to polling for users whose watch() call returns 403 (e.g. IMAP/API
disabled, missing Pub/Sub publisher binding) — those users are returned to the
caller so it can run them through `DomainPollingWatcher`.
"""

import json
import threading
from collections.abc import Callable

from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from googleapiclient.errors import HttpError

from tfatp.client import GmailClient
from tfatp.config import Config
from tfatp.directory import list_workspace_users

NewMailHandler = Callable[[GmailClient, str], None]

PUBSUB_SCOPES = ["https://www.googleapis.com/auth/pubsub"]
WATCH_RENEW_SECONDS = 24 * 3600  # users.watch expires after 7 days; renew daily.


class PubSubWatcher:
    def __init__(self, cfg: Config, users: list[str] | None = None) -> None:
        if cfg.auth_mode != "service_account":
            raise ValueError("PubSubWatcher requires DWD (service_account).")
        for field in ("pubsub_project_id", "pubsub_topic", "pubsub_subscription"):
            if not getattr(cfg, field):
                raise ValueError(f"config.{field} is required for Pub/Sub mode.")
        self._cfg = cfg
        self._users = users
        self._clients: dict[str, GmailClient] = {}
        self._history: dict[str, str] = {}
        self._stop = threading.Event()

    @property
    def _topic_name(self) -> str:
        return f"projects/{self._cfg.pubsub_project_id}/topics/{self._cfg.pubsub_topic}"

    @property
    def _subscription_path(self) -> str:
        return (
            f"projects/{self._cfg.pubsub_project_id}"
            f"/subscriptions/{self._cfg.pubsub_subscription}"
        )

    def _client(self, user: str) -> GmailClient:
        if user not in self._clients:
            self._clients[user] = GmailClient.for_user(self._cfg, user)
        return self._clients[user]

    def _watch(self, user: str) -> str | None:
        """Call users.watch for one user. Returns historyId, or None if forbidden."""
        try:
            return self._client(user).start_watch(self._topic_name)
        except HttpError as exc:
            if exc.resp.status in (401, 403):
                return None
            raise

    def install_watches(self) -> tuple[list[str], list[str]]:
        """Register Pub/Sub watch for each user. Returns (watched, unwatched)."""
        users = self._users if self._users is not None else list_workspace_users(self._cfg)
        watched: list[str] = []
        unwatched: list[str] = []
        for u in users:
            hid = self._watch(u)
            if hid is None:
                print(f"[pubsub] watch denied for {u}; will fall back to polling")
                unwatched.append(u)
            else:
                self._history[u] = hid
                watched.append(u)
        return watched, unwatched

    def _subscriber_credentials(self) -> ServiceAccountCredentials:
        return ServiceAccountCredentials.from_service_account_file(
            str(self._cfg.service_account_file), scopes=PUBSUB_SCOPES
        )

    def _renew_loop(self, users: list[str]) -> None:
        while not self._stop.wait(WATCH_RENEW_SECONDS):
            for u in users:
                try:
                    hid = self._watch(u)
                    if hid:
                        self._history[u] = hid
                except Exception as exc:  # noqa: BLE001
                    print(f"[pubsub] renew failed for {u}: {exc!r}")

    def run(self, on_new_mail: NewMailHandler, watched_users: list[str]) -> None:
        # Lazy import — keeps the dep optional for users on the polling-only path.
        from google.cloud import pubsub_v1

        subscriber = pubsub_v1.SubscriberClient(credentials=self._subscriber_credentials())

        def callback(message) -> None:  # google.cloud.pubsub_v1.subscriber.message.Message
            try:
                data = json.loads(message.data.decode("utf-8"))
                user = data["emailAddress"]
                start = self._history.get(user)
                if not start:
                    # Race: notification arrived before our watch registration recorded
                    # the historyId. Use whatever the notification carries minus 1.
                    start = str(int(data.get("historyId", 0)))
                new_ids, new_hid = self._client(user).history_since(start)
                self._history[user] = new_hid
                for mid in new_ids:
                    on_new_mail(self._client(user), mid)
                message.ack()
            except Exception as exc:  # noqa: BLE001
                print(f"[pubsub] callback error: {exc!r}")
                message.nack()

        renew = threading.Thread(target=self._renew_loop, args=(watched_users,), daemon=True)
        renew.start()

        future = subscriber.subscribe(self._subscription_path, callback=callback)
        print(
            f"[pubsub] subscribed to {self._subscription_path} "
            f"watching {len(watched_users)} user(s)"
        )
        try:
            future.result()
        except KeyboardInterrupt:
            print("\n[pubsub] stopping")
        finally:
            self._stop.set()
            future.cancel()
            try:
                future.result(timeout=5)
            except Exception:  # noqa: BLE001
                pass
