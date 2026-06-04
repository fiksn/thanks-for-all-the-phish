import socket
import time
from collections.abc import Callable

from imapclient import IMAPClient
from imapclient.exceptions import IMAPClientError

from tfatp.auth import fresh_access_token, get_credentials
from tfatp.client import GmailClient, Message

NewMailHook = Callable[[Message], None]

DEFAULT_IMAP_HOST = "imap.gmail.com"
DEFAULT_IMAP_PORT = 993
# RFC 2177 requires re-issuing IDLE at least every 29 minutes; Gmail drops earlier in practice.
IDLE_REFRESH_SECONDS = 25 * 60


class IdleWatcher:
    """Push-style watcher using IMAP IDLE with XOAUTH2.

    Uses the same credentials as GmailClient. New messages are looked up via the
    Gmail REST API so the hook receives a fully-populated `Message`.
    """

    def __init__(self, client: GmailClient) -> None:
        self._client = client
        self._user = client.user
        self._hooks: list[NewMailHook] = []
        self._creds = get_credentials(client.config, subject=self._user)
        self._host = client.config.imap_host or DEFAULT_IMAP_HOST
        self._port = client.config.imap_port or DEFAULT_IMAP_PORT

    def on_new_mail(self, hook: NewMailHook) -> NewMailHook:
        self._hooks.append(hook)
        return hook

    def _emit(self, msg: Message) -> None:
        for hook in self._hooks:
            try:
                hook(msg)
            except Exception as exc:  # noqa: BLE001
                print(f"[idle] hook {hook.__name__} raised: {exc!r}")

    def _connect(self) -> IMAPClient:
        token = fresh_access_token(self._creds)
        imap = IMAPClient(self._host, port=self._port, ssl=True)
        imap.oauth2_login(self._user, token)
        imap.select_folder("INBOX")
        return imap

    def probe(self) -> tuple[bool, str]:
        """Try to log into IMAP. Returns (ok, error_detail).

        Useful as a precondition check: if IMAP is disabled on the account
        (Gmail Settings → Forwarding and POP/IMAP, or admin-disabled),
        the login raises and we can fall back to a different watcher.
        """
        try:
            imap = self._connect()
        except (OSError, IMAPClientError) as exc:
            return False, repr(exc)
        try:
            imap.logout()
        except Exception:  # noqa: BLE001
            pass
        return True, ""

    def _highest_uid(self, imap: IMAPClient) -> int:
        uids = imap.search(["ALL"])
        return max(uids) if uids else 0

    def _fetch_new(self, imap: IMAPClient, last_uid: int) -> tuple[list[str], int]:
        """Return (tfatp-api ids of new messages, new high-water UID)."""
        uids = imap.search(["UID", f"{last_uid + 1}:*"])
        uids = [u for u in uids if u > last_uid]
        if not uids:
            return [], last_uid
        # X-GM-MSGID is Gmail's 64-bit message id; the REST API uses its hex form.
        data = imap.fetch(uids, ["X-GM-MSGID"])
        api_ids: list[str] = []
        for uid in uids:
            gm = data.get(uid, {}).get(b"X-GM-MSGID")
            if isinstance(gm, int):
                api_ids.append(format(gm, "x"))
        return api_ids, max(uids)

    def run(self) -> None:
        print(f"[idle] connecting to {self._host}:{self._port} as {self._user}")
        imap = self._connect()
        last_uid = self._highest_uid(imap)
        print(f"[idle] watching INBOX from UID>{last_uid}")

        try:
            while True:
                try:
                    imap.idle()
                    deadline = time.monotonic() + IDLE_REFRESH_SECONDS
                    while True:
                        timeout = max(1, int(deadline - time.monotonic()))
                        responses = imap.idle_check(timeout=timeout)
                        if responses:
                            imap.idle_done()
                            api_ids, last_uid = self._fetch_new(imap, last_uid)
                            for mid in api_ids:
                                self._emit(self._client.get_message(mid))
                            imap.idle()
                            deadline = time.monotonic() + IDLE_REFRESH_SECONDS
                            continue
                        if time.monotonic() >= deadline:
                            imap.idle_done()
                            break
                except KeyboardInterrupt:
                    try:
                        imap.idle_done()
                    except IMAPClientError:
                        pass
                    print("\n[idle] stopped")
                    return
                except (OSError, socket.error, IMAPClientError) as exc:
                    print(f"[idle] connection lost ({exc!r}); reconnecting in 5s")
                    try:
                        imap.logout()
                    except Exception:  # noqa: BLE001
                        pass
                    time.sleep(5)
                    imap = self._connect()
                    last_uid = max(last_uid, self._highest_uid(imap))
        finally:
            try:
                imap.logout()
            except Exception:  # noqa: BLE001
                pass
