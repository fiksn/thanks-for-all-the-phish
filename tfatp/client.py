import base64
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any

from googleapiclient.discovery import build

from tfatp.auth import get_credentials
from tfatp.config import Config


@dataclass(frozen=True, slots=True)
class Message:
    id: str
    thread_id: str
    sender: str
    subject: str
    snippet: str
    date: str

    @classmethod
    def from_api(cls, payload: dict[str, Any]) -> "Message":
        headers = {h["name"].lower(): h["value"] for h in payload["payload"].get("headers", [])}
        return cls(
            id=payload["id"],
            thread_id=payload["threadId"],
            sender=headers.get("from", ""),
            subject=headers.get("subject", ""),
            snippet=payload.get("snippet", ""),
            date=headers.get("date", ""),
        )


class GmailClient:
    def __init__(self, cfg: Config, subject: str | None = None) -> None:
        self._cfg = cfg
        self._user_id = subject or cfg.user
        creds = get_credentials(cfg, subject=self._user_id)
        self._service = build("gmail", "v1", credentials=creds, cache_discovery=False)

    @classmethod
    def for_user(cls, cfg: Config, user: str) -> "GmailClient":
        """Create a client acting as `user`. Only valid in service_account (DWD) mode."""
        if cfg.auth_mode != "service_account":
            raise ValueError(
                "for_user() requires auth_mode='service_account' (domain-wide delegation)."
            )
        return cls(cfg, subject=user)

    @property
    def user(self) -> str:
        return self._user_id

    @property
    def config(self) -> Config:
        return self._cfg

    def list_message_ids(self, query: str = "", max_results: int = 10) -> list[str]:
        resp = (
            self._service.users()
            .messages()
            .list(userId=self._user_id, q=query, maxResults=max_results)
            .execute()
        )
        return [m["id"] for m in resp.get("messages", [])]

    def get_message(self, message_id: str) -> Message:
        payload = (
            self._service.users()
            .messages()
            .get(userId=self._user_id, id=message_id, format="metadata",
                 metadataHeaders=["From", "Subject", "Date"])
            .execute()
        )
        return Message.from_api(payload)

    def get_raw_message(self, message_id: str) -> bytes:
        """Return the raw RFC822 bytes of a message (needed for DKIM verification)."""
        payload = (
            self._service.users()
            .messages()
            .get(userId=self._user_id, id=message_id, format="raw")
            .execute()
        )
        return base64.urlsafe_b64decode(payload["raw"])

    def latest_message(self) -> Message | None:
        ids = self.list_message_ids(max_results=1)
        if not ids:
            return None
        return self.get_message(ids[0])

    def insert_message(self, raw_rfc822: bytes, label_ids: list[str] | None = None) -> str:
        body = {
            "raw": base64.urlsafe_b64encode(raw_rfc822).decode("ascii"),
            "labelIds": label_ids or ["INBOX"],
        }
        resp = (
            self._service.users()
            .messages()
            .insert(userId=self._user_id, body=body, internalDateSource="dateHeader")
            .execute()
        )
        return resp["id"]

    def insert_simple(self, sender: str, subject: str, body: str) -> str:
        msg = EmailMessage()
        msg["From"] = sender
        msg["To"] = self._user_id
        msg["Subject"] = subject
        msg.set_content(body)
        return self.insert_message(bytes(msg))

    def delete_message(self, message_id: str) -> None:
        self._service.users().messages().delete(
            userId=self._user_id, id=message_id
        ).execute()

    def start_watch(self, topic_name: str, label_ids: list[str] | None = None) -> str:
        """Register a Cloud Pub/Sub topic to receive mailbox change notifications.

        topic_name format: 'projects/{project}/topics/{topic}'. Returns the
        starting historyId; persist it so the subscriber can call history_since().
        Expires after ~7 days — call again to renew.
        """
        body: dict = {
            "topicName": topic_name,
            "labelIds": label_ids or ["INBOX"],
            "labelFilterAction": "include",
        }
        resp = self._service.users().watch(userId=self._user_id, body=body).execute()
        return str(resp["historyId"])

    def stop_watch(self) -> None:
        self._service.users().stop(userId=self._user_id).execute()

    def current_history_id(self) -> str:
        profile = self._service.users().getProfile(userId=self._user_id).execute()
        return profile["historyId"]

    def history_since(self, start_history_id: str) -> tuple[list[str], str]:
        new_ids: list[str] = []
        page_token: str | None = None
        latest_history_id = start_history_id

        while True:
            req = self._service.users().history().list(
                userId=self._user_id,
                startHistoryId=start_history_id,
                historyTypes=["messageAdded"],
                pageToken=page_token,
            )
            resp = req.execute()
            for h in resp.get("history", []):
                latest_history_id = h.get("id", latest_history_id)
                for added in h.get("messagesAdded", []):
                    msg = added.get("message", {})
                    if "id" in msg:
                        new_ids.append(msg["id"])
            page_token = resp.get("nextPageToken")
            if not page_token:
                break

        return new_ids, latest_history_id
