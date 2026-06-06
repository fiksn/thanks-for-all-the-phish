"""List workspace users via the Admin SDK Directory API.

Requires:
- auth_mode = "service_account" (DWD)
- The service account authorized in the admin console for the scope
  https://www.googleapis.com/auth/admin.directory.user.readonly
- A super-admin to impersonate (config.admin_user) — directory access cannot be
  delegated to a non-admin even with DWD.
"""

import re

from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from googleapiclient.discovery import build

from tfatp.config import Config

DIRECTORY_SCOPES = ["https://www.googleapis.com/auth/admin.directory.user.readonly"]


def list_workspace_users(cfg: Config, include_suspended: bool = False) -> list[str]:
    if cfg.auth_mode != "service_account":
        raise ValueError("list_workspace_users requires auth_mode='service_account'.")
    if not cfg.admin_user:
        raise ValueError(
            "Set 'admin_user' in config to a workspace super-admin email — required "
            "to impersonate for Admin SDK calls."
        )

    sa = ServiceAccountCredentials.from_service_account_file(
        str(cfg.service_account_file), scopes=DIRECTORY_SCOPES
    )
    creds = sa.with_subject(cfg.admin_user)
    service = build("admin", "directory_v1", credentials=creds, cache_discovery=False)

    users: list[str] = []
    page_token: str | None = None
    while True:
        resp = (
            service.users()
            .list(domain=cfg.domain, pageToken=page_token, maxResults=500)
            .execute()
        )
        for u in resp.get("users", []):
            if u.get("suspended") and not include_suspended:
                continue
            primary = u.get("primaryEmail")
            if primary:
                users.append(primary)
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return users


def filter_users(
    users: list[str],
    include: tuple[str, ...] = (),
    exclude: tuple[str, ...] = (),
) -> list[str]:
    """Apply optional include then exclude regex filters to a user list.

    Both arguments default to empty, so the no-filter case returns ``users``
    unchanged. Semantics match the documented precedence: an empty
    ``include`` means "every user is in"; a non-empty ``include`` narrows
    to users whose primary email ``fullmatch``-es at least one entry.
    ``exclude`` then trims that narrowed set: anything matching at least
    one exclude pattern is dropped.

    Patterns are case-insensitive — matching uses the lower-cased email
    against the already-lower-cased patterns from config.
    """
    if not include and not exclude:
        return users
    inc = tuple(re.compile(p) for p in include)
    exc = tuple(re.compile(p) for p in exclude)
    out: list[str] = []
    for u in users:
        lu = u.lower()
        if inc and not any(p.fullmatch(lu) for p in inc):
            continue
        if exc and any(p.fullmatch(lu) for p in exc):
            continue
        out.append(u)
    return out
