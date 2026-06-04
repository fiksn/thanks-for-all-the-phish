"""Resolve the set of domains that count as 'internal' for the workspace.

Two paths:
- service_account (DWD): query Admin SDK `domains.list` impersonating
  `cfg.admin_user`. Returns every verified domain + alias the workspace owns.
  Scope required: `admin.directory.domain.readonly`.
- oauth: call the OpenID Connect userinfo endpoint and read `hd` (hosted
  domain). Always union with the email-domain of `cfg.user` and `cfg.domain`
  as a fallback so a missing/blocked userinfo response still yields the
  obvious cases.

Domains are returned lowercase. An empty set means "classification disabled" —
callers should treat every sender as neither internal nor external in that
case (no yellow banner, original phase list applies).
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

from google.auth.credentials import Credentials
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from googleapiclient.discovery import build

from tfatp.auth import fresh_access_token
from tfatp.config import Config

DOMAIN_SCOPES = ["https://www.googleapis.com/auth/admin.directory.domain.readonly"]
_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"


def _email_domain(addr: str) -> str:
    return addr.split("@", 1)[1].lower() if "@" in addr else ""


def _fallback(cfg: Config) -> frozenset[str]:
    return frozenset(d for d in (_email_domain(cfg.user), cfg.domain.lower()) if d)


def resolve(cfg: Config, creds: Credentials | None = None) -> frozenset[str]:
    if cfg.auth_mode == "service_account":
        return _resolve_dwd(cfg)
    if creds is None:
        return _fallback(cfg)
    return _resolve_oauth(cfg, creds)


def _resolve_dwd(cfg: Config) -> frozenset[str]:
    fallback = _fallback(cfg)
    if not cfg.admin_user:
        return fallback
    try:
        sa = ServiceAccountCredentials.from_service_account_file(
            str(cfg.service_account_file), scopes=DOMAIN_SCOPES
        )
        creds = sa.with_subject(cfg.admin_user)
        service = build("admin", "directory_v1", credentials=creds, cache_discovery=False)
        resp = service.domains().list(customer="my_customer").execute()
    except Exception as exc:  # noqa: BLE001
        print(f"[org_domains] Admin SDK domains.list failed: {exc!r}; "
              f"using fallback {sorted(fallback)!r}", file=sys.stderr)
        return fallback
    out = set(fallback)
    for d in resp.get("domains", []):
        name = (d.get("domainName") or "").lower()
        if name:
            out.add(name)
    return frozenset(out)


def _resolve_oauth(cfg: Config, creds: Credentials) -> frozenset[str]:
    out: set[str] = set(_fallback(cfg))
    try:
        token = fresh_access_token(creds)
        req = urllib.request.Request(
            _USERINFO_URL, headers={"Authorization": f"Bearer {token}"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"[org_domains] userinfo lookup failed: {exc!r}; "
              f"using fallback {sorted(out)!r}", file=sys.stderr)
        return frozenset(out)
    hd = (data.get("hd") or "").lower()
    if hd:
        out.add(hd)
    return frozenset(out)
