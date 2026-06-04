import os
import tempfile

from google.auth.credentials import Credentials
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials as UserCredentials
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google_auth_oauthlib.flow import InstalledAppFlow

from tfatp.config import Config

# https://mail.google.com/ is required for messages.delete (permanent delete).
# It also covers readonly + insert + modify, so a single scope is enough for
# the mail pipeline. `openid` + `userinfo.email` let us call the OIDC userinfo
# endpoint to read `hd` (hosted domain), so org-domain classification works
# even without DWD. Adding these to the SCOPES list invalidates older token
# files — the next launch will prompt re-consent once.
SCOPES = [
    "https://mail.google.com/",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
]
_TOKEN_FILE_MODE = 0o600


def fresh_access_token(creds: Credentials) -> str:
    """Return a valid OAuth access token, refreshing if needed."""
    if not creds.valid:
        creds.refresh(Request())
    token = creds.token
    if not token:
        raise RuntimeError("Credentials refreshed but no access token available.")
    return token


def get_credentials(cfg: Config, subject: str | None = None) -> Credentials:
    """Return credentials for the configured auth mode.

    In service_account mode, `subject` overrides which workspace user to impersonate.
    In oauth mode, `subject` must equal `cfg.user` (or be None) since OAuth is bound
    to the account that granted consent.
    """
    if cfg.auth_mode == "service_account":
        return _service_account_credentials(cfg, subject or cfg.user)
    if subject is not None and subject != cfg.user:
        raise ValueError(
            f"OAuth credentials are bound to {cfg.user!r}; cannot act as {subject!r}. "
            "Use auth_mode='service_account' to impersonate other users."
        )
    return _oauth_credentials(cfg)


def _service_account_credentials(cfg: Config, subject: str) -> Credentials:
    if not cfg.service_account_file.exists():
        raise FileNotFoundError(
            f"Service account key not found at {cfg.service_account_file}."
        )
    sa = ServiceAccountCredentials.from_service_account_file(
        str(cfg.service_account_file), scopes=SCOPES
    )
    return sa.with_subject(subject)


def _oauth_credentials(cfg: Config) -> Credentials:
    creds: UserCredentials | None = None
    if cfg.token_file.exists():
        creds = UserCredentials.from_authorized_user_file(str(cfg.token_file), SCOPES)

    if creds and creds.valid:
        return creds

    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        _write_token_file(cfg.token_file, creds.to_json())
        return creds

    if not cfg.client_secret_file.exists():
        raise FileNotFoundError(
            f"OAuth client secret not found at {cfg.client_secret_file}."
        )

    flow = InstalledAppFlow.from_client_secrets_file(str(cfg.client_secret_file), SCOPES)
    creds = flow.run_local_server(port=0, login_hint=cfg.user)

    if creds.id_token is None and getattr(creds, "_id_token", None) is None:
        # google-auth doesn't always expose the granted account; we trust the flow.
        pass

    _write_token_file(cfg.token_file, creds.to_json())
    return creds


def _write_token_file(path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp:
            tmp.write(content)
            tmp.flush()
            os.fchmod(tmp.fileno(), _TOKEN_FILE_MODE)
        os.replace(tmp_name, path)
        path.chmod(_TOKEN_FILE_MODE)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise
