import email
import json
import random
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email import policy
from email.utils import getaddresses, parsedate_to_datetime
from functools import lru_cache
from urllib.parse import quote, urlparse, urlunparse

import drawbridge
import drawbridge.sync
import httpx
import tldextract
from bs4 import BeautifulSoup, NavigableString
from bs4.builder import ParserRejectedMarkup

_LINK_RE = re.compile(
    r"(?i)\b((?:https?|ftps?|sftp)://[^\s<>\"'\)\]]+)",
)
_PRESSURE_RE = re.compile(
    r"(?i)\b("
    r"urgent|today only|within 24 hours?|final notice|gift cards?|wire transfer|"
    r"bank details changed|payment overdue|invoice overdue|immediate action required|"
    r"account suspended|password expires?|verify your account|ach"
    r")\b",
)
_TRAILING_PUNCT = ".,);]>!?"
DEFAULT_YOUNG_DOMAIN_DAYS = 365
_HTTP_TIMEOUT = 8
_MAX_LINK_RESPONSE_BYTES = 1_000_000
_LINK_RESPONSE_CHUNK_BYTES = 8192
# RDAP JSON for a single domain is typically a few KB. Cap at 1 MB so a
# hostile rdap.org response (or man-in-the-middle) can't OOM us.
_MAX_RDAP_RESPONSE_BYTES = 1_000_000
# Retry budget for RDAP. A single transient blip used to silently downgrade a
# legitimate old domain into a phase-0 failure ("unknown age" → too young →
# every later phase gated off). Three attempts on transient failures keep the
# false-positive rate low without blowing the per-message latency cap.
_RDAP_TIMEOUT = 3
_RDAP_MAX_ATTEMPTS = 3
_RDAP_BACKOFF_SECONDS = (0.5, 1.0, 2.0)
_RDAP_JITTER_RATIO = 0.2
_RDAP_BUDGET_SECONDS = 8
# Retry on transient server-side problems and rate limiting. 404 (and other
# 4xx) mean RDAP definitively has no record — retrying just wastes the budget.
_RDAP_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
# Upper bound on HTML payload fed to BeautifulSoup. Gmail allows up to 25 MB
# of MIME; a hostile sender can pack deeply-nested or pathologically-shaped
# HTML that pins CPU for seconds at a fraction of that size. 2 MB covers any
# legitimate marketing email and leaves ample headroom for parsing.
_MAX_HTML_PARSE_BYTES = 2_000_000
# Domain labels are alphanumeric, dots, hyphens. Punycode adds underscores in
# A-labels? No — xn-- prefix is ASCII. Stick to RFC 1035 chars plus the colon
# and brackets used for IPv6 literals, then reject the IP-literal cases since
# RDAP wouldn't make sense for them anyway.
_VALID_DOMAIN_RE = re.compile(r"\A[A-Za-z0-9.\-]{1,253}\Z")

# Pose as recent stable Chrome on macOS. Many phishing kits and CDNs gate on
# UA / Accept / Sec-CH-UA headers and serve a stub or block when these are missing.
_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Ch-Ua": '"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"macOS"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}


@dataclass(frozen=True, slots=True)
class YoungDomain:
    """Link domain age is below the configured threshold."""
    domain: str
    age_days: int | None         # None means RDAP returned no usable answer

    def __str__(self) -> str:
        return f"young ({self.age_days}d)" if self.age_days is not None else "young (age unknown)"


@dataclass(frozen=True, slots=True)
class LinkLookalike:
    """Link domain is a Levenshtein-close variant of an organization domain."""
    domain: str
    target: str
    distance: int

    def __str__(self) -> str:
        from tfatp.lookalike import describe
        return describe(self.domain, self.target, self.distance)


@dataclass(frozen=True, slots=True)
class PasswordForm:
    """Fetched page contains a form with a password input."""
    domain: str

    def __str__(self) -> str:
        return "password form"


@dataclass(frozen=True, slots=True)
class RedirectorResolves:
    """Link points at a known redirector; final_domain is empty when fetch was gated off."""
    domain: str
    final_domain: str

    def __str__(self) -> str:
        return (
            f"redirector resolves to {self.final_domain}"
            if self.final_domain
            else "redirector (not resolved)"
        )


@dataclass(frozen=True, slots=True)
class LinkTextMismatch:
    """Anchor text shows one domain, href points at a different one."""
    displayed: str
    actual: str
    via_redirector: bool

    def __str__(self) -> str:
        verb = "redirector resolves to" if self.via_redirector else "href points to"
        return f"link text shows {self.displayed} but {verb} {self.actual}"


@dataclass(frozen=True, slots=True)
class UrlInSubject:
    """URL was lifted from the Subject header rather than the body."""
    domain: str

    def __str__(self) -> str:
        return "URL appears in Subject header"


@dataclass(frozen=True, slots=True)
class SenderDomainAge:
    """Sender's registrable domain is younger than the configured floor."""
    domain: str
    age_days: int | None         # None means RDAP returned no usable answer
    min_required: int

    def __str__(self) -> str:
        if self.age_days is None:
            return (
                f"Sender domain age unknown for {self.domain} "
                f"(treated as too young)"
            )
        return (
            f"Sender domain age {self.age_days}d < {self.min_required}d "
            f"for {self.domain}"
        )


@dataclass(frozen=True, slots=True)
class AttachmentIssue:
    """Attachment scanner flagged a payload (macros, zip bombs, etc.)."""
    name: str
    kind: str                    # 'macro' | 'bomb' | 'encrypted' | 'unreadable' | 'oversized' | 'scan_failed'
    detail: str                  # human-readable specifics

    def __str__(self) -> str:
        return f"{self.detail} ({self.name})"


@dataclass(frozen=True, slots=True)
class HeaderAnomaly:
    """Reply-To/From mismatch or pressure language in subject/body."""
    detail: str

    def __str__(self) -> str:
        return self.detail


Warning = (
    YoungDomain
    | LinkLookalike
    | PasswordForm
    | RedirectorResolves
    | LinkTextMismatch
    | UrlInSubject
    | SenderDomainAge
    | AttachmentIssue
    | HeaderAnomaly
)


@dataclass(frozen=True, slots=True)
class LinkFinding:
    url: str
    host: str
    domain: str
    age_days: int | None
    has_password_form: bool
    warnings: list[Warning] = field(default_factory=list)


def _parse_html(content: str | bytes) -> BeautifulSoup:
    """Bound the HTML byte size before handing it to BeautifulSoup.

    bs4 has no upstream cap and will happily build a DOM for hostile inputs
    that nest tags millions deep or repeat attributes endlessly. Truncating
    at a fixed size keeps parse time and memory predictable regardless of
    sender intent. A truncated suffix may yield malformed tail tokens; bs4
    handles those gracefully.
    """
    if isinstance(content, str):
        encoded = content.encode("utf-8", errors="ignore")
        truncated = encoded[:_MAX_HTML_PARSE_BYTES].decode("utf-8", errors="ignore")
    else:
        truncated = content[:_MAX_HTML_PARSE_BYTES].decode("utf-8", errors="ignore")
    try:
        return BeautifulSoup(truncated, "html.parser")
    except ParserRejectedMarkup:
        # Malformed CDATA/marked sections in some senders' HTML crash html.parser
        # outright. Treat the body as empty rather than aborting the whole
        # pipeline — link extraction from the plain-text fallback still runs.
        return BeautifulSoup("", "html.parser")


# Path / query substrings that strongly suggest a URL whose GET would
# trigger a destructive or state-changing side effect: a one-click
# unsubscribe, an account lock, an invitation accept, a password-reset
# token redemption. Email senders ship these as plain links because the
# user is *expected* to click; a phish-scanner fetching them blind
# completes the action on the recipient's behalf, which is much worse
# than producing no signal. We treat any match here as "do not fetch".
#
# The verb is the dangerous part. We anchor on a delimiter before and a
# delimiter after the keyword so substrings buried inside larger words
# (e.g. "documentation" doesn't trip "men", "stocklock" doesn't trip
# "lock") stay clean. Account-state and confirmation verbs require a
# specific tail (`account|wallet|user|email|...`) to narrow further.
_UNSAFE_FETCH_RE = re.compile(
    r"(?:^|[/?&_=-])(?:"
    # --- Mailing list opt-out / preference flip ---
    r"unsubscribe|unsub|opt[-_]?out|optout|"
    r"list[-_]?remove|remove[-_]?me|"
    r"leave[-_]?list|stop[-_]?email|"
    r"email[-_]?prefs?|email[-_]?settings|"
    r"manage[-_]?subscription|"
    # --- Account-state changes (lock/freeze/suspend/delete account) ---
    r"lock[-_]?(?:account|wallet|user|card)|"
    r"unlock[-_]?(?:account|wallet|user|card)|"
    r"freeze[-_]?(?:account|wallet|user|card)|"
    r"suspend[-_]?(?:account|wallet|user)|"
    r"disable[-_]?(?:account|wallet|user|2fa|mfa)|"
    r"deactivate(?:[-_]?account)?|"
    r"close[-_]?account|"
    r"delete[-_]?account|"
    r"block[-_]?(?:account|user|sender)|"
    # --- Confirmation / verification one-click (token-bound) ---
    r"confirm[-_]?(?:email|login|account|payment|order|"
    r"subscription|signup|registration|address|delivery|booking)|"
    r"verify[-_]?(?:email|account|identity|phone|address|login)|"
    r"activate[-_]?(?:account|email|user|subscription)|"
    r"validate[-_]?(?:email|account|address)|"
    # --- Password / token-reset flows (click burns the token) ---
    r"reset[-_]?password|password[-_]?reset|"
    r"recover[-_]?(?:account|password)|account[-_]?recovery|"
    r"forgot[-_]?password|"
    # --- Invitations and access requests ---
    r"accept[-_]?(?:invite|invitation|request)|"
    r"decline[-_]?(?:invite|invitation|request)|"
    r"approve[-_]?(?:request|invite|access|signin|login|payment)|"
    r"reject[-_]?(?:request|invite|access|signin|login)|"
    r"join[-_]?(?:team|workspace|organi[sz]ation)|"
    # --- Transactional one-clicks ---
    r"cancel[-_]?(?:order|payment|subscription|booking|reservation)|"
    r"refund[-_]?(?:request|order)|"
    r"pay[-_]?now|"
    # --- "Wasn't me" / report flows ---
    r"report[-_]?(?:fraud|phish|abuse|not[-_]?me|wasn[-_]?t[-_]?me)|"
    r"not[-_]?me|wasn[-_]?t[-_]?me"
    r")(?:[/?&_=]|$)",
    re.IGNORECASE,
)

# Generic ?action=<verb>, ?do=<verb>, ?cmd=<verb> patterns. Mailing
# systems and SaaS apps frequently expose dispatchers behind a single
# script that branches on a query value, e.g. `?do=unsubscribe`.
_UNSAFE_QUERY_RE = re.compile(
    r"[?&](?:action|do|cmd|op|command|task|method)="
    r"(?:confirm|verify|validate|approve|reject|"
    r"lock|unlock|freeze|suspend|disable|deactivate|"
    r"unsubscribe|subscribe|delete|remove|cancel|"
    r"activate|reset|recover|"
    r"accept|decline|join|leave)\b",
    re.IGNORECASE,
)

# Action verbs in human prose. The URL might be opaque (a tracking
# token, a vanity shortener) and the anchor text might be generic
# ("here", "click", "this link"), so the only signal of intent is in the
# *prose around the link*. We climb to a block-level ancestor (paragraph,
# table cell, list item) and look for action verbs in that block's text.
# False positives only reduce signal — they never trigger an action.
_UNSAFE_PROSE_RE = re.compile(
    r"(?ix) (?:^|\b) (?:"
    # mailing-list opt-out
    r"unsubscribe | opt[-_\s]?out | remove\s+me |"
    r"leave\s+(?:this\s+)?list | stop\s+receiving |"
    r"email\s+preferences | manage\s+(?:your\s+)?subscription |"
    # account state changes
    r"lock\s+(?:your\s+|my\s+|the\s+)?(?:account|wallet|card) |"
    r"unlock\s+(?:your\s+|my\s+|the\s+)?(?:account|wallet|card) |"
    r"freeze\s+(?:your\s+|my\s+|the\s+)?(?:account|wallet|card) |"
    r"suspend\s+(?:your\s+|my\s+)?account |"
    r"close\s+(?:your\s+|my\s+)?account |"
    r"deactivate\s+(?:your\s+|my\s+)?account |"
    r"delete\s+(?:your\s+|my\s+)?account |"
    r"disable\s+(?:2fa|mfa|account) |"
    # confirmation / verification
    r"confirm\s+(?:your\s+)?"
    r"(?:email|login|sign[-_\s]?in|account|order|"
    r"payment|subscription|address|signup|registration) |"
    r"verify\s+(?:your\s+)?(?:email|account|identity|phone|address|login) |"
    r"activate\s+(?:your\s+)?(?:account|email|subscription) |"
    r"validate\s+(?:your\s+)?(?:email|account) |"
    # password / token reset
    r"reset\s+(?:your\s+)?password | password\s+reset |"
    r"recover\s+(?:your\s+)?(?:account|password) |"
    r"forgot\s+(?:your\s+)?password |"
    # invite / approval
    r"accept\s+(?:this\s+|the\s+)?(?:invite|invitation|request) |"
    r"decline\s+(?:this\s+|the\s+)?(?:invite|invitation|request) |"
    r"approve\s+(?:this\s+|the\s+)?"
    r"(?:request|sign[-_\s]?in|login|payment|access) |"
    r"reject\s+(?:this\s+|the\s+)?(?:request|sign[-_\s]?in|login|access) |"
    r"join\s+(?:the\s+|this\s+)?(?:team|workspace|organi[sz]ation) |"
    # transactional one-clicks
    r"cancel\s+(?:this\s+|your\s+)?(?:order|payment|subscription|booking) |"
    r"pay\s+now |"
    # "wasn't me" / report flows
    r"this\s+was(?:n[''‘’]?t|\s+not)\s+me | wasn[''‘’]?t\s+me"
    r") (?:$|\b)"
)


def _collect_action_context_urls(raw_rfc822: bytes | None) -> set[str]:
    """Return href URLs whose containing block (paragraph, table cell,
    list item) carries an action verb in its prose.

    The anchor itself is often a generic word ("here", "click", "this
    link") that reveals nothing about the click target. Widening the
    inspection to the block lets us recognise "...click here to lock
    your account." even when the link text alone says nothing. Every
    anchor inside a block that contains an action verb is flagged, so
    multi-link blocks get a conservative treatment: skip the fetch.
    """
    if raw_rfc822 is None:
        return set()
    out: set[str] = set()
    try:
        msg = email.message_from_bytes(raw_rfc822, policy=policy.default)
    except Exception:  # noqa: BLE001 — malformed bytes shouldn't break analysis
        return out
    parts = msg.walk() if msg.is_multipart() else [msg]
    block_tags = {"p", "li", "td", "th", "div", "blockquote", "section", "body"}
    for part in parts:
        if part.get_content_type() != "text/html":
            continue
        try:
            html = part.get_content()
        except (LookupError, UnicodeDecodeError):
            continue
        soup = _parse_html(html)
        for a in soup.find_all("a", href=True):
            href = _normalize_href(a["href"])
            if not href.lower().startswith(("http://", "https://")):
                continue
            # Climb to a block-level ancestor (bounded so a deeply-nested
            # inline doesn't grab the whole document).
            ctx = a.parent
            hops = 0
            while ctx is not None and ctx.name not in block_tags and hops < 6:
                ctx = ctx.parent
                hops += 1
            container = ctx if ctx is not None else a
            text = " ".join(container.stripped_strings)
            if _UNSAFE_PROSE_RE.search(text):
                out.add(href)
    return out


def _extract_unsubscribe_urls(raw_rfc822: bytes | None) -> set[str]:
    """Return the set of HTTP(S) URLs from the message's ``List-Unsubscribe``
    header. Fetching one of these can complete an unsubscribe even with a
    plain GET (RFC 8058 one-click) — they must be excluded from any
    network-touching check.
    """
    if raw_rfc822 is None:
        return set()
    try:
        msg = email.message_from_bytes(raw_rfc822, policy=policy.default)
    except Exception:  # noqa: BLE001 — malformed bytes shouldn't break analysis
        return set()
    out: set[str] = set()
    for header in msg.get_all("List-Unsubscribe") or []:
        for m in re.finditer(r"<([^>]+)>", str(header)):
            url = m.group(1).strip()
            if url.lower().startswith(("http://", "https://")):
                out.add(url)
    return out


def _is_unsafe_to_fetch(url: str, list_unsubscribe_urls: set[str]) -> bool:
    """True when fetching ``url`` is likely to trigger a destructive side
    effect — unsubscribe, account lock, password-reset token redemption,
    invitation accept/decline, payment confirmation, etc. — or when the
    URL appears in the message's ``List-Unsubscribe`` header.
    """
    if url in list_unsubscribe_urls:
        return True
    return bool(_UNSAFE_FETCH_RE.search(url) or _UNSAFE_QUERY_RE.search(url))


def extract_links(text: str) -> list[str]:
    """Return unique URLs in text, preserving first-occurrence order."""
    seen: set[str] = set()
    out: list[str] = []
    for m in _LINK_RE.finditer(text):
        url = m.group(1).rstrip(_TRAILING_PUNCT)
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


def _header_address_domain(msg: email.message.Message, header_name: str) -> str:
    addresses = getaddresses(msg.get_all(header_name, []))
    for _, addr in addresses:
        if "@" not in addr:
            continue
        host = addr.rsplit("@", 1)[1].strip().strip("[]")
        if host:
            return registrable_domain(host.lower())
    return ""


def registrable_domain(host: str) -> str:
    ext = tldextract.extract(host)
    if not ext.domain or not ext.suffix:
        return host
    return f"{ext.domain}.{ext.suffix}"


def _read_rdap_body(resp) -> dict | None:
    """Stream the RDAP response with a hard byte cap. None on cap-hit or
    non-JSON payload."""
    body = bytearray()
    for chunk in resp.iter_bytes(chunk_size=_LINK_RESPONSE_CHUNK_BYTES):
        if not chunk:
            continue
        body.extend(chunk[: _MAX_RDAP_RESPONSE_BYTES - len(body)])
        if len(body) >= _MAX_RDAP_RESPONSE_BYTES:
            return None
    try:
        return json.loads(body)
    except ValueError:
        return None


def _registration_age_days(data: dict) -> int | None:
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            raw_date = (event.get("eventDate") or "").replace("Z", "+00:00")
            try:
                created = datetime.fromisoformat(raw_date)
            except ValueError:
                continue
            return (datetime.now(UTC) - created).days
    return None


def _parse_retry_after(value: str | None) -> float | None:
    """Parse a Retry-After header (RFC 7231) — seconds or HTTP-date — into a
    non-negative wait duration. None on missing or unparseable input."""
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, (when - datetime.now(UTC)).total_seconds())


def _rdap_backoff_delay(attempt: int, retry_after: float | None) -> float:
    """Pick the next-attempt wait time. Server-supplied Retry-After wins."""
    if retry_after is not None:
        return retry_after
    base = _RDAP_BACKOFF_SECONDS[min(attempt, len(_RDAP_BACKOFF_SECONDS) - 1)]
    jitter = random.uniform(-_RDAP_JITTER_RATIO, _RDAP_JITTER_RATIO)
    return base * (1.0 + jitter)


def _rdap_age_days(domain: str) -> int | None:
    """RDAP lookup with jittered exponential backoff on transient failures.

    The domain is whitelisted against [A-Za-z0-9.-]{1,253} and percent-encoded
    before interpolation so attacker-controlled input cannot steer the request
    to a different rdap.org endpoint. Responses are streamed with a byte cap.

    Retries cover transient network failures and 429/5xx. 404 (and other 4xx)
    short-circuit: RDAP definitively has no record, so further attempts only
    waste the budget. A wall-clock cap keeps the worst case bounded per call.
    """
    if not _VALID_DOMAIN_RE.match(domain):
        return None
    quoted = quote(domain, safe="")
    url = f"https://rdap.org/domain/{quoted}"
    deadline = time.monotonic() + _RDAP_BUDGET_SECONDS

    for attempt in range(_RDAP_MAX_ATTEMPTS):
        if time.monotonic() >= deadline:
            return None
        retry_after: float | None = None
        try:
            # drawbridge enforces no-private-IP at every redirect hop, so the
            # rdap.org → registry-specific RDAP redirect can't be steered to
            # an internal address.
            with drawbridge.sync.stream(
                "GET",
                url,
                timeout=_RDAP_TIMEOUT,
                    headers={"Accept": "application/rdap+json"},
                max_response_bytes=_MAX_RDAP_RESPONSE_BYTES,
            ) as resp:
                if resp.status_code == 200:
                    data = _read_rdap_body(resp)
                    return _registration_age_days(data) if data is not None else None
                if resp.status_code in _RDAP_RETRY_STATUS:
                    retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
                else:
                    # 404 or other 4xx — definitive miss, no retry.
                    return None
        except (drawbridge.DrawbridgeError, httpx.HTTPError):
            # Transient network or policy failure — retry if budget permits.
            pass

        # Only reach here on transient failure. Bail unless another attempt
        # remains and the backoff fits in the remaining budget.
        if attempt + 1 >= _RDAP_MAX_ATTEMPTS:
            return None
        delay = _rdap_backoff_delay(attempt, retry_after)
        if time.monotonic() + delay >= deadline:
            return None
        if delay > 0:
            time.sleep(delay)
    return None


@lru_cache(maxsize=512)
def _cached_age_or_raise(domain: str) -> int:
    """LRU-cached RDAP lookup. Raises LookupError on miss so the failure
    is NOT memoized — lru_cache never stores exception results.
    """
    age = _rdap_age_days(domain)
    if age is None:
        raise LookupError(domain)
    return age


def domain_age_days(domain: str) -> int | None:
    """Return age of `domain` in days using RDAP, or None if unknown.

    Successful lookups are LRU-cached; failures (transient or otherwise) are
    retried on the next call so a single network blip doesn't poison the
    process-lifetime cache.
    """
    try:
        return _cached_age_or_raise(domain)
    except LookupError:
        return None


# Forward cache introspection to the underlying lru_cache so existing callers
# and tests can still inspect / clear it.
domain_age_days.cache_info = _cached_age_or_raise.cache_info  # type: ignore[attr-defined]
domain_age_days.cache_clear = _cached_age_or_raise.cache_clear  # type: ignore[attr-defined]


# Common URL shorteners. When a deceptive anchor (display text URL != href domain)
# is detected and the href points at one of these, we follow the redirect before
# deciding it's deceptive — the displayed URL may simply be the resolved target.
_SHORTENER_DOMAINS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "lnkd.in", "tiny.cc", "shorturl.at", "rebrand.ly",
    "cutt.ly", "rb.gy", "t.ly", "short.io", "shorturl.com",
    "amzn.to", "youtu.be", "fb.me", "wp.me", "trib.al",
})
_TRACKING_REDIRECTOR_DOMAINS = frozenset({
    "safelinks.protection.outlook.com",
    "google.com",
    "www.google.com",
    "sendgrid.net",
    "mandrillapp.com",
    "list-manage.com",
    "mailchi.mp",
    "facebook.com",
    "l.facebook.com",
    "lm.facebook.com",
    "click.mailgun.com",
    "urldefense.com",
    "urldefense.proofpoint.com",
    "nam10.safelinks.protection.outlook.com",
})
_KNOWN_REDIRECTOR_DOMAINS = _SHORTENER_DOMAINS | _TRACKING_REDIRECTOR_DOMAINS


@lru_cache(maxsize=512)
def _fetch_url(url: str, follow_redirects: bool = False) -> tuple[str, bool]:
    """Return (final_url_after_redirects, page_has_password_input).

    A single GET serves both the redirect-resolution and password-form checks
    so we never hit the same URL twice. Returns (url, False) on failure.

    ``follow_redirects`` defaults to **False**. A redirected GET completes
    on the *target* of the redirect, so following a shortener-style hop
    silently performs the action sitting at the end of the chain — and
    the user-supplied URL may have looked benign while the redirect's
    Location lands on ``/lock-account``. Callers that legitimately want
    the final URL (the shortener-resolution path) opt in explicitly with
    ``follow_redirects=True``.
    """
    if not url.startswith(("http://", "https://")):
        return url, False
    try:
        with drawbridge.sync.stream(
            "GET",
            url,
            timeout=_HTTP_TIMEOUT,
            headers=_BROWSER_HEADERS,
            max_response_bytes=_MAX_LINK_RESPONSE_BYTES,
            follow_redirects=follow_redirects,
        ) as resp:
            final_url = str(resp.url)
            content_type = resp.headers.get("Content-Type", "").lower()
            if not resp.is_success or "html" not in content_type:
                return final_url, False
            body = _read_link_response(resp)
    except (drawbridge.DrawbridgeError, httpx.HTTPError):
        return url, False
    soup = _parse_html(body)
    return final_url, _looks_like_login(soup, body)


# Catch credential prompts that hide behind `type="text"` plus a JS reveal,
# or that name the field naturally without setting the input type. The list
# stays static-HTML only — JS-rendered SPAs need a headless browser, see the
# Limitations section of the README.
_PASSWORD_NAME_RE = re.compile(r"\b(password|passwd|pwd|pass)\b", re.I)
_LOGIN_HINT_RE = re.compile(
    rb"""(?ix)
    (?: type \s* [:=] \s* ['"]password['"]      # JS literals: {type:"password"}
      | autocomplete \s* = \s* ['"]?current-password
      | autocomplete \s* = \s* ['"]?new-password
      | id \s* = \s* ['"]passwd ['"]?
      | <\s*input [^>]*\b name \s* = \s* ['"]?(password|passwd|pwd|pass)\b
    )
    """
)


def _looks_like_login(soup: BeautifulSoup, raw_body: bytes) -> bool:
    """Return True if the fetched page exposes a credential prompt.

    Static-HTML only. We look for the obvious `<input type=password>`, plus
    inputs whose name/id/placeholder/autocomplete betray a password field even
    when `type` is something else (a common evasion: `type="text"` flipped by
    JS on focus). We also scan the raw bytes for inline-script literals like
    `type:"password"` and HTML5 autocomplete hints. JavaScript-rendered SPAs
    still slip through — see README "Known limitations".
    """
    if soup.find("input", attrs={"type": re.compile(r"^password$", re.I)}):
        return True
    for inp in soup.find_all("input"):
        for attr in ("name", "id", "placeholder", "autocomplete"):
            value = inp.get(attr, "")
            if isinstance(value, str) and _PASSWORD_NAME_RE.search(value):
                return True
    return _LOGIN_HINT_RE.search(raw_body) is not None


def _read_link_response(resp: httpx.Response) -> bytes:
    remaining = _MAX_LINK_RESPONSE_BYTES
    chunks: list[bytes] = []
    for chunk in resp.iter_bytes(chunk_size=_LINK_RESPONSE_CHUNK_BYTES):
        if not chunk:
            continue
        chunks.append(chunk[:remaining])
        remaining -= len(chunks[-1])
        if remaining == 0:
            break
    return b"".join(chunks)


def has_password_form(url: str) -> bool:
    # Password-form detection: never follow redirects. A redirect-target
    # GET can complete a side-effect (lock account, unsubscribe, ...) that
    # the original URL didn't visibly express.
    return _fetch_url(url, follow_redirects=False)[1]


def resolve_final_url(url: str) -> str:
    # Shortener resolution: caller is asking specifically for the final
    # URL after the redirect chain, so following is opt-in here. Callers
    # gate this themselves (only known redirectors trigger it).
    return _fetch_url(url, follow_redirects=True)[0]


def analyze(
    text: str,
    young_domain_days: int = DEFAULT_YOUNG_DOMAIN_DAYS,
    raw_rfc822: bytes | None = None,
    check_link_domain_age: bool = True,
    check_password_form: bool = True,
) -> list[LinkFinding]:
    """Analyze links in `text`.

    - `check_link_domain_age` gates RDAP lookups for each link's registrable
      domain (no contact with the link itself).
    - `check_password_form` gates fetching each URL — needed for the password
      input check and for resolving redirector targets. Off means: no GET to
      the link's server, so your IP isn't exposed; redirectors get a generic
      "not resolved" warning instead.
    """
    # Build the "do not fetch" set once. Three signals contribute:
    #   1. URLs in the `List-Unsubscribe` header (RFC 8058 one-click).
    #   2. URL path/query patterns we recognise as state-changing.
    #   3. Anchor whose containing paragraph carries an action verb
    #      ("click here to lock your account") — surrounding prose is
    #      often the only intent signal when the URL itself is opaque.
    # Any URL in this set will skip `has_password_form` (and any other
    # GET) even when phase 3 of the gate is enabled.
    do_not_fetch: set[str] = set()
    if check_password_form and raw_rfc822 is not None:
        do_not_fetch |= _extract_unsubscribe_urls(raw_rfc822)
        do_not_fetch |= _collect_action_context_urls(raw_rfc822)

    findings: list[LinkFinding] = []
    seen_urls: set[str] = set()

    def _fetch_ok(url: str) -> bool:
        return check_password_form and not _is_unsafe_to_fetch(url, do_not_fetch)

    for url in extract_links(text):
        if url in seen_urls:
            continue
        seen_urls.add(url)
        findings.append(_link_finding(
            url, young_domain_days=young_domain_days,
            check_link_domain_age=check_link_domain_age,
            check_password_form=_fetch_ok(url),
        ))
    if raw_rfc822 is not None:
        subject = ""
        try:
            subject = str(email.message_from_bytes(raw_rfc822, policy=policy.default)
                          .get("Subject", "") or "")
        except Exception:  # noqa: BLE001
            subject = ""
        for url in extract_links(subject):
            if url in seen_urls:
                continue
            seen_urls.add(url)
            f = _link_finding(
                url, young_domain_days=young_domain_days,
                check_link_domain_age=check_link_domain_age,
                check_password_form=_fetch_ok(url),
            )
            # Surface origin so the analysis banner makes it clear the URL came
            # from a place a recipient would not normally expect to see one.
            f.warnings.insert(0, UrlInSubject(domain=f.domain))
            findings.append(f)
        _attach_anchor_deception_warnings(
            findings, raw_rfc822,
            resolve_redirectors=check_password_form,
            do_not_fetch=do_not_fetch,
        )
        _attach_message_warnings(findings, raw_rfc822, text)
    return findings


def _link_finding(
    url: str,
    *,
    young_domain_days: int,
    check_link_domain_age: bool,
    check_password_form: bool,
) -> LinkFinding:
    host = urlparse(url).hostname or ""
    domain = registrable_domain(host) if host else ""
    # A real registrable domain always contains a dot. A URL like
    # `https://https//www.finance.si/...` — produced by trackers that
    # double-prefix the scheme — gets parsed as host="https"/domain="https".
    # Skip RDAP, password-form fetch, and warning emission for such
    # not-actually-a-domain strings; the finding is still recorded so
    # the URL is known to the defang pipeline.
    real_domain = "." in domain
    if not real_domain:
        return LinkFinding(url, host, domain, None, False, [])
    age = domain_age_days(domain) if check_link_domain_age else None
    pwd = has_password_form(url) if check_password_form else False
    warnings: list[Warning] = []
    if check_link_domain_age:
        if age is None:
            warnings.append(YoungDomain(domain=domain, age_days=None))
        elif age < young_domain_days:
            warnings.append(YoungDomain(domain=domain, age_days=age))
    if pwd:
        warnings.append(PasswordForm(domain=domain))
    if check_password_form:
        resolved = _redirector_final_domain(url, host, domain)
        if resolved:
            warnings.append(RedirectorResolves(domain=domain, final_domain=resolved))
    elif _is_known_redirector(host, domain):
        warnings.append(RedirectorResolves(domain=domain, final_domain=""))
    return LinkFinding(url, host, domain, age, pwd, warnings)


def _attach_message_warnings(
    findings: list[LinkFinding],
    raw_rfc822: bytes,
    body_text: str,
) -> None:
    msg = email.message_from_bytes(raw_rfc822, policy=policy.default)
    warnings: list[Warning] = []
    reply_to_domain = _header_address_domain(msg, "Reply-To")
    from_domain = _header_address_domain(msg, "From")
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        warnings.append(HeaderAnomaly(
            f"reply-to domain {reply_to_domain} differs from from domain {from_domain}"
        ))

    phrases = _pressure_phrases(str(msg.get("Subject", "")), body_text)
    if phrases:
        warnings.append(HeaderAnomaly(
            f"time/payment pressure language: {', '.join(phrases)}"
        ))

    if warnings:
        findings.append(
            LinkFinding(
                url="message:headers",
                host="",
                domain="",
                age_days=None,
                has_password_form=False,
                warnings=warnings,
            )
        )


def _pressure_phrases(*texts: str) -> list[str]:
    seen: set[str] = set()
    phrases: list[str] = []
    for text in texts:
        for match in _PRESSURE_RE.finditer(text):
            phrase = match.group(1).lower()
            if phrase not in seen:
                seen.add(phrase)
                phrases.append(phrase)
    return phrases


_HREF_STRIPPABLE_CHARS = "".join(chr(c) for c in (0x09, 0x0A, 0x0D)) + "​‌‍⁠﻿"
_HREF_STRIPPABLE_TABLE = str.maketrans("", "", _HREF_STRIPPABLE_CHARS)


def _normalize_href(href: str) -> str:
    """Match browser parsing: drop TAB/CR/LF and zero-width characters from
    URLs before host inspection. WHATWG URL parsing strips these silently,
    so a sender can smuggle `https://safe.com<TAB>.evil.com/` past a naive
    `urlparse(...).hostname` check that would otherwise return `safe.com`.
    """
    return href.strip().translate(_HREF_STRIPPABLE_TABLE)


def _extract_html_anchors(raw_rfc822: bytes) -> list[tuple[str, str]]:
    """Return (href, anchor_text) pairs from every text/html part."""
    pairs: list[tuple[str, str]] = []
    msg = email.message_from_bytes(raw_rfc822, policy=policy.default)
    for part in msg.walk() if msg.is_multipart() else [msg]:
        if part.get_content_type() != "text/html":
            continue
        try:
            html = part.get_content()
        except (LookupError, UnicodeDecodeError):
            continue
        soup = _parse_html(html)
        for a in soup.find_all("a", href=True):
            href = _normalize_href(a["href"])
            text = a.get_text(separator=" ").strip()
            if href and text:
                pairs.append((href, text))
    return pairs


def _attach_anchor_deception_warnings(
    findings: list[LinkFinding],
    raw_rfc822: bytes,
    resolve_redirectors: bool = True,
    do_not_fetch: set[str] | frozenset[str] = frozenset(),
) -> None:
    """For each <a href=X>...text-with-URL...</a> where the displayed URL's
    registrable domain differs from X's, append a warning to the finding for X.

    When X is a known shortener and `resolve_redirectors` is True, follow X's
    redirects: if the final domain matches the displayed one, suppress the
    warning (legitimate short link). When `resolve_redirectors` is False, no
    fetch happens, so shortener cases yield a plain displayed/href mismatch.

    ``do_not_fetch`` lists URLs that must never be GET'd regardless of
    the redirector flag — typically because the surrounding prose or
    URL pattern indicates the click would trigger an action.
    """
    findings_by_url = {f.url: f for f in findings}
    for href, anchor_text in _extract_html_anchors(raw_rfc822):
        text_urls = extract_links(anchor_text)
        if not text_urls:
            continue
        href_host = urlparse(href).hostname or ""
        href_domain = registrable_domain(href_host)
        if not href_domain:
            continue
        for displayed in text_urls:
            disp_domain = registrable_domain(urlparse(displayed).hostname or "")
            if not disp_domain or disp_domain == href_domain:
                continue
            href_unsafe = (
                href in do_not_fetch
                or _is_unsafe_to_fetch(href, do_not_fetch)
            )
            if (
                _is_known_redirector(href_host, href_domain)
                and resolve_redirectors
                and not href_unsafe
            ):
                final = resolve_final_url(href)
                final_domain = registrable_domain(urlparse(final).hostname or "")
                if final_domain == disp_domain:
                    continue  # shortener resolved to what the display promised
                if final_domain and final_domain != href_domain:
                    warning = LinkTextMismatch(
                        displayed=disp_domain,
                        actual=final_domain,
                        via_redirector=True,
                    )
                    target = findings_by_url.get(href)
                    if target is not None and warning not in target.warnings:
                        target.warnings.append(warning)
                    continue
            warning = LinkTextMismatch(
                displayed=disp_domain, actual=href_domain, via_redirector=False,
            )
            target = findings_by_url.get(href)
            if target is not None and warning not in target.warnings:
                target.warnings.append(warning)


def _redirector_final_domain(url: str, host: str, domain: str) -> str:
    """Resolve a known redirector to its final registrable domain, or "" if N/A."""
    if not _is_known_redirector(host, domain):
        return ""
    final = resolve_final_url(url)
    final_domain = registrable_domain(urlparse(final).hostname or "")
    if not final_domain or final_domain == domain:
        return ""
    return final_domain


def _is_known_redirector(host: str, domain: str) -> bool:
    normalized_host = host.lower().rstrip(".")
    normalized_domain = domain.lower().rstrip(".")
    return (
        normalized_host in _KNOWN_REDIRECTOR_DOMAINS
        or normalized_domain in _KNOWN_REDIRECTOR_DOMAINS
    )


def html_to_text(html: str, reveal_hrefs: bool = True) -> str:
    """Flatten HTML to plain text.

    When `reveal_hrefs` is True (default) each anchor's href is appended next
    to its visible label, so a misleading link can't hide its destination.
    When False, anchors render as just their label text — no href, no
    clickable URL leaks into the output.
    """
    soup = _parse_html(html)
    for tag in soup(["script", "style", "head"]):
        tag.decompose()
    if reveal_hrefs:
        for a in soup.find_all("a"):
            href = a.get("href", "")
            if href:
                a.append(NavigableString(f" [{href}]"))
    return soup.get_text(separator="\n")


def message_body(raw_rfc822: bytes) -> tuple[str, str]:
    """Return (content, subtype) where subtype is 'html' or 'plain'.

    HTML wins when both are present: it's the structure phishers actually
    style, and preserving it keeps the rewritten message visually faithful
    to the original. Falls back to plain text otherwise; ('', 'plain') if
    neither part exists or both fail to decode.
    """
    msg = email.message_from_bytes(raw_rfc822, policy=policy.default)
    plain: list[str] = []
    html: list[str] = []
    for part in msg.walk() if msg.is_multipart() else [msg]:
        ct = part.get_content_type()
        if ct == "text/plain":
            try:
                plain.append(part.get_content())
            except (LookupError, UnicodeDecodeError):
                pass
        elif ct == "text/html":
            try:
                html.append(part.get_content())
            except (LookupError, UnicodeDecodeError):
                pass
    if html:
        return "\n".join(html), "html"
    if plain:
        return "\n".join(plain), "plain"
    return "", "plain"


def message_body_text(raw_rfc822: bytes, reveal_hrefs: bool = True) -> str:
    """Return a flattened text view of an RFC822 message.

    When `reveal_hrefs` is False, HTML anchors are stripped to their visible
    label only — no href is included in the output. Used for neutralized
    display when we don't trust the sender.
    """
    msg = email.message_from_bytes(raw_rfc822, policy=policy.default)
    plain: list[str] = []
    html: list[str] = []
    for part in msg.walk() if msg.is_multipart() else [msg]:
        ct = part.get_content_type()
        if ct == "text/plain":
            try:
                plain.append(part.get_content())
            except (LookupError, UnicodeDecodeError):
                pass
        elif ct == "text/html":
            try:
                html.append(part.get_content())
            except (LookupError, UnicodeDecodeError):
                pass
    if plain:
        return "\n".join(plain)
    return "\n".join(html_to_text(h, reveal_hrefs=reveal_hrefs) for h in html)


# Suffix appended to a URL's hostname to neutralise it. ``.invalid`` is
# reserved by RFC 6761 so no real DNS resolver can ever map it to an
# address — clicking the rewritten link yields a DNS failure instead of
# reaching the attacker's host. The leading dot keeps the original
# hostname as a clearly visible label inside the new name, so the
# recipient can read what was meant to be reached and, if they choose,
# strip the suffix back off to navigate. Configurable via
# ``defang_url_suffix`` in config.toml.
_DEFAULT_DEFANG_SUFFIX = ".REMOVE-TO-VISIT.invalid"

_DEFANGABLE_SCHEMES = ("http://", "https://", "ftp://", "ftps://", "sftp://")


def defang(text: str, suffix: str = _DEFAULT_DEFANG_SUFFIX) -> str:
    """Neutralise URLs in `text` by appending `suffix` to each hostname.

    The scheme is left intact (``https://`` stays ``https://``) so email
    clients with strict URL allowlists — Gmail, OWA — keep treating the
    anchor as a real link. The hostname is the part we mangle: a default
    suffix of ``.REMOVE-TO-VISIT.invalid`` guarantees DNS failure, and the
    recipient can see what the original hostname was just by reading the
    URL. Pass a different `suffix` (e.g. ``.example``) to customise.
    """
    return _LINK_RE.sub(lambda m: _defang_one(m.group(1), suffix), text)


def _defang_one(url: str, suffix: str) -> str:
    """Append `suffix` to the hostname inside `url`, preserving the rest."""
    # `_LINK_RE` may have swept up trailing punctuation that's not really
    # part of the URL (e.g. ``https://x.com.`` at the end of a sentence).
    # Strip it for parsing, re-attach after, so we don't double-up dots.
    trailing = ""
    while url and url[-1] in _TRAILING_PUNCT:
        trailing = url[-1] + trailing
        url = url[:-1]
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        return url + trailing
    auth = ""
    if parsed.username is not None:
        auth = parsed.username
        if parsed.password is not None:
            auth += f":{parsed.password}"
        auth += "@"
    port = f":{parsed.port}" if parsed.port else ""
    new_netloc = f"{auth}{host}{suffix}{port}"
    return urlunparse(parsed._replace(netloc=new_netloc)) + trailing


def defang_html(
    html: str,
    urls_to_defang: set[str],
    neutralize_all: bool,
    suffix: str = _DEFAULT_DEFANG_SUFFIX,
) -> str:
    """Defang URLs in an HTML body while preserving structure.

    Two vectors get neutralized:
      - `<a href>` — the click target; defanging the scheme breaks the click.
      - URLs appearing as visible text inside any element.

    `<img src>` is deliberately left alone: rewriting the scheme would just
    break image rendering without preventing anything a user can act on.
    Tracking-pixel suppression is a separate concern (strip the `<img>` tag
    entirely if you want that) and doesn't belong in URL defang.

    `neutralize_all=True` defangs every URL we can find; otherwise only those
    in `urls_to_defang` are touched. The surrounding HTML (layout, fonts,
    inline images of the brand we're impersonating) is left intact so the
    rewritten message still looks like the original — just no longer clickable.
    """
    soup = _parse_html(html)

    def hit(u: str) -> bool:
        return neutralize_all or u in urls_to_defang

    for a in soup.find_all("a", href=True):
        href = a["href"]
        # Only act on web-scheme anchors. mailto:, tel:, javascript:, and
        # in-document fragments don't fit the defang model — touching them
        # mangles email addresses rendered as `<a href="mailto:…">…</a>`
        # and tooltip-style links the sender styled themselves.
        if not href.lower().startswith(_DEFANGABLE_SCHEMES):
            continue
        if hit(_normalize_href(href)):
            a["href"] = _defang_one(href, suffix)
            # Anchor contents (button text, inline image, styled span) are
            # left intact so the recipient sees the original layout. The
            # rewritten href still has the original scheme (so Gmail's
            # sanitizer keeps the anchor clickable) but resolves to an
            # ``.invalid`` host that will never connect anywhere.
    # Visible-text URLs. Walk text nodes once; skip script/style which can
    # contain URL-shaped tokens that aren't meant to be clicked.
    for txt in list(soup.find_all(string=True)):
        if txt.parent is None or txt.parent.name in ("script", "style"):
            continue
        original = str(txt)
        if "://" not in original:
            continue
        if neutralize_all:
            replaced = defang(original, suffix)
        else:
            replaced = original
            for u in urls_to_defang:
                replaced = replaced.replace(u, _defang_one(u, suffix))
        if replaced != original:
            txt.replace_with(replaced)
    return str(soup)


# Smallest possible transparent GIF (43 bytes). Used to replace tracking-pixel
# src values so the tag still renders to a 1×1 invisible image but the client
# never reaches out to the attacker's tracking endpoint. Data URIs don't fetch.
_TRANSPARENT_1X1_GIF = (
    "data:image/gif;base64,"
    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
)
_HIDDEN_STYLE_RE = re.compile(
    r"(?i)(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?\b)"
)
_SMALL_DIM_RE = re.compile(r"(?i)(?:width|height)\s*:\s*[01](?:px)?\b")


def _is_tracking_pixel(img) -> bool:
    """True when an `<img>` is shaped like a tracking beacon — 1×1, hidden,
    or explicitly opaque-zero. False positives here would replace a legit
    icon's src with a blank, so the rules are deliberately narrow."""
    style = (img.get("style") or "").strip()
    if style and _HIDDEN_STYLE_RE.search(style):
        return True
    w_attr = (img.get("width") or "").strip().lower()
    h_attr = (img.get("height") or "").strip().lower()
    if w_attr in ("0", "1") and h_attr in ("0", "1"):
        return True
    if style:
        small_dims = _SMALL_DIM_RE.findall(style)
        # Need both width AND height called out as tiny — a 1px border on an
        # icon shouldn't trip this.
        kinds = {m.split(":")[0].strip().lower() for m in small_dims}
        if {"width", "height"}.issubset(kinds):
            return True
    return False


def neutralize_tracking_pixels(html: str) -> tuple[str, int]:
    """Replace each tracking-pixel `<img src>` with a transparent data URI.

    Returns (rewritten_html, count_of_neutralized_images). The tag is kept in
    place so the surrounding layout isn't disturbed; only the src is swapped.
    """
    soup = _parse_html(html)
    count = 0
    for img in soup.find_all("img", src=True):
        if _is_tracking_pixel(img):
            img["src"] = _TRANSPARENT_1X1_GIF
            count += 1
    return str(soup), count


def annotate_html(html: str, findings: list[LinkFinding]) -> str:
    """Append a ⚠ tooltip span after each `<a>` whose href is in `findings`.

    The anchor itself is left strictly untouched — no attribute, content, or
    style change — so the sender's button captions, existing tooltips, and
    layout survive verbatim. The warning lives on a sibling ``<span>⚠</span>``
    inserted directly after the anchor; its ``title`` attribute carries the
    original href plus the warning text. On Gmail web, OWA, Apple Mail, and
    Thunderbird the recipient sees the small red triangle and can hover it
    for the tooltip. Mobile clients have no hover surface, but the icon is
    still a visible "this link was flagged" cue.

    Plain text bodies still get the inline ``[WARNING: ...]`` marker — see
    :func:`annotate` — because text has no DOM to attach a sibling to.
    """
    soup = _parse_html(html)
    by_url = {f.url: f for f in findings if f.warnings}
    for a in soup.find_all("a", href=True):
        href = _normalize_href(a["href"])
        finding = by_url.get(href)
        if finding is None:
            continue
        message = (
            f"{href} WARNING: "
            + "; ".join(str(w) for w in finding.warnings)
        )
        marker = soup.new_tag(
            "span",
            attrs={
                "title": message,
                "style": "color:#c00; font-weight:bold; margin-left:2px;",
            },
        )
        marker.string = "⚠"
        a.insert_after(marker)
    return str(soup)


def annotate(text: str, findings: list[LinkFinding]) -> str:
    """Append ' [WARNING: ...]' after each URL in `text` that has warnings.

    The URL itself is left untouched.
    """
    out = text
    for f in findings:
        if not f.warnings:
            continue
        tag = f" [WARNING: {'; '.join(str(w) for w in f.warnings)}]"
        out = out.replace(f.url, f.url + tag, 1)
    return out
