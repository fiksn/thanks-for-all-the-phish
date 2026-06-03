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
from urllib.parse import quote, urlparse

import drawbridge
import drawbridge.sync
import httpx
import tldextract
from bs4 import BeautifulSoup, NavigableString

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
class LinkFinding:
    url: str
    host: str
    domain: str
    age_days: int | None
    has_password_form: bool
    warnings: list[str] = field(default_factory=list)


def _parse_html(content: str | bytes) -> BeautifulSoup:
    """Bound the HTML byte size before handing it to BeautifulSoup.

    bs4 has no upstream cap and will happily build a DOM for hostile inputs
    that nest tags millions deep or repeat attributes endlessly. Truncating
    at a fixed size keeps parse time and memory predictable regardless of
    sender intent. A truncated suffix may yield malformed tail tokens; bs4
    handles those gracefully.
    """
    if isinstance(content, str):
        encoded = content.encode("utf-8", errors="replace")
        truncated = encoded[:_MAX_HTML_PARSE_BYTES]
        return BeautifulSoup(truncated.decode("utf-8", errors="replace"), "html.parser")
    return BeautifulSoup(content[:_MAX_HTML_PARSE_BYTES], "html.parser")


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
def _fetch_url(url: str) -> tuple[str, bool]:
    """Return (final_url_after_redirects, page_has_password_input).

    A single GET serves both the redirect-resolution and password-form checks
    so we never hit the same URL twice. Returns (url, False) on failure.
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
        ) as resp:
            final_url = str(resp.url)
            content_type = resp.headers.get("Content-Type", "").lower()
            if not resp.is_success or "html" not in content_type:
                return final_url, False
            body = _read_link_response(resp)
    except (drawbridge.DrawbridgeError, httpx.HTTPError):
        return url, False
    soup = _parse_html(body)
    has_pwd = soup.find("input", attrs={"type": re.compile(r"^password$", re.I)}) is not None
    return final_url, has_pwd


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
    return _fetch_url(url)[1]


def resolve_final_url(url: str) -> str:
    return _fetch_url(url)[0]


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
    findings: list[LinkFinding] = []
    for url in extract_links(text):
        host = urlparse(url).hostname or ""
        domain = registrable_domain(host) if host else ""
        age = domain_age_days(domain) if (domain and check_link_domain_age) else None
        pwd = has_password_form(url) if check_password_form else False
        warnings: list[str] = []
        if check_link_domain_age and domain:
            if age is None:
                warnings.append(f"young domain - age unknown for {domain} (treated as too young)")
            elif age < young_domain_days:
                warnings.append(f"young domain - {age}d")
        if pwd:
            warnings.append("form contains password input field")
        if check_password_form:
            redirect_warning = _redirector_warning(url, host, domain)
            if redirect_warning:
                warnings.append(redirect_warning)
        elif _is_known_redirector(host, domain):
            warnings.append("redirector/tracking URL (not resolved — link fetch gated off)")
        findings.append(LinkFinding(url, host, domain, age, pwd, warnings))
    if raw_rfc822 is not None:
        _attach_anchor_deception_warnings(
            findings, raw_rfc822, resolve_redirectors=check_password_form
        )
        _attach_message_warnings(findings, raw_rfc822, text)
    return findings


def _attach_message_warnings(
    findings: list[LinkFinding],
    raw_rfc822: bytes,
    body_text: str,
) -> None:
    msg = email.message_from_bytes(raw_rfc822, policy=policy.default)
    warnings: list[str] = []
    reply_to_domain = _header_address_domain(msg, "Reply-To")
    from_domain = _header_address_domain(msg, "From")
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        warnings.append(f"reply-to domain {reply_to_domain} differs from from domain {from_domain}")

    phrases = _pressure_phrases(str(msg.get("Subject", "")), body_text)
    if phrases:
        warnings.append(f"time/payment pressure language: {', '.join(phrases)}")

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
    findings: list[LinkFinding], raw_rfc822: bytes, resolve_redirectors: bool = True
) -> None:
    """For each <a href=X>...text-with-URL...</a> where the displayed URL's
    registrable domain differs from X's, append a warning to the finding for X.

    When X is a known shortener and `resolve_redirectors` is True, follow X's
    redirects: if the final domain matches the displayed one, suppress the
    warning (legitimate short link). When `resolve_redirectors` is False, no
    fetch happens, so shortener cases yield a plain displayed/href mismatch.
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
            if _is_known_redirector(href_host, href_domain) and resolve_redirectors:
                final = resolve_final_url(href)
                final_domain = registrable_domain(urlparse(final).hostname or "")
                if final_domain == disp_domain:
                    continue  # shortener resolved to what the display promised
                if final_domain and final_domain != href_domain:
                    warning = (
                        f"link text shows {disp_domain} but redirector resolves to "
                        f"{final_domain}"
                    )
                    target = findings_by_url.get(href)
                    if target is not None and warning not in target.warnings:
                        target.warnings.append(warning)
                    continue
            warning = f"link text shows {disp_domain} but href points to {href_domain}"
            target = findings_by_url.get(href)
            if target is not None and warning not in target.warnings:
                target.warnings.append(warning)


def _redirector_warning(url: str, host: str, domain: str) -> str:
    if not _is_known_redirector(host, domain):
        return ""
    final = resolve_final_url(url)
    final_domain = registrable_domain(urlparse(final).hostname or "")
    if not final_domain or final_domain == domain:
        return ""
    return f"redirector/tracking URL resolves to {final_domain}"


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


_DEFANG = {
    "http://": "hxxp://",
    "https://": "hxxps://",
    "ftp://": "fxp://",
    "ftps://": "fxps://",
    "sftp://": "sxftp://",
}


def defang(text: str) -> str:
    """Replace URL scheme separators so most terminals stop auto-linking them."""
    out = text
    for src, dst in _DEFANG.items():
        out = out.replace(src, dst)
    return out


def defang_html(html: str, urls_to_defang: set[str], neutralize_all: bool) -> str:
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
        if hit(_normalize_href(a["href"])):
            a["href"] = defang(a["href"])
    # Visible-text URLs. Walk text nodes once; skip script/style which can
    # contain URL-shaped tokens that aren't meant to be clicked.
    for txt in list(soup.find_all(string=True)):
        if txt.parent is None or txt.parent.name in ("script", "style"):
            continue
        original = str(txt)
        if "://" not in original:
            continue
        if neutralize_all:
            replaced = defang(original)
        else:
            replaced = original
            for u in urls_to_defang:
                replaced = replaced.replace(u, defang(u))
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
    """Insert a red warning marker after each `<a>` whose href appears in
    `findings` with attached warnings. Leaves the anchor itself untouched."""
    soup = _parse_html(html)
    by_url = {f.url: f for f in findings if f.warnings}
    for a in soup.find_all("a", href=True):
        finding = by_url.get(_normalize_href(a["href"]))
        if finding is None:
            continue
        marker = soup.new_tag(
            "span",
            attrs={"style": "color:#c00; font-weight:bold; font-size:90%;"},
        )
        marker.string = f" [WARNING: {'; '.join(finding.warnings)}]"
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
        tag = f" [WARNING: {'; '.join(f.warnings)}]"
        out = out.replace(f.url, f.url + tag, 1)
    return out
