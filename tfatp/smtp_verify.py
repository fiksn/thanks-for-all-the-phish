"""Verify that the From address of a message actually exists on its MX server.

We look up the MX records for the sender's domain, connect to each in turn on
TCP 587 then 25, say HELO/EHLO, issue MAIL FROM with our identity and RCPT TO
with the sender's address, then RSET and QUIT.

We never send DATA — so no mail is generated. This is the "SMTP callout" /
"sender address verification" technique. Some servers refuse it and some
operators consider it abusive; use with judgement.

Return values:
- pass         — server accepted RCPT TO
- rejected     — server returned 5xx for RCPT TO (mailbox doesn't exist)
- unreachable  — all MX hosts failed to connect or timed out
- no_mx        — domain has neither MX nor A records
- error        — malformed input or unexpected SMTP error
"""

import smtplib
import socket
from dataclasses import dataclass
from functools import lru_cache
from ipaddress import ip_address

from dns import resolver as dns_resolver
from dns.exception import DNSException

SMTP_PORTS = (587, 25)
DEFAULT_TIMEOUT = 8.0


@dataclass(frozen=True, slots=True)
class SmtpVerifyResult:
    status: str  # pass | rejected | unreachable | no_mx | error
    detail: str

    @property
    def ok(self) -> bool:
        return self.status == "pass"


def _mx_hosts(domain: str) -> list[str]:
    try:
        answers = dns_resolver.resolve(domain, "MX")
        return [str(r.exchange).rstrip(".") for r in sorted(answers, key=lambda r: r.preference)]
    except DNSException:
        pass
    # RFC 5321: if no MX, fall back to the implicit A record.
    try:
        dns_resolver.resolve(domain, "A")
        return [domain]
    except DNSException:
        return []


def _probe(host: str, port: int, mail_from: str, rcpt_to: str, helo_domain: str,
           timeout: float) -> tuple[str, str]:
    """Return (status, detail) for a single host:port probe."""
    smtp = smtplib.SMTP(host, port, timeout=timeout, local_hostname=helo_domain)
    try:
        code, _ = smtp.ehlo(helo_domain)
        if code >= 400:
            smtp.helo(helo_domain)
        code, msg = smtp.mail(mail_from)
        if code >= 400:
            return "error", f"{host}:{port} MAIL FROM rejected {code} {_decode(msg)}"
        code, msg = smtp.rcpt(rcpt_to)
        # Always reset and quit cleanly — never call smtp.data().
        try:
            smtp.rset()
        except smtplib.SMTPException:
            pass
        if 200 <= code < 300:
            return "pass", f"{host}:{port} accepted RCPT {rcpt_to}"
        if 500 <= code < 600:
            return "rejected", f"{host}:{port} rejected RCPT {code} {_decode(msg)}"
        return "unreachable", f"{host}:{port} temp {code} {_decode(msg)}"
    finally:
        try:
            smtp.quit()
        except smtplib.SMTPException:
            try:
                smtp.close()
            except OSError:
                pass


def _decode(b: bytes | str) -> str:
    if isinstance(b, bytes):
        return b.decode("utf-8", errors="replace").strip()
    return str(b).strip()


def _host_has_only_public_addresses(host: str) -> tuple[bool, str]:
    try:
        addrinfos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        return False, f"{host} DNS resolution failed {exc!r}"
    if not addrinfos:
        return False, f"{host} DNS resolution returned no addresses"
    for addrinfo in addrinfos:
        raw_ip = addrinfo[4][0]
        ip = ip_address(raw_ip)
        mapped = getattr(ip, "ipv4_mapped", None)
        if mapped is not None:
            ip = mapped
        if not ip.is_global or ip.is_multicast:
            return False, f"{host} resolves to non-public address {raw_ip}"
    return True, ""


def _verify_uncached(from_address: str, mail_from: str, helo_domain: str,
                     timeout: float) -> SmtpVerifyResult:
    if "@" not in from_address:
        return SmtpVerifyResult("error", f"malformed From address {from_address!r}")
    domain = from_address.rsplit("@", 1)[1].lower()
    hosts = _mx_hosts(domain)
    if not hosts:
        return SmtpVerifyResult("no_mx", f"no MX or A record for {domain}")

    last_detail = ""
    for host in hosts:
        host_is_safe, detail = _host_has_only_public_addresses(host)
        if not host_is_safe:
            last_detail = detail
            continue
        for port in SMTP_PORTS:
            try:
                status, detail = _probe(host, port, mail_from, from_address,
                                        helo_domain, timeout)
            except (socket.timeout, ConnectionRefusedError, OSError,
                    smtplib.SMTPException) as exc:
                last_detail = f"{host}:{port} {exc!r}"
                continue
            if status in ("pass", "rejected"):
                return SmtpVerifyResult(status, detail)
            last_detail = detail
    return SmtpVerifyResult("unreachable", last_detail or "all MX hosts failed")


class _Transient(Exception):
    """Raised so lru_cache doesn't memoize transient failures."""


@lru_cache(maxsize=512)
def _verify_cached(from_address: str, mail_from: str, helo_domain: str,
                   timeout: float) -> SmtpVerifyResult:
    result = _verify_uncached(from_address, mail_from, helo_domain, timeout)
    if result.status in ("unreachable", "error"):
        raise _Transient(result.detail)
    return result


def verify_sender(from_address: str, mail_from: str, helo_domain: str,
                  timeout: float = DEFAULT_TIMEOUT) -> SmtpVerifyResult:
    """Cache-safe entry point. Only definitive results (pass / rejected / no_mx)
    are cached — transient failures retry on every call.
    """
    try:
        return _verify_cached(from_address, mail_from, helo_domain, timeout)
    except _Transient as exc:
        return SmtpVerifyResult("unreachable", str(exc))


verify_sender.cache_info = _verify_cached.cache_info  # type: ignore[attr-defined]
verify_sender.cache_clear = _verify_cached.cache_clear  # type: ignore[attr-defined]
