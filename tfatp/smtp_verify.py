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
# Per-SMTP-operation timeout (connect + each command). Probes that block at the
# TCP layer (firewall blackholes) cap out here.
DEFAULT_TIMEOUT = 4.0
# DNS lookups (MX, A) have their own lifetime independent of the SMTP timeout.
# Resolver default is ~30s, which dominates total runtime when networks blackhole
# UDP/53 — cap it tight so the gate doesn't stall.
DNS_LIFETIME = 3.0


@dataclass(frozen=True, slots=True)
class SmtpVerifyResult:
    status: str  # pass | rejected | unreachable | no_mx | error
    detail: str

    @property
    def ok(self) -> bool:
        return self.status == "pass"


def _resolver() -> dns_resolver.Resolver:
    r = dns_resolver.Resolver()
    r.lifetime = DNS_LIFETIME
    r.timeout = DNS_LIFETIME
    return r


def _mx_hosts(domain: str) -> list[str]:
    r = _resolver()
    try:
        answers = r.resolve(domain, "MX")
        return [str(rr.exchange).rstrip(".") for rr in sorted(answers, key=lambda x: x.preference)]
    except DNSException:
        pass
    # RFC 5321: if no MX, fall back to the implicit A record.
    try:
        r.resolve(domain, "A")
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
    r = _resolver()
    raw_ips: list[str] = []
    for qtype in ("A", "AAAA"):
        try:
            answers = r.resolve(host, qtype)
        except DNSException:
            continue
        raw_ips.extend(str(rr) for rr in answers)
    if not raw_ips:
        return False, f"{host} DNS resolution returned no addresses"
    for raw_ip in raw_ips:
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


# Hosts to probe for outbound SMTP reachability at startup. Both are public
# Google endpoints — any environment that can do SMTP callouts will reach at
# least one of them on at least one of the configured SMTP_PORTS.
_CONNECTIVITY_HOSTS = ("aspmx.l.google.com", "smtp.gmail.com")
_CONNECTIVITY_TIMEOUT = 3.0


def can_smtp_callout() -> tuple[set[int], str]:
    """Probe known-good MX/submission hosts to see which SMTP ports are open.

    Returns (reachable_ports, detail). An empty set means every probe failed —
    the network blocks outbound SMTP entirely (residential ISPs and most cloud
    providers block 25 by default; some also restrict 587). When 25 is
    unreachable, smtp_verify will time out on every real probe, so callers
    should disable it rather than eat the per-MX timeout on each message.
    """
    reachable: set[int] = set()
    details: list[str] = []
    for host in _CONNECTIVITY_HOSTS:
        for port in SMTP_PORTS:
            if port in reachable:
                continue
            try:
                with socket.create_connection((host, port), timeout=_CONNECTIVITY_TIMEOUT):
                    reachable.add(port)
                    details.append(f"{host}:{port} ok")
            except OSError as exc:
                details.append(f"{host}:{port} {exc!r}")
    return reachable, "; ".join(details)
