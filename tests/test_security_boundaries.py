import contextlib
from collections.abc import Iterator

from tfatp import link_analysis, smtp_verify
from tfatp.link_analysis import (
    HeaderAnomaly,
    LinkTextMismatch,
    RedirectorResolves,
    _MAX_LINK_RESPONSE_BYTES,
)


class _Response:
    def __init__(self, chunks: list[bytes]) -> None:
        self.url = "https://example.com/login"
        self.is_success = True
        self.headers = {"Content-Type": "text/html; charset=utf-8"}
        self._chunks = chunks

    def iter_bytes(self, chunk_size: int) -> Iterator[bytes]:
        assert chunk_size == 8192
        yield from self._chunks


def test_fetch_url_detects_password_form_with_drawbridge_stream(monkeypatch):
    link_analysis._fetch_url.cache_clear()

    @contextlib.contextmanager
    def stream(method: str, url: str, **kwargs):
        assert method == "GET"
        assert url == "https://example.com/login"
        assert kwargs["max_response_bytes"] == _MAX_LINK_RESPONSE_BYTES
        yield _Response([b"<form><input type='password'></form>"])

    monkeypatch.setattr(link_analysis.drawbridge.sync, "stream", stream)

    assert link_analysis._fetch_url("https://example.com/login") == (
        "https://example.com/login",
        True,
    )


def test_fetch_url_ignores_password_form_after_response_cap(monkeypatch):
    link_analysis._fetch_url.cache_clear()

    @contextlib.contextmanager
    def stream(method: str, url: str, **kwargs):
        yield _Response([b"a" * _MAX_LINK_RESPONSE_BYTES + b"<input type='password'>"])

    monkeypatch.setattr(link_analysis.drawbridge.sync, "stream", stream)

    assert link_analysis._fetch_url("https://example.com/login") == (
        "https://example.com/login",
        False,
    )


def test_smtp_verify_skips_mx_host_with_private_address(monkeypatch):
    smtp_verify.verify_sender.cache_clear()
    monkeypatch.setattr(smtp_verify, "_mx_hosts", lambda domain: ["mx.attacker.test"])

    class _Rdata:
        def __init__(self, ip: str) -> None:
            self._ip = ip
        def __str__(self) -> str:
            return self._ip

    class _FakeResolver:
        lifetime = 1.0
        timeout = 1.0
        def resolve(self, host, qtype):
            if qtype == "A":
                return [_Rdata("10.0.0.5")]
            raise smtp_verify.DNSException("no AAAA")

    monkeypatch.setattr(smtp_verify, "_resolver", _FakeResolver)

    def probe(*args, **kwargs):
        raise AssertionError("private MX host must not be probed")

    monkeypatch.setattr(smtp_verify, "_probe", probe)

    result = smtp_verify.verify_sender(
        "sender@attacker.test",
        "checker@example.com",
        "example.com",
    )

    assert result.status == "unreachable"
    assert "non-public address 10.0.0.5" in result.detail


def test_analyze_flags_reply_to_domain_mismatch():
    raw = (
        b"From: Invoices <billing@vendor.com>\n"
        b"Reply-To: Accounts <pay@vendor-payments.com>\n"
        b"Subject: monthly invoice\n"
        b"\n"
        b"Please review the invoice."
    )

    findings = link_analysis.analyze("Please review the invoice.", raw_rfc822=raw)

    assert findings[-1].url == "message:headers"
    assert findings[-1].warnings == [
        HeaderAnomaly("reply-to domain vendor-payments.com differs from from domain vendor.com")
    ]


def test_analyze_does_not_flag_matching_reply_to_domain():
    raw = (
        b"From: Invoices <billing@mail.vendor.com>\n"
        b"Reply-To: Accounts <pay@vendor.com>\n"
        b"Subject: monthly invoice\n"
        b"\n"
        b"Please review the invoice."
    )

    findings = link_analysis.analyze("Please review the invoice.", raw_rfc822=raw)

    assert not any(f.url == "message:headers" for f in findings)


def test_analyze_flags_time_and_payment_pressure_language():
    raw = (
        b"From: Payroll <payroll@example.com>\n"
        b"Subject: Final notice: payment overdue\n"
        b"\n"
        b"Wire transfer required within 24 hours. Bank details changed."
    )

    findings = link_analysis.analyze(
        "Wire transfer required within 24 hours. Bank details changed.",
        raw_rfc822=raw,
    )

    assert findings[-1].url == "message:headers"
    assert findings[-1].warnings == [
        HeaderAnomaly(
            "time/payment pressure language: final notice, payment overdue, "
            "wire transfer, within 24 hours, bank details changed"
        )
    ]


def test_analyze_flags_direct_redirector_chain(monkeypatch):
    link_analysis._fetch_url.cache_clear()
    monkeypatch.setattr(link_analysis, "domain_age_days", lambda domain: 9999)
    monkeypatch.setattr(
        link_analysis,
        "_fetch_url",
        lambda url: ("https://credential-capture.com/login", False),
    )

    findings = link_analysis.analyze(
        "https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fcredential-capture.com"
    )

    assert findings[0].warnings == [
        RedirectorResolves(
            domain=findings[0].domain, final_domain="credential-capture.com",
        )
    ]


def test_anchor_deception_uses_redirector_final_domain(monkeypatch):
    link_analysis._fetch_url.cache_clear()
    monkeypatch.setattr(link_analysis, "domain_age_days", lambda domain: 9999)
    monkeypatch.setattr(
        link_analysis,
        "_fetch_url",
        lambda url: ("https://credential-capture.com/login", False),
    )
    raw = (
        b"From: Security <security@example.com>\n"
        b"Subject: account notice\n"
        b"Content-Type: text/html\n"
        b"\n"
        b'<a href="https://safelinks.protection.outlook.com/?url=x">'
        b"https://account.example.com</a>"
    )
    body = (
        "https://account.example.com "
        "https://safelinks.protection.outlook.com/?url=x"
    )

    findings = link_analysis.analyze(body, raw_rfc822=raw)

    assert findings[1].warnings == [
        RedirectorResolves(
            domain=findings[1].domain, final_domain="credential-capture.com",
        ),
        LinkTextMismatch(
            displayed="example.com",
            actual="credential-capture.com",
            via_redirector=True,
        ),
    ]


# --- attachment scanner hardening --------------------------------------------

import io as _io
import zipfile as _zipfile
from email.message import EmailMessage as _EmailMessage

from tfatp import attachments as _attachments


def _eml_with_attachment(filename: str, payload: bytes, subtype: str = "octet-stream") -> bytes:
    msg = _EmailMessage()
    msg["From"] = "x@example.com"
    msg["To"] = "y@example.com"
    msg["Subject"] = "t"
    msg.set_content("body")
    msg.add_attachment(payload, maintype="application", subtype=subtype, filename=filename)
    return bytes(msg)


def test_attachment_scan_flags_ooxml_with_vba_project():
    buf = _io.BytesIO()
    with _zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "x")
        zf.writestr("word/vbaProject.bin", b"\x00")
    raw = _eml_with_attachment("doc.docm", buf.getvalue())
    findings = _attachments.scan(raw)
    assert len(findings) == 1
    assert "VBA macro" in str(findings[0].warnings[0])


def test_attachment_scan_skips_oversized_payload(monkeypatch):
    monkeypatch.setattr(_attachments, "_MAX_ATTACHMENT_BYTES", 64)
    raw = _eml_with_attachment("big.bin", b"A" * 200)
    findings = _attachments.scan(raw)
    assert len(findings) == 1
    assert "too large to scan" in str(findings[0].warnings[0])


def test_attachment_scan_caps_zip_entry_count(monkeypatch):
    monkeypatch.setattr(_attachments, "_MAX_ZIP_ENTRIES", 5)
    buf = _io.BytesIO()
    with _zipfile.ZipFile(buf, "w") as zf:
        for i in range(20):
            zf.writestr(f"f{i}.txt", b"x")
    raw = _eml_with_attachment("many.zip", buf.getvalue(), subtype="zip")
    findings = _attachments.scan(raw)
    assert len(findings) == 1
    assert "zip bomb" in str(findings[0].warnings[0])


def test_attachment_scan_flags_zip_compression_bomb(monkeypatch):
    monkeypatch.setattr(_attachments, "_MAX_ZIP_COMPRESSION_RATIO", 50)
    buf = _io.BytesIO()
    with _zipfile.ZipFile(buf, "w", compression=_zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("payload.bin", b"\x00" * (1 * 1024 * 1024))
    raw = _eml_with_attachment("bomb.zip", buf.getvalue(), subtype="zip")
    findings = _attachments.scan(raw)
    assert len(findings) == 1
    assert "zip bomb" in str(findings[0].warnings[0])


def test_attachment_scan_flags_zip_declared_size_bomb(monkeypatch):
    monkeypatch.setattr(_attachments, "_MAX_ZIP_UNCOMPRESSED_BYTES", 1024)
    buf = _io.BytesIO()
    with _zipfile.ZipFile(buf, "w", compression=_zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("payload.bin", b"\x00" * (100 * 1024))
    raw = _eml_with_attachment("big.zip", buf.getvalue(), subtype="zip")
    findings = _attachments.scan(raw)
    assert len(findings) == 1
    assert "zip bomb" in str(findings[0].warnings[0])


def test_attachment_scan_flags_encrypted_zip():
    buf = _io.BytesIO()
    with _zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("inner.txt", b"hello")
    # Forge the general-purpose bit 0 (encryption flag) on the central
    # directory entry. zipfile won't write encrypted archives, so we patch
    # the bytes directly: locate the central directory signature and flip
    # the flag field. Simpler: rebuild infolist with flag_bits set via
    # monkey-patch isn't worth it — use a tiny known-encrypted fixture.
    data = bytearray(buf.getvalue())
    # Central directory header signature 0x02014b50. Flag field at offset +8.
    cdh = data.find(b"PK\x01\x02")
    assert cdh >= 0
    data[cdh + 8] |= 0x01
    # Also the local file header flag at offset +6.
    lfh = data.find(b"PK\x03\x04")
    data[lfh + 6] |= 0x01
    raw = _eml_with_attachment("locked.zip", bytes(data), subtype="zip")
    findings = _attachments.scan(raw)
    assert len(findings) == 1
    assert "encrypted" in str(findings[0].warnings[0])


def test_attachment_scan_does_not_crash_on_garbage_payload():
    # Random bytes that look vaguely like an OLE header but aren't.
    raw = _eml_with_attachment("evil.doc", b"\xd0\xcf\x11\xe0" + b"\xff" * 4096)
    findings = _attachments.scan(raw)
    # Either flagged unreadable or treated as not-OLE; must not raise.
    assert all(f.url == "attachment:evil.doc" for f in findings)


def test_attachment_scan_isolates_per_attachment_failure(monkeypatch):
    """A crash on one attachment must not skip the next."""
    calls = {"n": 0}

    def boom(payload: bytes) -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("synthetic parser crash")
        return ""

    monkeypatch.setattr(_attachments, "_ooxml_macro_status", boom)
    # Build a message with two attachments
    msg = _EmailMessage()
    msg["From"] = "x@example.com"
    msg["To"] = "y@example.com"
    msg["Subject"] = "t"
    msg.set_content("body")
    msg.add_attachment(b"PK\x03\x04junk", maintype="application", subtype="zip", filename="a.zip")
    msg.add_attachment(b"PK\x03\x04junk", maintype="application", subtype="zip", filename="b.zip")

    findings = _attachments.scan(bytes(msg))
    names = {f.url for f in findings}
    assert "attachment:a.zip" in names
    # Second attachment was reached even though first raised
    assert calls["n"] == 2


from tfatp.lookalike import check as _check_lookalike


def test_lookalike_decodes_punycode_before_distance():
    # `pаypal` with Cyrillic а encodes to xn--pypal-4ve; a raw ASCII
    # distance check would miss it.
    ascii_form = "pаypal".encode("idna").decode("ascii")
    res = _check_lookalike(f"{ascii_form}.com", "paypal.com", max_distance=1)
    assert res.matched
    assert res.distance == 0


def test_lookalike_does_not_match_unrelated_idn():
    # A legitimately different Unicode label must not be flagged as paypal.
    label = "zürich"
    ascii_form = label.encode("idna").decode("ascii")
    res = _check_lookalike(f"{ascii_form}.com", "paypal.com", max_distance=1)
    assert not res.matched


def test_double_scheme_url_does_not_produce_false_warnings(monkeypatch):
    """Trackers that double-prefix ``https://`` produce strings like
    ``https://https//host/...`` where urlparse extracts host="https".
    Such not-actually-a-domain values must not trigger RDAP, password-form
    fetch, or any YoungDomain warning. The finding is still emitted so
    the defang pipeline knows about the URL.
    """
    # Fail loud if the analyzer tries to fetch the URL or look up the
    # bogus domain — the whole point of this test is that neither runs.
    monkeypatch.setattr(
        link_analysis, "domain_age_days",
        lambda d: (_ for _ in ()).throw(AssertionError(f"RDAP called for {d!r}")),
    )
    monkeypatch.setattr(
        link_analysis, "has_password_form",
        lambda u: (_ for _ in ()).throw(AssertionError(f"fetched {u!r}")),
    )

    body = "Visit https://https//www.finance.si/page?utm=x for details."
    findings = link_analysis.analyze(body, check_link_domain_age=True, check_password_form=True)
    assert len(findings) == 1
    f = findings[0]
    assert f.url.startswith("https://https//")
    assert f.domain == "https"
    assert f.warnings == []


def test_lookalike_charges_www_prefix_as_one_edit():
    # `www-acme.io` would otherwise be 4 raw edits from `acme.io`. Charging
    # the glued-in `www-` as a single edit brings it back within threshold.
    res = _check_lookalike("www-acme.io", "acme.io", max_distance=1)
    assert res.matched
    assert res.distance == 1


def test_lookalike_detail_tld_swap_phrasing():
    res = _check_lookalike("acme.io", "acme.com", max_distance=1)
    assert res.matched
    assert res.detail == (
        "acme.io looks like acme.com — same name, different TLD (.io vs .com)"
    )


def test_lookalike_detail_sld_edit_phrasing():
    # `acrme` is one insertion away from `acme`; TLDs also differ, so we
    # expect the dual-clause phrasing.
    res = _check_lookalike("acrme.io", "acme.com", max_distance=1)
    assert res.matched
    assert res.detail == (
        "acrme.io looks like acme.com — "
        "name differs by 1 edit (acrme vs acme); TLDs differ (.io vs .com)"
    )


def test_normalize_href_strips_tab_cr_lf():
    assert link_analysis._normalize_href(
        "https://safe.com\t.evil.com/path"
    ) == "https://safe.com.evil.com/path"
    assert link_analysis._normalize_href(
        "https://safe.com\r\n.evil.com/"
    ) == "https://safe.com.evil.com/"


def test_normalize_href_strips_zero_width_characters():
    # U+200B ZERO WIDTH SPACE between safe.com and .evil.com
    assert link_analysis._normalize_href(
        "https://safe.com​.evil.com/"
    ) == "https://safe.com.evil.com/"


def test_normalize_href_extracts_correct_anchor_host():
    raw = (
        b"From: x@example.com\nSubject: x\nContent-Type: text/html\n\n"
        b'<a href="https://safe.com\t.evil.com/p">click</a>'
    )
    pairs = link_analysis._extract_html_anchors(raw)
    assert pairs == [("https://safe.com.evil.com/p", "click")]


# --- RDAP retry semantics ----------------------------------------------------

import contextlib as _contextlib


class _MockRDAPResponse:
    def __init__(self, status_code: int, body: bytes = b"", headers: dict | None = None):
        self.status_code = status_code
        self.headers = headers or {}
        self._body = body

    def iter_bytes(self, chunk_size: int):
        if self._body:
            yield self._body


def _ok_body(age_days: int) -> bytes:
    import datetime as _dt
    when = _dt.datetime.now(_dt.UTC) - _dt.timedelta(days=age_days)
    return (
        '{"events":[{"eventAction":"registration","eventDate":"'
        + when.isoformat().replace("+00:00", "Z") + '"}]}'
    ).encode()


def _patch_rdap_stream(monkeypatch, responder, call_log: list | None = None):
    """Replace drawbridge.sync.stream with a context manager driven by `responder`.

    `responder(url, kwargs)` returns either a _MockRDAPResponse to yield, or
    raises an exception that the caller should see.
    """
    @_contextlib.contextmanager
    def fake_stream(method, url, **kwargs):
        if call_log is not None:
            call_log.append(url)
        yield responder(url, kwargs)
    monkeypatch.setattr(link_analysis.drawbridge.sync, "stream", fake_stream)


def test_rdap_returns_age_on_first_success(monkeypatch):
    calls = []
    _patch_rdap_stream(monkeypatch, lambda u, kw: _MockRDAPResponse(200, _ok_body(1000)), calls)
    monkeypatch.setattr(link_analysis.time, "sleep", lambda s: None)
    age = link_analysis._rdap_age_days("example.com")
    assert age is not None and 999 <= age <= 1001
    assert len(calls) == 1


def test_rdap_retries_on_5xx_then_succeeds(monkeypatch):
    statuses = [503, 502, 200]
    def respond(url, kw):
        s = statuses.pop(0)
        return _MockRDAPResponse(s, _ok_body(500) if s == 200 else b"")
    sleeps = []
    _patch_rdap_stream(monkeypatch, respond)
    monkeypatch.setattr(link_analysis.time, "sleep", lambda s: sleeps.append(s))
    age = link_analysis._rdap_age_days("example.com")
    assert age is not None
    assert len(sleeps) == 2  # two backoffs before the successful 3rd attempt


def test_rdap_does_not_retry_on_404(monkeypatch):
    calls = []
    _patch_rdap_stream(monkeypatch, lambda u, kw: _MockRDAPResponse(404), calls)
    monkeypatch.setattr(link_analysis.time, "sleep", lambda s: None)
    assert link_analysis._rdap_age_days("example.com") is None
    assert len(calls) == 1


def test_rdap_retries_on_transport_exception(monkeypatch):
    import httpx as _httpx
    counter = {"n": 0}
    def respond(url, kw):
        counter["n"] += 1
        if counter["n"] < 3:
            raise _httpx.ConnectError("boom")
        return _MockRDAPResponse(200, _ok_body(100))
    _patch_rdap_stream(monkeypatch, respond)
    monkeypatch.setattr(link_analysis.time, "sleep", lambda s: None)
    age = link_analysis._rdap_age_days("example.com")
    assert age is not None
    assert counter["n"] == 3


def test_rdap_gives_up_after_max_attempts(monkeypatch):
    calls = []
    _patch_rdap_stream(monkeypatch, lambda u, kw: _MockRDAPResponse(503), calls)
    monkeypatch.setattr(link_analysis.time, "sleep", lambda s: None)
    assert link_analysis._rdap_age_days("example.com") is None
    assert len(calls) == link_analysis._RDAP_MAX_ATTEMPTS


def test_rdap_honors_retry_after_seconds(monkeypatch):
    statuses = [429, 200]
    def respond(url, kw):
        s = statuses.pop(0)
        if s == 429:
            return _MockRDAPResponse(429, headers={"Retry-After": "2"})
        return _MockRDAPResponse(200, _ok_body(50))
    sleeps = []
    _patch_rdap_stream(monkeypatch, respond)
    monkeypatch.setattr(link_analysis.time, "sleep", lambda s: sleeps.append(s))
    age = link_analysis._rdap_age_days("example.com")
    assert age is not None
    assert sleeps == [2.0]  # honored server-supplied delay, no jitter


def test_rdap_respects_wall_clock_budget(monkeypatch):
    calls = []
    _patch_rdap_stream(
        monkeypatch,
        lambda u, kw: _MockRDAPResponse(503, headers={"Retry-After": "999"}),
        calls,
    )
    monkeypatch.setattr(link_analysis.time, "sleep",
                        lambda s: (_ for _ in ()).throw(AssertionError("should not sleep")))
    assert link_analysis._rdap_age_days("example.com") is None
    assert len(calls) == 1


def test_rdap_rejects_attacker_controlled_domain():
    # Path-injection attempt — must be rejected by the whitelist regex.
    assert link_analysis._rdap_age_days("foo/../bar") is None
