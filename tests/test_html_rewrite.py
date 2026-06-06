"""Tests for HTML-preserving rewrite path."""

import email
from email import policy
from email.message import EmailMessage

from tfatp.analyze_eml import build_corrected_eml, rewrite_body
from tfatp.link_analysis import LinkFinding, PasswordForm, YoungDomain


def _html_eml(body: str) -> bytes:
    m = EmailMessage()
    m["From"] = "x@example.com"
    m["To"] = "y@example.com"
    m["Subject"] = "t"
    m["Date"] = "Mon, 01 Jun 2026 10:00:00 +0000"
    m["Message-Id"] = "<abc@host>"
    m.set_content(body, subtype="html")
    return bytes(m)


def _decoded_html(raw: bytes) -> str:
    msg = email.message_from_bytes(raw, policy=policy.default)
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            return part.get_content()
    return ""


def test_corrected_eml_keeps_html_content_type():
    raw = _html_eml('<a href="https://x.example/">click</a>')
    corrected = build_corrected_eml(raw, "<a href=\"hxxps://x.example/\">click</a>",
                                    [], body_subtype="html")
    msg = email.message_from_bytes(corrected, policy=policy.default)
    # First body part is text/html, not text/plain.
    body_part = next(p for p in msg.walk()
                     if p.get_content_type() in ("text/plain", "text/html")
                     and not p.is_multipart())
    assert body_part.get_content_type() == "text/html"


def test_rewrite_body_html_defangs_anchor_href():
    body = '<p>Click <a href="https://evil.example/login">here</a></p>'
    out = rewrite_body(body, "html", findings=[], neutralize_all=True, per_url=set())
    assert 'href="https://evil.example.REMOVE-TO-VISIT.invalid/login"' in out
    # surrounding HTML structure preserved
    assert "<p>" in out and "<a " in out


def test_rewrite_body_html_does_not_defang_legit_img_src():
    """defang_html must not scheme-rewrite <img src>. A 200x60 brand logo is
    untouched even when neutralize_all=True; only anchors and visible-text
    URLs are defanged. Tracking-pixel suppression is a separate transform."""
    body = '<img src="https://cdn.example/logo.png" width="200" height="60">'
    out = rewrite_body(body, "html", findings=[], neutralize_all=True, per_url=set())
    assert 'src="https://cdn.example/logo.png"' in out
    assert "hxxps://cdn" not in out


def test_rewrite_body_html_per_url_only_touches_matched():
    body = ('<a href="https://bad.example/x">a</a>'
            '<a href="https://good.example/y">b</a>')
    out = rewrite_body(body, "html", findings=[], neutralize_all=False,
                       per_url={"https://bad.example/x"})
    assert 'href="https://bad.example.REMOVE-TO-VISIT.invalid/x"' in out
    assert 'href="https://good.example/y"' in out


def test_rewrite_body_html_annotates_anchor_with_warning():
    body = '<a href="https://bad.example/x">click</a>'
    findings = [LinkFinding(
        url="https://bad.example/x", host="bad.example", domain="bad.example",
        age_days=10, has_password_form=False,
        warnings=[YoungDomain(domain="bad.example", age_days=10)],
    )]
    out = rewrite_body(body, "html", findings=findings, neutralize_all=False, per_url=set())
    # Warning lives on a ⚠ icon span appended after the anchor; the anchor
    # itself stays untouched (no style, no title, original contents).
    assert "⚠" in out
    assert 'title="https://bad.example/x WARNING: young (10d)"' in out
    # The anchor still says "click" and has no extra attributes.
    assert ">click</a>" in out
    assert "border-bottom" not in out
    # No inline `[WARNING: ...]` text in the body anymore.
    assert "[WARNING:" not in out


def test_rewrite_body_html_preserves_anchor_contents():
    # Button text, image, styled span must survive a whole-body defang;
    # only the href changes — hostname gets a `.REMOVE-TO-VISIT.invalid`
    # suffix so Gmail keeps the anchor clickable but DNS never resolves.
    body = '<a class="btn" href="https://bad.example/x">Verify Account</a>'
    out = rewrite_body(body, "html", findings=[], neutralize_all=True, per_url=set())
    assert 'href="https://bad.example.REMOVE-TO-VISIT.invalid/x"' in out
    assert ">Verify Account</a>" in out
    assert 'class="btn"' in out


def test_rewrite_body_html_does_not_touch_mailto_anchors():
    # `mailto:` anchors are not URLs we defang; the visible email
    # address inside must not be altered.
    body = (
        'Contact <a href="mailto:alice@example.com">alice@example.com</a>'
        ' for details.'
    )
    out = rewrite_body(body, "html", findings=[], neutralize_all=True, per_url=set())
    assert 'href="mailto:alice@example.com"' in out
    assert ">alice@example.com</a>" in out


def test_defang_preserves_scheme_and_uses_invalid_suffix():
    # The defanged URL keeps `https://` so Gmail's sanitizer leaves the
    # anchor clickable, and the hostname picks up a `.invalid` suffix so
    # DNS resolution fails. Port + path + query survive unchanged.
    from tfatp.link_analysis import defang
    out = defang("https://mail.bad.example:8443/login?check=x", ".REMOVE.invalid")
    assert out == "https://mail.bad.example.REMOVE.invalid:8443/login?check=x"


def test_defang_custom_suffix_threads_through_rewrite_body():
    body = '<a href="https://bad.example/x">click</a>'
    out = rewrite_body(
        body, "html", findings=[], neutralize_all=True, per_url=set(),
        defang_suffix=".STRIP.example",
    )
    assert 'href="https://bad.example.STRIP.example/x"' in out


def test_rewrite_body_html_preserves_existing_anchor_title():
    body = (
        '<a href="https://bad.example/x" title="Click here to verify">'
        'click</a>'
    )
    findings = [LinkFinding(
        url="https://bad.example/x", host="bad.example", domain="bad.example",
        age_days=10, has_password_form=False,
        warnings=[YoungDomain(domain="bad.example", age_days=10)],
    )]
    out = rewrite_body(body, "html", findings=findings, neutralize_all=False, per_url=set())
    # Original title intact; the warning rides on a separate ⚠ icon span.
    assert 'title="Click here to verify"' in out
    assert "⚠" in out
    assert 'title="https://bad.example/x WARNING: young (10d)"' in out


def test_corrected_html_banner_uses_html_styling():
    raw = _html_eml('<p>hi</p>')
    finding = LinkFinding(
        url="https://bad.example/x", host="bad.example", domain="bad.example",
        age_days=1, has_password_form=True,
        warnings=[PasswordForm(domain="bad.example")],
    )
    corrected = build_corrected_eml(raw, "<p>hi</p>", [finding], body_subtype="html")
    body = _decoded_html(corrected)
    assert "border:2px solid #c00" in body  # styled banner
    assert ">WARNING:</div>" in body


def test_corrected_html_banner_suppressed_when_no_findings():
    raw = _html_eml('<p>hi</p>')
    corrected = build_corrected_eml(raw, "<p>hi</p>", [], body_subtype="html")
    body = _decoded_html(corrected)
    assert ">WARNING:</div>" not in body


def test_external_warning_html_renders_verbatim_in_html_body():
    raw = _html_eml('<p>hi</p>')
    custom = '<div class="my-banner">Sender is external.</div>'
    corrected = build_corrected_eml(
        raw, "<p>hi</p>", [], body_subtype="html",
        external_warning_html=custom,
    )
    body = _decoded_html(corrected)
    assert custom in body
    # No analysis banner when nothing else fired.
    assert ">WARNING:</div>" not in body


# --- tracking-pixel neutralization ------------------------------------------

from tfatp.link_analysis import (
    _TRANSPARENT_1X1_GIF,
    neutralize_tracking_pixels,
)


def test_tracking_pixel_width_height_attrs_neutralized():
    html = '<img src="https://t.example/p?u=1" width="1" height="1">'
    out, count = neutralize_tracking_pixels(html)
    assert count == 1
    assert "https://t.example" not in out
    assert _TRANSPARENT_1X1_GIF in out


def test_tracking_pixel_display_none_neutralized():
    html = '<img src="https://t.example/p?u=1" style="display:none">'
    out, count = neutralize_tracking_pixels(html)
    assert count == 1
    assert _TRANSPARENT_1X1_GIF in out


def test_tracking_pixel_visibility_hidden_neutralized():
    html = '<img src="https://t.example/p?u=1" style="visibility: hidden">'
    out, count = neutralize_tracking_pixels(html)
    assert count == 1


def test_tracking_pixel_opacity_zero_neutralized():
    html = '<img src="https://t.example/p?u=1" style="opacity:0">'
    out, count = neutralize_tracking_pixels(html)
    assert count == 1


def test_tracking_pixel_style_dims_neutralized():
    html = '<img src="https://t.example/p?u=1" style="width:1px; height:1px;">'
    out, count = neutralize_tracking_pixels(html)
    assert count == 1


def test_legit_image_kept_intact():
    html = '<img src="https://cdn.example/logo.png" width="200" height="60">'
    out, count = neutralize_tracking_pixels(html)
    assert count == 0
    assert "https://cdn.example/logo.png" in out


def test_small_only_in_one_dimension_not_a_pixel():
    # A 1px border or thin divider isn't a tracking beacon.
    html = '<img src="https://cdn.example/divider.png" style="width:100%; height:1px;">'
    out, count = neutralize_tracking_pixels(html)
    assert count == 0


def test_rewrite_body_html_neutralizes_pixel_in_full_flow():
    body = (
        '<p>Body</p>'
        '<img src="https://attacker.example/pixel?u=42" width="1" height="1">'
    )
    out = rewrite_body(body, "html", findings=[], neutralize_all=False, per_url=set())
    assert "attacker.example" not in out
    assert _TRANSPARENT_1X1_GIF in out
    # Body content otherwise untouched
    assert "<p>Body</p>" in out
