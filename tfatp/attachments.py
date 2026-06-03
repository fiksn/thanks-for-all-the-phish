"""Inspect message attachments for high-confidence malicious signals.

Initial scope: VBA macros inside Microsoft Office attachments — both modern
OOXML (.docm/.xlsm/.pptm and disguised .docx/.xlsx variants) and the legacy
OLE Compound File Binary format (.doc/.xls/.ppt). A macro in an attachment
is a primary delivery vector for credential stealers and droppers; the mere
presence — regardless of macro content — is the signal we surface here.

All checks are pure data-on-bytes: no execution, no network, no rendering.
"""

import email
import io
import zipfile
from email import policy

import olefile

from tfatp.link_analysis import LinkFinding

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# Caps tuned to keep one malicious or malformed attachment from grinding the
# pipeline. Larger than typical phish lures (10–500 KB) but smaller than the
# Gmail API per-message ceiling (25 MB) so a single oversized blob fails
# noisily instead of swallowing memory.
_MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024
# zipfile.namelist() materializes one Python str per entry, so a zip declaring
# millions of entries can exhaust memory without ever extracting anything.
_MAX_ZIP_ENTRIES = 10_000
# Sum of declared uncompressed sizes across all members. Legitimate Office
# documents fit comfortably here; classic zip bombs (42.zip and descendants)
# declare petabytes.
_MAX_ZIP_UNCOMPRESSED_BYTES = 200 * 1024 * 1024
# Compression ratio above which we assume hostile intent. Real Office files
# rarely exceed ~10x; padding-only payloads can hit thousands.
_MAX_ZIP_COMPRESSION_RATIO = 100


def _iter_attachments(raw: bytes):
    """Yield (filename, content_type, payload_bytes) for each non-inline part."""
    msg = email.message_from_bytes(raw, policy=policy.default)
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        # Anything with a filename or explicit attachment disposition counts;
        # inline images and the text body parts are skipped.
        if not filename and disposition != "attachment":
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        yield filename or "(unnamed)", part.get_content_type(), payload


def _ooxml_macro_status(payload: bytes) -> str:
    """Return 'macro', 'bomb', 'encrypted', 'unreadable', or '' (clean / not a zip)."""
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            infos = zf.infolist()
            if len(infos) > _MAX_ZIP_ENTRIES:
                return "bomb"
            # ZIP general-purpose bit 0 set on any entry means that entry is
            # encrypted. A password-protected archive is opaque to us — we
            # can't tell if it carries a macro or a payload — so we surface
            # the fact loudly instead of letting it pass silently.
            if any(i.flag_bits & 0x1 for i in infos):
                return "encrypted"
            total_uncompressed = sum(i.file_size for i in infos)
            total_compressed = sum(i.compress_size for i in infos) or 1
            if total_uncompressed > _MAX_ZIP_UNCOMPRESSED_BYTES:
                return "bomb"
            if total_uncompressed // total_compressed > _MAX_ZIP_COMPRESSION_RATIO:
                return "bomb"
            return "macro" if any(i.filename.endswith("vbaProject.bin") for i in infos) else ""
    except Exception:  # noqa: BLE001 — third-party parser on untrusted input
        return "unreadable"


def _ole_macro_status(payload: bytes) -> str:
    """Return 'macro', 'unreadable', or '' (clean / not an OLE file)."""
    if not payload.startswith(_OLE_MAGIC):
        return ""
    try:
        ole = olefile.OleFileIO(io.BytesIO(payload))
    except Exception:  # noqa: BLE001 — third-party parser on untrusted input
        return "unreadable"
    try:
        for entry in ole.listdir(streams=True, storages=True):
            lowered = "/".join(entry).lower()
            if "vba" in lowered or "macros" in lowered:
                return "macro"
        return ""
    except Exception:  # noqa: BLE001 — malformed directory tree
        return "unreadable"
    finally:
        ole.close()


def _finding(name: str, warning: str) -> LinkFinding:
    return LinkFinding(
        url=f"attachment:{name}",
        host="",
        domain="",
        age_days=None,
        has_password_form=False,
        warnings=[warning],
    )


def scan(raw: bytes) -> list[LinkFinding]:
    """Return findings for any attachment that trips a malicious-payload check.

    Each attachment is independently size-capped and exception-isolated: a
    single hostile or malformed file produces a warning, never a crash, and
    never blocks scanning of the remaining attachments.
    """
    findings: list[LinkFinding] = []
    for name, _mime, payload in _iter_attachments(raw):
        try:
            size = len(payload)
            if size > _MAX_ATTACHMENT_BYTES:
                findings.append(_finding(
                    name,
                    f"attachment too large to scan: {size} bytes "
                    f"(max {_MAX_ATTACHMENT_BYTES})",
                ))
                continue
            ooxml = _ooxml_macro_status(payload)
            ole = _ole_macro_status(payload)
            if ooxml == "macro" or ole == "macro":
                findings.append(_finding(name, f"attachment contains VBA macro ({name})"))
            elif ooxml == "bomb":
                findings.append(_finding(
                    name, f"attachment looks like a zip bomb: structure exceeds caps ({name})"
                ))
            elif ooxml == "encrypted":
                findings.append(_finding(
                    name, f"attachment encrypted (cannot scan for macros) ({name})"
                ))
            elif ooxml == "unreadable" or ole == "unreadable":
                findings.append(_finding(
                    name, f"attachment unreadable: structure could not be parsed ({name})"
                ))
        except Exception as exc:  # noqa: BLE001 — last-resort isolation per attachment
            findings.append(_finding(
                name, f"attachment scan failed: {type(exc).__name__} ({name})"
            ))
    return findings
