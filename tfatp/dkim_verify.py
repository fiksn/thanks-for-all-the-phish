import re
from dataclasses import dataclass

import dkim


@dataclass(frozen=True, slots=True)
class DkimResult:
    status: str  # "pass" | "fail" | "none" | "error"
    detail: str  # human-readable reason / signing domain

    @property
    def ok(self) -> bool:
        return self.status == "pass"


_SIG_RE = re.compile(rb"^DKIM-Signature\s*:(.*?)(?=\r?\n[^ \t])", re.IGNORECASE | re.DOTALL | re.MULTILINE)
_D_TAG_RE = re.compile(rb"\bd\s*=\s*([^;\s]+)", re.IGNORECASE)


def _signing_domain(raw: bytes) -> str | None:
    m = _SIG_RE.search(raw)
    if not m:
        return None
    d = _D_TAG_RE.search(m.group(1))
    return d.group(1).decode("ascii", "replace") if d else None


def verify(raw_rfc822: bytes) -> DkimResult:
    """Verify the first DKIM-Signature on a raw RFC822 message.

    Uses the live DNS to fetch the signing key. Returns a structured result rather
    than raising — DKIM failures are an expected outcome, not an error.
    """
    domain = _signing_domain(raw_rfc822)
    if domain is None:
        return DkimResult("none", "no DKIM-Signature header")
    try:
        ok = dkim.verify(raw_rfc822)
    except dkim.DKIMException as exc:
        return DkimResult("fail", f"d={domain}: {exc}")
    except Exception as exc:  # noqa: BLE001 — DNS / network / parser errors
        return DkimResult("error", f"d={domain}: {exc!r}")
    return DkimResult("pass" if ok else "fail", f"d={domain}")


def main(argv: list[str]) -> int:
    import argparse
    import sys
    from pathlib import Path

    p = argparse.ArgumentParser(
        description="Verify the DKIM signature on an .eml file. "
        "Point this at the attached original.eml to independently confirm "
        "the message wasn't modified in flight.",
    )
    p.add_argument(
        "path", nargs="?",
        help="Path to .eml file. Omit or use '-' to read from stdin.",
    )
    args = p.parse_args(argv)

    if args.path and args.path != "-":
        raw = Path(args.path).read_bytes()
    else:
        raw = sys.stdin.buffer.read()

    result = verify(raw)
    label = "VERIFIED" if result.ok else "NOT VERIFIED"
    print(f"{label} — {result.status} ({result.detail})")
    return 0 if result.ok else 1


