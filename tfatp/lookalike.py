"""Detect sender-domain impersonation against the configured user's domain.

Two stages:

1. **Skeleton normalization** — each character is replaced by its canonical
   Latin equivalent via `confusable_homoglyphs` (Unicode TR#39). This collapses
   Cyrillic `а` → Latin `a`, `0` → `o`, and similar visual look-alikes so the
   subsequent distance check operates on a single alphabet.
2. **Damerau-Levenshtein distance** on the registrable label. Catches single
   insertions, deletions, substitutions, and transpositions — e.g.
   `paypal` ↔ `paypa1` (l-for-1, distance 1) or `goolge` ↔ `google`
   (transposition, distance 1).

A finding fires when the observed and protected domains are *not* identical
but their normalized labels are within `max_distance` edits.
"""

from dataclasses import dataclass

import tldextract
from confusable_homoglyphs import confusables
from rapidfuzz.distance import DamerauLevenshtein


@dataclass(frozen=True, slots=True)
class LookalikeResult:
    matched: bool
    observed: str   # e.g. "exarnple.com"
    protected: str  # e.g. "example.com"
    distance: int   # Damerau-Levenshtein after skeleton normalization

    @property
    def detail(self) -> str:
        if not self.matched:
            return f"{self.observed} != {self.protected}"
        return describe(self.observed, self.protected, self.distance)


def describe(observed: str, protected: str, distance: int) -> str:
    """Render a human-readable explanation of an observed/protected match.

    Two shapes get distinct wording:
    - TLD-swap: SLDs equal, TLDs differ. e.g. ``acme.io`` vs ``acme.com``.
    - SLD edit: SLDs differ by ``distance`` characters. e.g. ``acrme`` vs
      ``acme``. The original (pre-normalization) SLDs are shown so the
      reader can see the literal difference, including a ``www-`` prefix
      that we charge as a single edit.
    """
    obs_label, _, obs_tld = observed.partition(".")
    pro_label, _, pro_tld = protected.partition(".")
    same_label = obs_label == pro_label
    same_tld = obs_tld == pro_tld
    if same_label and not same_tld:
        return (
            f"{observed} looks like {protected} — "
            f"same name, different TLD (.{obs_tld} vs .{pro_tld})"
        )
    edit_word = "edit" if distance == 1 else "edits"
    name_part = (
        f"name differs by {distance} {edit_word} ({obs_label} vs {pro_label})"
    )
    if same_tld:
        return f"{observed} looks like {protected} — {name_part}"
    return (
        f"{observed} looks like {protected} — "
        f"{name_part}; TLDs differ (.{obs_tld} vs .{pro_tld})"
    )


def registrable(domain: str) -> str:
    ext = tldextract.extract(domain)
    if not ext.domain or not ext.suffix:
        return domain.lower()
    return f"{ext.domain}.{ext.suffix}".lower()


def _idn_to_unicode(domain: str) -> str:
    """Decode each Punycode (A-label, xn--*) label to Unicode (U-label).

    Attackers register IDNs like xn--ppal-4ve (paypal with a Cyrillic а) and
    rely on receivers that compare against the raw A-label form, where the
    edit distance to "paypal" is large enough to slip past lookalike checks.
    Decoding to Unicode first puts the comparison on the same axis as the
    homoglyph skeleton step that follows.
    """
    if "xn--" not in domain:
        return domain
    out: list[str] = []
    for label in domain.split("."):
        if label.startswith("xn--"):
            try:
                out.append(label.encode("ascii").decode("idna"))
            except (UnicodeError, UnicodeDecodeError):
                out.append(label)
        else:
            out.append(label)
    return ".".join(out)


def _skeleton(s: str) -> str:
    """Map each character to its canonical Latin look-alike per Unicode TR#39."""
    out: list[str] = []
    for ch in s.lower():
        if ch.isascii() and (ch.isalnum() or ch in ".-"):
            out.append(ch)
            continue
        info = confusables.is_confusable(ch, greedy=True)
        replacement = ch
        if info:
            for entry in info:
                for hg in entry.get("homoglyphs", ()):
                    cand = hg.get("c", "")
                    if cand and cand.isascii():
                        replacement = cand.lower()
                        break
                if replacement != ch:
                    break
        out.append(replacement)
    return "".join(out)


def check(observed_domain: str, protected_domain: str,
          max_distance: int = 1) -> LookalikeResult:
    """Return a result describing whether `observed` is a lookalike of `protected`."""
    observed = registrable(observed_domain)
    protected = registrable(protected_domain)
    if not observed or not protected:
        return LookalikeResult(False, observed, protected, 0)
    if observed == protected:
        return LookalikeResult(False, observed, protected, 0)

    # Decode any xn-- A-labels to Unicode so the distance check sees the
    # visual form an end user would. The original ASCII string is still
    # returned in `observed` for the report.
    obs_label = _idn_to_unicode(observed).split(".", 1)[0]
    pro_label = _idn_to_unicode(protected).split(".", 1)[0]
    # A `www-` glued into the SLD (e.g. `www-acme.io`) sails past the
    # subdomain stripping that handles `www.acme.io`, but is the same
    # phishing shape — register the brand name with a `www-` shim so the
    # raw distance to the legitimate label is 4. Charge it as a single
    # edit so the impostor falls within the configured threshold.
    extra_cost = 0
    if obs_label.startswith("www-") and not pro_label.startswith("www-"):
        obs_label = obs_label[4:]
        extra_cost = 1
    elif pro_label.startswith("www-") and not obs_label.startswith("www-"):
        pro_label = pro_label[4:]
        extra_cost = 1
    distance = extra_cost + DamerauLevenshtein.distance(
        _skeleton(obs_label), _skeleton(pro_label)
    )
    return LookalikeResult(distance <= max_distance, observed, protected, distance)
