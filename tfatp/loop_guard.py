"""HMAC-based marker that lets the rewriter recognize its own inserted copies.

Without this, the rewriter would loop: every `messages.insert` of a corrected
copy bumps the mailbox historyId, the watcher dispatches the new id back into
`maybe_rewrite_new_mail`, the suspicious-decision re-fires on the preserved
From/Subject/Date, and another rewrite cycle begins.

A bare `X-Checked-By` header is not enough — any sender can put that string in
an outbound message and bypass the analyzer entirely. We bind the marker to
the message's `Message-Id` via HMAC-SHA256 over a per-mailbox secret so the
attacker can't produce a valid stamp without knowing the secret.

Known limitation: an attacker who has previously received a rewritten message
from us could copy that message's (Message-Id, X-Checked-Mac) pair onto a new
phish. In practice this requires them to have been a recipient of one of our
rewritten messages AND to send a message with the same Message-Id (which Gmail
often dedups). Full replay-resistance would need server-side state — out of
scope for this guard.
"""

import hmac
from email.message import Message
from hashlib import sha256

X_CHECKED_BY = "thanks-for-the-phish"
HEADER_CHECKED_BY = "X-Checked-By"
HEADER_MAC = "X-Checked-Mac"


def compute_mac(secret: str, message_id: str) -> str:
    """HMAC-SHA256 over the Message-Id, hex-encoded."""
    key = secret.encode("utf-8")
    msg = (message_id or "").encode("utf-8")
    return hmac.new(key, msg, sha256).hexdigest()


def is_own_rewrite(msg: Message, secret: str) -> bool:
    """True iff `msg` carries a marker we recognize as produced by us.

    Fails closed: empty secret, missing headers, or mismatched MAC all return
    False. `hmac.compare_digest` guards against timing oracles even though
    the inputs are public hex strings.
    """
    if not secret:
        return False
    if (msg.get(HEADER_CHECKED_BY, "") or "").strip().lower() != X_CHECKED_BY:
        return False
    presented = (msg.get(HEADER_MAC, "") or "").strip()
    expected = compute_mac(secret, str(msg.get("Message-Id", "")))
    return bool(presented) and hmac.compare_digest(presented, expected)
