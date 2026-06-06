# thanks-for-all-the-phish

A tool to help with phishing detection for Gmail/Google Workspace.
It will add warnings to existing mails if it detects phishing
(internally it will remove original mail and create a new one with added changes out of thin air).

You can use original attachment and DKIM to verify it is pristine (using public signature) and then do a diff
to see that this tool did not invent anything.

Similar as IRONSCALES just free and open-source.

## Install

Requires Python 3.13. Pick one of the two environments — they don't share state.

**Option A — uv venv**

```bash
uv venv
uv sync --group dev    # drop --group dev if you don't want pytest
source .venv/bin/activate
```

**Option B — Nix flake**

```bash
nix develop            # python 3.13 + all deps from nixpkgs, no venv
```

## Configure

```bash
cp config.example.toml config.toml
$EDITOR config.toml
```

Every option is documented inline in `config.example.toml`.

## Single-user setup (regular Workspace user, no admin role)

A normal Workspace user can run this for their own mailbox via OAuth. No admin
involvement, no DWD, no Pub/Sub. Multi-user setup is covered further down.

### 1. Get the code running locally

```bash
git clone git@github.com:fiksn/thanks-for-all-the-phish.git
cd thanks-for-all-the-phish
uv venv && uv sync && source .venv/bin/activate
```

(Or `nix develop` if you prefer the flake.)

### 2. Create a personal Google Cloud project

The OAuth client lives in Google Cloud, not in Workspace. Any user can create
personal GCP projects.

1. Sign in at <https://console.cloud.google.com/> with your `@yourcompany.tld`
   account.
2. Top bar → **Select a project → New Project**, e.g. `thanks-for-all-the-phish`. Save.

### 3. Enable the Gmail API

In the new project: **APIs & Services → Library** → search **Gmail API** →
**Enable**.

### 4. Configure the OAuth consent screen

**APIs & Services → OAuth consent screen**.

- **User type**:
  - **Internal** — only your domain's users can sign in. Cleanest, but some
    workspaces restrict who can create Internal OAuth clients.
  - **External + Testing mode** — works for any user. Add your own email
    under **Test users**. The app stays in "Testing" and doesn't need
    Google verification.
- App name: anything (e.g. `thanks-for-all-the-phish`). Support email: yours. Save.
- Scopes step can be left empty for a Desktop client — the actual scope is
  requested at runtime.

### 5. Create OAuth client credentials

**APIs & Services → Credentials → Create credentials → OAuth client ID**.

- Application type: **Desktop app**.
- Download the JSON, save it next to the repo as `client_secret.json`.

### 6. Edit `config.toml`

```bash
cp config.example.toml config.toml
```

Minimum settings:

```toml
domain = "yourcompany.tld"
user = "you@yourcompany.tld"
auth_mode = "oauth"
client_secret_file = "client_secret.json"
token_file = "token.json"

# Destructive feature: leave empty while testing. Each entry is a regex matched
# (re.fullmatch) against the lowercased From: address. Empty list disables
# rewriting entirely. Use [".*"] once you trust the round-trip.
rewrite_only_from = []
```

### 7. First run — read-only

```bash
python -m tfatp
```

A browser tab opens. Sign in **as the exact `user` above** and approve the
`mail.google.com` scope.

> If you used External + Testing, Google will warn "Google hasn't verified
> this app." Click **Advanced → Go to {app name} (unsafe)** — the app is
> your own code.

`token.json` is written. The console prints the latest message and watches for
new mail. Send yourself a test mail containing a link to a young domain (or
something with a password input form) to confirm warnings render.

### 8. Enable auto-rewrite (destructive — opt in once you trust it)

In `config.toml`:

```toml
rewrite_only_from = ["you@yourcompany\\.tld"]   # start strict
loop_guard_secret = "…32-byte secret…"          # required once non-empty
```

Restart `python -m tfatp`. Mail from senders matching `rewrite_only_from` that
trip a warning gets deleted and replaced with a rewritten copy that has the
original attached as `original.eml`. Mail from senders that don't match is
left alone — the watcher logs why it skipped.

Once you trust the round-trip, broaden the list (`[".*"]` matches every
sender). An empty list disables rewriting entirely.

### 9. Keep it running

- Foreground: `python -m tfatp` in a terminal.
- Background: `nohup python -m tfatp > phish.log 2>&1 &`, or wrap in systemd
  / launchd / a screen session.
- The default IDLE watcher holds one TLS socket to `imap.gmail.com` and
  uses near-zero CPU.

### What a non-admin user **cannot** do

- Domain-wide delegation, `python -m tfatp.cli.watch_domain`, Admin SDK user
  enumeration — these need Workspace super-admin to authorize a service
  account.
- Sub-second push via Cloud Pub/Sub *is* possible per-user (the GCP project
  is yours), but the simpler IDLE/polling watcher is fine for a single
  mailbox.

### Common gotchas

- **IMAP** in Gmail → Settings → **Forwarding and POP/IMAP** powers the
  IDLE watcher. If IMAP is off (or disabled org-wide), `python -m tfatp`
  automatically falls back to the history-polling watcher — same hooks,
  same analysis, just a few seconds of detection latency instead of
  sub-second push.
- **Headless VM**: the OAuth flow needs a browser. Run `python -m tfatp`
  once on a local machine, copy `token.json` to the VM.
- **External + Testing OAuth**: refresh tokens may expire after 7 days.
  Re-run the flow if Gmail starts returning auth errors.
- **Outbound probes**: the password-form check fetches each link from
  your IP. The Chrome-shaped User-Agent blends in, but if you want
  plausible deniability, set `HTTPS_PROXY` to route through a sandbox.

## Entry points

| Command | Purpose | Auth mode |
|---|---|---|
| `python -m tfatp` (= `python -m tfatp.cli.watch_mailbox`) | Single-user watcher, prints latest message + new mail with DKIM/link analysis. | oauth or DWD |
| `python -m tfatp.cli.analyze_eml` | Run analysis on an `.eml` from stdin/file, emit a rewritten `.eml` on stdout. | none |
| `python -m tfatp.cli.inject_eml` | Inject a raw `.eml` into the mailbox, simulating arrival (triggers IDLE/Pub/Sub/poll like a real receive). | oauth or DWD |
| `python -m tfatp.cli.replace_message <id>` | Delete + insert one message manually (needs `--yes`). | oauth or DWD |
| `python -m tfatp.cli.diff_message <id>` | Show what tfatp did to a rewritten message: header additions, DKIM verdict on the original, body diff. | oauth or DWD |
| `python -m tfatp.cli.watch_domain` | Watch every user in the domain via Pub/Sub with polling fallback. | DWD only |

## Permissions, scopes, and IAM

### Gmail mailbox access

Both auth modes use **one** Gmail scope:

```
https://mail.google.com/
```

This is the only scope that grants `messages.delete` (permanent delete). It
implicitly covers `readonly`, `insert`, and `modify`, so a single grant is
enough for the whole read/insert/delete pipeline.

### OAuth (per-user)

1. Cloud Console → **APIs & Services → Library** → enable **Gmail API**.
2. **OAuth consent screen** → configure (Internal if you own the workspace).
3. **Credentials → Create credentials → OAuth client ID** → application type
   **Desktop app**. Save the JSON as `client_secret.json`.
4. First `python -m tfatp` opens a browser. Sign in, approve `https://mail.google.com/`.
   The refresh token is cached at `token_file`.

OAuth is bound to the consenting account — you can only act as that user.

### Service account + domain-wide delegation (DWD)

For multi-user features (`watch_domain`, `GmailClient.for_user`), Admin SDK,
and Pub/Sub, you need DWD.

1. Cloud Console → **IAM & Admin → Service Accounts** → create one.
   Create a JSON key, save as `service_account.json`. Note the **client_id**.
2. On the service account, enable **domain-wide delegation**.
3. Workspace Admin Console → **Security → Access and data control →
   API controls → Domain-wide delegation → Add new**:
   - Client ID: from step 1
   - OAuth scopes (comma-separated — add only the ones you need):

     | Scope | Needed for |
     |---|---|
     | `https://mail.google.com/` | Reading, inserting, deleting mail for any user |
     | `https://www.googleapis.com/auth/admin.directory.user.readonly` | `watch_domain` user enumeration |

4. Set `auth_mode = "service_account"`, fill `service_account_file`, and (for
   `watch_domain`) set `admin_user` to a **super-admin** email. Directory API
   calls must impersonate an admin; regular users can't list the directory
   even with DWD.

### Cloud Pub/Sub (only for `watch_domain` push mode)

Gmail push notifications publish to a Pub/Sub topic that **you** own. Without
Pub/Sub config or with insufficient IAM, `watch_domain` falls back to polling
automatically.

1. Cloud Console → **Pub/Sub → Topics → Create topic**, e.g. `gmail-events`.
2. On the topic → **Permissions → Add principal**:
   - Principal: `gmail-api-push@system.gserviceaccount.com`
   - Role: **Pub/Sub Publisher** (`roles/pubsub.publisher`)

   This is what authorizes Gmail to publish to the topic. Without it,
   `users.watch()` returns **403 — permission denied**, and `watch_domain`
   falls back to polling for those users.
3. **Create subscription** on the topic, type **Pull**, e.g. `gmail-events-sub`.
4. On the subscription → **Permissions → Add principal**:
   - Principal: your service account's email
   - Role: **Pub/Sub Subscriber** (`roles/pubsub.subscriber`)
5. Fill `pubsub_project_id`, `pubsub_topic`, `pubsub_subscription` in `config.toml`.

`users.watch()` expires after ~7 days; `PubSubWatcher` renews every 24 hours.

## Detection paths

| Mode | Triggered by | Latency | Connections | When to use |
|---|---|---|---|---|
| `python -m tfatp --idle` | IMAP IDLE on a TLS socket | sub-second | 1 per user | single user, no GCP needed |
| `python -m tfatp --poll` | Gmail history polling | ≈ `poll_interval` | 0 | single user, dead-simple |
| `python -m tfatp.cli.watch_domain` (Pub/Sub) | Push to Pub/Sub | sub-second | 1 streaming subscriber | full domain, recommended |
| `python -m tfatp.cli.watch_domain --force-polling` | History polling per user | ≈ `poll_interval × users` | 0 | full domain, no GCP / debugging |

`watch_domain` automatically falls back to polling if Pub/Sub config is missing
or if `users.watch()` returns 403 for every user. If some users succeed and
others get denied, the denied ones are run on a polling thread alongside the
Pub/Sub subscriber.

## DKIM verification

```
dkim    : pass (d=google.com)
dkim    : fail (d=evil.example: signature did not verify)
dkim    : none (no DKIM-Signature header)
```

```python
from tfatp import GmailClient, verify_dkim, load_config

client = GmailClient(load_config())
msg = client.latest_message()
result = verify_dkim(client.get_raw_message(msg.id))
print(result.status, result.detail, result.ok)
```

## Link analysis

For each URL extracted from the body:

- **Registrable domain** via the Public Suffix List (`tldextract`).
- **Domain age** via RDAP at `https://rdap.org/domain/{domain}`. LRU-cached
  (`maxsize=512`, repeat lookups are free).
- **Password form check**: fetches the URL with a real Chrome 131 User-Agent
  and `Sec-Ch-Ua-*` headers, parses with BeautifulSoup. Flags a credential
  prompt on any of:
  - `<input type="password">`
  - `<input>` whose `name`/`id`/`placeholder`/`autocomplete` mentions
    `password`/`passwd`/`pwd`/`pass` (catches `type="text"` flipped by JS)
  - inline-script literals like `type:"password"` or `autocomplete="current-password"`
  LRU-cached. See **Known limitations** below for what this still misses.

Suspicious URLs (`age < config.young_domain_days` or password input found) get
`[WARNING: ...]` appended inline in the displayed body. The URL itself is
left intact so it stays usable in URL-aware terminals.

```python
from tfatp import analyze_links, annotate_links, message_body_text

body = message_body_text(raw_eml_bytes)
findings = analyze_links(body, young_domain_days=365)
print(annotate_links(body, findings))
```

## Known limitations

This is a small, static-only scanner. Treating any single check as authoritative
will give you false confidence; the phase model is designed so several signals
have to agree before a message is rewritten. Specific gaps worth knowing:

**Password-form detection (static HTML only).** The fetch parses the bytes the
server sent — no JavaScript executes. A modern phishing kit hosted as an SPA
(React/Vue/Svelte) ships a near-empty `<body>` and renders the credential prompt
client-side; we will see no password field. Likewise missed:
- forms injected on a click handler or after a `fetch(...)` for an "email-first"
  screen
- credential UIs loaded inside an `<iframe>` (we only inspect the top frame)
- WASM-rendered UIs
- credential capture without a form at all — pages that say "paste the code from
  your authenticator below" into a plain text field, then exfiltrate over fetch
A headless browser (Playwright) would close most of these gaps at the cost of
~200 MB of Chromium, several seconds per URL, and a much bigger CVE surface.
We do not run one. Outsourcing to a feed like urlscan.io or Safe Browsing is the
intended escape hatch once static checks are not enough.

**Domain age (RDAP).** We treat "RDAP returned nothing usable" as "young." That
defaults safe but produces false positives for ccTLDs with thin or missing RDAP
service. Three-attempt retry with backoff is in place, but a sustained outage at
`rdap.org` degrades every check using it.

**Lookalike (Levenshtein).** String distance only. Catches `y0urbank.com` /
`yourbamk.com`-style typosquats. Misses homoglyph attacks (`уоurbank.com` with
Cyrillic letters), IDN-encoded variants, and visually-similar TLD swaps
(`yourbank.co` vs `yourbank.com`). The check runs against your registered org
domains; anyone targeting a brand you don't own is invisible.

**SMTP probe.** Sends `RCPT TO:<sender>` and reads the response. Many providers
(Google, Outlook, Proton) accept-then-bounce as policy, so a clean SMTP result
proves the MX exists, not that the sender does. Treat it as one signal, not a
verdict.

**DKIM.** Verified on the original bytes only and surfaced display-only — never
used for scoring, gating, or defang. A DKIM pass does not vouch for the sender's
intent; it only proves the signing domain held the key when the message was
signed.

**Attachment scanning.** OOXML (`.docx`/`.xlsm`/...) and legacy OLE
(`.doc`/`.xls`/...) only. PDFs, HTML attachments, ISO/IMG containers, LNK files,
script droppers, and signed installers are not inspected. Size-capped to 25 MB
per attachment; anything larger is flagged as "too large to scan" but not
analyzed.

**Phases run sequentially, not in parallel.** The phase list is grouped to
express "these checks gate together, the next group runs only if this one
passes" — but inside a phase we still loop over stages one by one. There is no
`asyncio.gather` or thread pool today. Latency is dominated by RDAP and the
link-fetch GETs.

**Outbound exposure.** Both the link fetch and the SMTP probe touch the
sender's infrastructure from your IP. Anti-phish kits log that visit and may
serve different content to repeat visitors. Route through a sandbox or proxy
if attribution matters.

## .eml analysis without OAuth

```bash
cat suspicious.eml | python -m tfatp.cli.analyze_eml > corrected.eml
# stderr: human report   stdout: rewritten .eml
```

The corrected `.eml`:

- Preserves all original headers (`From`, `To`, `Subject`, `Date`, `Message-ID`,
  `References`, `In-Reply-To`).
- Adds `X-Checked-By: thanks-for-all-the-phish`, `X-Checked-DKIM: ...`,
  `X-Checked-Findings: ...`.
- Body is `multipart/mixed`: part 1 is the annotated text, part 2 is the
  original message as a `message/rfc822` attachment named `original.eml`.

## Rewrite-in-place

`maybe_rewrite_new_mail(client, message_id)` deletes the original and inserts
the corrected copy. It's gated by two independent checks:

1. The message's `From:` address matches a regex in `rewrite_only_from`.
   Empty list disables rewriting; `[".*"]` enables it for every sender.
2. At least one warning was raised by the analysis.

Skipped messages log the reason. The deletion is permanent — the original is
preserved only inside the attached `message/rfc822` part of the new message.

Manual round-trip:

```bash
python -m tfatp.cli.analyze_eml original.eml > corrected.eml
python -m tfatp.cli.replace_message MESSAGE_ID < corrected.eml       # dry run
python -m tfatp.cli.replace_message --yes MESSAGE_ID < corrected.eml # commit
```

## Inspecting a rewritten message

`python -m tfatp.cli.diff_message <id>` shows exactly what the rewriter did to
a message that's still sitting in the mailbox. Useful for "is this banner
real?" debugging and after-the-fact audits.

Identifier forms accepted:

- **Gmail hex id** — the form the watcher prints (`18f3c2a9b4d5e6f7`). Passed
  to `users.messages.get` as-is.
- **RFC 822 Message-ID** — what `View original` in Gmail shows
  (`<CADna=9z…@mail.gmail.com>`). The CLI detects the `@` and resolves it to
  the hex id via `users.messages.list(q="rfc822msgid:…")` first.

What the command does, in order:

1. **Fetch** the raw RFC 822 bytes for the message id.
2. **Marker check.** Read the `X-Checked-By` header. If it isn't
   `tfatp/<version>`, the message was never rewritten and the command exits
   `1`. The watcher uses the same marker to skip its own rewrites, so the
   check is authoritative.
3. **HMAC verify** (if `loop_guard_secret` is set in config). The watcher
   stamps every rewrite with an `X-Checked-Mac` HMAC over the Message-ID.
   The CLI prints whether the MAC validates under the current secret —
   useful when a secret rotation is in flight.
4. **Find the embedded original.** Walk the MIME tree for a
   `message/rfc822` part named `original.eml`. That's the verbatim bytes
   the sender's MTA delivered, preserved as an attachment. Missing or
   unreadable → exit `2`.
5. **Verify DKIM** on the embedded original bytes. If DKIM passes, the
   diff is trustworthy: nobody between the sender and now (including a
   tampered-with rewrite) could have altered the original. If DKIM fails
   the diff is still printed, but exit code `3` flags it as untrusted —
   scripts can gate on the exit status.
6. **Render header diff.** Headers that the rewriter added (or that
   start with `x-checked-`) are listed: `X-Checked-By`, `X-Checked-Mac`,
   `X-Checked-Findings`, etc.
7. **Render body diff.** Unified diff between the original body and the
   rewritten body (with the embedded `original.eml` attachment stripped
   from the comparison so it isn't reported as a giant addition). Lines
   are whitespace-normalised before diffing — runs of spaces collapse to
   one, leading/trailing whitespace is dropped, and consecutive empty
   lines fold to one. That hides HTML reformatting noise from the
   BeautifulSoup round-trip and lets the diff highlight the changes that
   actually matter: banner additions, defanged URLs, header tweaks. Drop
   to a byte-level comparison by extracting `original.eml` from the
   rewritten message manually if you need it.

Example:

```bash
$ python -m tfatp.cli.diff_message 18f3c2a9b4d5e6f7
processed by tfatp — x-checked-by: tfatp/0.1.0
x-checked-mac: valid HMAC
original.eml: 4831 bytes
DKIM on original: pass (domain=example.com, selector=s1)

--- headers added by tfatp ---
  + X-Checked-Findings: https://login.bad.example/ -> password form
  + X-Checked-SMTP: pass (250 OK)

--- body diff (original → rewritten, excluding original.eml attachment) ---
@@
+CAUTION: This email originated from outside of the organization. …
+WARNING:
+  - Sender impersonation: …
+  - Links to young domains: …
 …original body lines…
-https://login.bad.example/
+https://login.bad.example.REMOVE-TO-VISIT.invalid/
```

Auth and impersonation:

```bash
python -m tfatp.cli.diff_message <id>                              # current user
python -m tfatp.cli.diff_message <id> --as alice@example.com       # DWD only
python -m tfatp.cli.diff_message <id> --config other.toml          # alt config
```

## Testing the pipeline safely

1. **Bench, no OAuth.** Use a synthetic `.eml` via `analyze_eml` and inspect
   the rewritten output. No risk to live mail.
2. **OAuth, read-only.** `rewrite_only_from = []`, run `python -m tfatp`, send
   yourself a phishy mail and verify the warnings render correctly.
3. **End-to-end without a real sender.** `inject_eml` writes an `.eml`
   straight into your inbox via `users.messages.insert`, so the watcher
   sees it as a fresh arrival (history-id bumps for Pub/Sub, UID bumps for
   IMAP IDLE) and the full pipeline runs.

   ```sh
   # Drop a phish lure into the inbox right now (no SMTP, no real sender).
   python -m tfatp.cli.inject_eml suspicious.eml

   # Land it at the top of the inbox view too (cosmetic — detection fires
   # either way; watchers don't key off Date:).
   python -m tfatp.cli.inject_eml suspicious.eml --bump-date

   # See what would happen, no API call:
   python -m tfatp.cli.inject_eml suspicious.eml --dry-run

   # Inject into another user's mailbox (domain-wide-delegation only):
   python -m tfatp.cli.inject_eml suspicious.eml --as alice@example.com
   ```

   Notes: the injected message's `From:` is whatever the `.eml` carries —
   if SMTP-verify is on, it will probe the real MX of that domain. Pair
   with `smtp_verify = false` for fully offline runs. `rewrite_only_from`
   still applies; if the injected `From:` doesn't match you'll see
   "suspicious but sender … does not match rewrite_only_from".
4. **One specific message.** `analyze_eml` → `replace_message --yes <id>` for
   one known-bad message. Confirm the new mail looks right in Gmail.
5. **Automatic, allowlist-gated.** `rewrite_only_from = ["alice@example\\.com"]`,
   `loop_guard_secret = "<32+ random chars>"`. Mail from anyone else is
   skipped; mail from yourself gets rewritten.
6. **Open up.** Set `rewrite_only_from = [".*"]` once you trust the round-trip.

## Library overview

```python
from tfatp import (
    GmailClient, load_config,
    MailWatcher, IdleWatcher,        # single-user watchers
    verify_dkim, DkimResult,
    analyze_links, annotate_links, message_body_text, LinkFinding,
)
from tfatp.directory import list_workspace_users        # DWD only
from tfatp.domain_watcher import DomainPollingWatcher   # DWD
from tfatp.pubsub_watcher import PubSubWatcher          # DWD
from tfatp.rewriter import maybe_rewrite_new_mail, replace_message
```

## Notes

- `insert` adds a message to the mailbox without sending it. To send,
  use `users.messages.send` (not implemented here).
- `delete` is **permanent** — bypasses Trash. The original survives only via
  the `message/rfc822` attachment of the rewritten message.
- The password-form check fetches each link from your IP with a Chrome-like
  UA. Anti-phish kits will log that visit. Route through a sandbox/proxy if
  that matters.
- `token.json`, `client_secret.json`, `service_account.json`, and
  `config.toml` are in `.gitignore` — never commit them.
