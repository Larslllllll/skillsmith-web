# skillsmith-web

Live browser demo for [skillsmith](https://github.com/Larslllllll/skillsmith):
paste a `SKILL.md`, get instant lint + static security-scan results.

**Live:** https://skillsmith-web.vercel.app

- `public/index.html` — paste-and-scan UI + signup/account bar
- `api/scan.py` — `POST /api/scan`, single-file scan
- `api/scan_pro.py` — `POST /api/scan_pro`, batch scan (up to 25 files) + Pro activation
- `api/signup.py` — `POST /api/signup` (create account), `GET /api/signup?api_key=...` (quota status)
- `api/account.py` — shared account/quota store (Vercel Blob-backed)

## Pricing: one account, any device

Sign in with GitHub, or `POST /api/signup` for an anonymous API key (no
email/password). Save the key and paste it into skillsmith-web on your
other device to share the **same** quota — sign up once, use it from your
phone and your laptop without double-paying or hitting two separate
free-tier counters. Scanning requires being signed in (either way).

| Tier | Limit | Price |
| --- | --- | --- |
| Free (no signup) | 5 scans/day, tracked per IP | $0 |
| Free (signed up) | 5 scans/day, tracked per account, same on every device | $0 |
| Pro | 100 scans/day for 30 days, same on every device | $5 USDC (Solana) |

## API

```bash
# 1. sign up
curl -X POST https://skillsmith-web.vercel.app/api/signup
# -> {"api_key": "sk_...", "free_daily_limit": 5, "pro_price_usdc": 5.0, "pro_daily_limit": 100}

# 2. scan (free tier, consumes 1/5 daily)
curl -X POST https://skillsmith-web.vercel.app/api/scan \
  -H "Content-Type: application/json" \
  -d '{"api_key":"sk_...","text":"---\nname: x\ndescription: y\n---\n\nbody"}'

# 3. check quota any time
curl "https://skillsmith-web.vercel.app/api/signup?api_key=sk_..."
```

### Pro API

```bash
# activate: send 5 USDC (SPL, mainnet mint EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v)
# to 2esJogvKTYDuxZaB9PEuEaHvz4U6TuQnTx3pkLcdH34N, then:
curl -X POST https://skillsmith-web.vercel.app/api/scan_pro \
  -H "Content-Type: application/json" \
  -d '{"api_key":"sk_...","activate_payment_signature":"<tx signature>"}'
# -> {"activated": true, "pro_expires_at": ..., "pro_daily_limit": 100}

# then batch-scan (consumes 1/100 daily, regardless of file count in the batch):
curl -X POST https://skillsmith-web.vercel.app/api/scan_pro \
  -H "Content-Type: application/json" \
  -d '{"api_key":"sk_...","files":[{"name":"a/SKILL.md","text":"..."},{"name":"b/SKILL.md","text":"..."}]}'
```

**Test mode:** any `activate_payment_signature` starting with
`test_signature_` activates Pro without a real payment, for integration
testing.

## How quota tracking works

Accounts are stored as JSON blobs in Vercel Blob storage
(`api/account.py`), keyed by a hash of the API key, so the same account
looks identical no matter which device or browser calls the API. Callers
with no `api_key` fall back to a coarser per-IP pseudo-account (still
5/day), which is why signing up matters once you use more than one
device or network.

Known limitation, documented rather than hidden: Vercel Blob is an object
store, not a transactional database, so a rare race between two
near-simultaneous requests from the same account could under-count a
quota check by one. Fine at this project's scale; would move to a proper
KV/DB store before this needed to be airtight under load.

## Legal / policy pages

- [Privacy Policy](public/privacy-policy.html) — what data is (and isn't) collected, AdSense cookie disclosure, EU consent handling
- [Terms of Service](public/terms.html)


## Security notes (fixed after an external audit, 2026-08-09)

An external review flagged several real issues, all fixed same-day:

- **XSS via scan results** (P0): scan output (including the untrusted
  skill's own `name` field) was rendered with `innerHTML`. Fixed: results
  are now built as DOM nodes with `textContent` only, so a malicious
  `SKILL.md` can't inject script into the page that scans it.
- **Free payment bypass** (P0): any `test_signature_*` string activated
  Pro for free in production. Fixed: test mode now also requires an
  `ALLOW_TEST_PAYMENTS=1` env var that is never set in production.
- **Free-quota bypass** (P0): an unknown `api_key` silently got a fresh
  blank quota record instead of being rejected, so a new random key
  reset the "5/day" limit every time. Fixed: unknown real (`sk_...`) keys
  are now rejected with 401 instead of auto-created.
- **OAuth without `state`** (P1): GitHub login had no CSRF protection.
  Fixed: a random `state` is set as an HttpOnly cookie on `/api/auth/github/start`
  and verified against the callback's `state` query param.
- **Account data in a public blob store** (P1): account records (email,
  name, avatar, quota) were stored with public access. Fixed: moved to a
  private Vercel Blob store (`skillsmith-accounts`) that 403s without the
  server's own token.

Google sign-in was removed (not configured / not wanted) — GitHub and an
anonymous key are the two ways to get an account.


## VirusTotal-style features

- **Hash-based scan history:** every scan is indexed by SHA-256 (we never
  store the raw text). Re-scanning identical content shows "seen before,
  N times". Look up any hash directly: `GET /api/lookup?sha256=<hash>`.
- **Safe skills database:** `GET /api/registry` lists skills that scanned
  clean + lint-ok, newest-first. Explicitly labeled as automated-heuristic
  only, not a manual security audit -- see the disclaimer shown in the UI
  and returned in every API response.
- **Pay-per-use:** `POST /api/buy_credit` buys exactly one extra scan for
  $0.02 USDC, no Pro subscription required -- for the occasional overflow
  scan without committing to 100/day.
- **Tabs in the UI:** Overview / Details / Database, matching a
  malware-scanner-style results view.

## Detection engine v2

Significantly expanded ruleset beyond the original pass: dynamic code
execution (`eval`/`exec`/`pickle`/`marshal`/unsafe `yaml.load`/`ctypes`),
credential/secret file access (SSH keys, AWS/GCP creds, wallet files),
network exfiltration (env vars sent in outbound requests, DNS exfil
patterns), persistence mechanisms (cron, shell startup files, OS
auto-start locations), obfuscation techniques (long base64/hex blobs,
zero-width unicode characters, Latin/Cyrillic homoglyph mixing), and a
much broader prompt-injection phrasing list (jailbreak framing,
instruction-override phrasing, hidden HTML-comment instructions,
prompt-extraction phrasing). Still a static heuristic scanner -- see the
disclaimer in the UI and in every scan response.
