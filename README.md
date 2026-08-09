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

No email or password: `POST /api/signup` mints an API key. Save it and
paste it into skillsmith-web on your other device to share the **same**
quota — sign up once, use it from your phone and your laptop without
double-paying or hitting two separate free-tier counters.

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
