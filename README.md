# skillsmith-web

Live browser demo for [skillsmith](https://github.com/Larslllllll/skillsmith):
paste a `SKILL.md`, get instant lint + static security-scan results.
Stateless — nothing submitted is stored.

**Live:** https://skillsmith-web.vercel.app

- `public/index.html` — single-page paste-and-scan UI (free tier)
- `api/scan.py` — Vercel Python (WSGI) serverless function, free tier: one file per call
- `api/scan_pro.py` — **Pro tier**: batch-scan up to 25 files per call, gated by a
  real on-chain USDC (Solana) payment

## Pro API

```
POST /api/scan-pro
```

Call it with no `payment_signature` to get pricing + a pay-to address:

```bash
curl -X POST https://skillsmith-web.vercel.app/api/scan-pro \
  -H "Content-Type: application/json" \
  -d '{"files":[{"name":"a/SKILL.md","text":"..."}]}'
```

```json
{
  "error": "payment_required",
  "price_usdc": 0.02,
  "pay_to": "2esJogvKTYDuxZaB9PEuEaHvz4U6TuQnTx3pkLcdH34N",
  "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  "network": "solana-mainnet"
}
```

Send `price_usdc` worth of USDC (SPL token, mainnet) to `pay_to`, then
resubmit with the finalized transaction signature:

```bash
curl -X POST https://skillsmith-web.vercel.app/api/scan-pro \
  -H "Content-Type: application/json" \
  -d '{"payment_signature":"<tx signature>","files":[{"name":"a/SKILL.md","text":"..."}]}'
```

The signature is verified server-side against the public Solana JSON-RPC
(`getTransaction`), checking that a finalized USDC transfer of at least
`price_usdc` landed at `pay_to`. No API key, no account, no webhook —
pay-per-call.

**Test mode:** use `"payment_signature": "test_signature_anything"` to
exercise the batch endpoint for free while integrating, without sending a
real payment.

**Known limitation:** signature reuse is not yet blocked across cold
starts (no persistence layer wired up in this first version) — fine for a
$0.02-scale utility, would add before handling larger amounts.

## Why USDC/Solana instead of Stripe

This is a tool built for AI agents as much as for humans — agents can hold
and spend a Solana wallet autonomously with no human-in-the-loop signup,
KYC, or card entry, which a card-based paywall would require. It's the
same "pay-per-call over HTTP" model used elsewhere in the agent-tooling
ecosystem (x402-style flows, AgentVault-style marketplaces).

## Legal / policy pages

- [Privacy Policy](public/privacy-policy.html) — what data is (and isn't) collected, AdSense cookie disclosure, EU consent handling
- [Terms of Service](public/terms.html)
