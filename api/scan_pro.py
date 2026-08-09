"""
skillsmith-web /api/scan-pro — Vercel Serverless (WSGI)
=========================================================
Paid "Pro" tier: batch-scan up to 25 SKILL.md files in one call, gated by a
real on-chain USDC (Solana) payment, verified against the public Solana RPC.

POST body:
  {
    "payment_signature": "<base58 solana tx signature>",
    "files": [{"name": "skill-a/SKILL.md", "text": "..."}, ...]
  }

Payment: send >= PRICE_USDC of USDC (SPL token, mainnet mint
EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v) to PAYOUT_WALLET, then submit
the finalized transaction signature. We verify the transfer server-side via
the public Solana JSON-RPC before running the batch scan. Test mode: a
signature starting with "test_signature_" is accepted without a real
payment so integrators can build against this before spending anything.

Known limitation (documented, not hidden): signature re-use is not
persisted across serverless cold starts in this first version, so this is
"pay per verified transaction" rather than strict single-use redemption.
Fine for a $0.02-scale utility endpoint; would add a persistence layer
(Vercel KV/Blob) before this handled meaningfully larger amounts.
"""
import json
import urllib.request

from scan import analyze  # same module as the free /api/scan endpoint

PAYOUT_WALLET = "2esJogvKTYDuxZaB9PEuEaHvz4U6TuQnTx3pkLcdH34N"
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
PRICE_USDC = 0.02  # per batch call, up to MAX_FILES files
MAX_FILES = 25
SOLANA_RPC = "https://api.mainnet-beta.solana.com"

_CORS_HEADERS = [
    ("Access-Control-Allow-Origin", "*"),
    ("Access-Control-Allow-Methods", "POST, OPTIONS"),
    ("Access-Control-Allow-Headers", "Content-Type"),
    ("Access-Control-Max-Age", "86400"),
]


def _rpc(method, params):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(SOLANA_RPC, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def verify_payment(signature: str) -> tuple[bool, str]:
    if signature.startswith("test_signature_"):
        return True, "test mode"

    try:
        result = _rpc(
            "getTransaction",
            [signature, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}],
        )
    except Exception as e:  # noqa: BLE001
        return False, f"RPC error: {e}"

    tx = result.get("result")
    if not tx:
        return False, "transaction not found (not yet finalized, or invalid signature)"
    if tx.get("meta", {}).get("err") is not None:
        return False, "transaction failed on-chain"

    meta = tx.get("meta", {})
    pre = {b["accountIndex"]: b for b in meta.get("preTokenBalances", []) if b.get("mint") == USDC_MINT}
    post = {b["accountIndex"]: b for b in meta.get("postTokenBalances", []) if b.get("mint") == USDC_MINT}

    received = 0.0
    for idx, post_bal in post.items():
        if post_bal.get("owner") != PAYOUT_WALLET:
            continue
        pre_amount = float(pre.get(idx, {}).get("uiTokenAmount", {}).get("uiAmount") or 0)
        post_amount = float(post_bal.get("uiTokenAmount", {}).get("uiAmount") or 0)
        received += max(0.0, post_amount - pre_amount)

    if received + 1e-9 < PRICE_USDC:
        return False, f"payment too small: received {received} USDC, need {PRICE_USDC}"
    return True, f"verified {received} USDC"


def handle(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET")
    if method == "OPTIONS":
        start_response("204 No Content", _CORS_HEADERS)
        return [b""]
    if method != "POST":
        start_response("405 Method Not Allowed", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": "POST only"}).encode()]

    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
        raw = environ["wsgi.input"].read(length) if length else b"{}"
        payload = json.loads(raw or b"{}")
        signature = payload.get("payment_signature", "")
        files = payload.get("files", [])

        if not signature:
            start_response("402 Payment Required", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({
                "error": "payment_required",
                "price_usdc": PRICE_USDC,
                "pay_to": PAYOUT_WALLET,
                "mint": USDC_MINT,
                "network": "solana-mainnet",
                "instructions": f"Send >= {PRICE_USDC} USDC to {PAYOUT_WALLET}, then POST again with payment_signature set to the finalized tx signature.",
            }).encode()]

        ok, detail = verify_payment(signature)
        if not ok:
            start_response("402 Payment Required", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "payment_not_verified", "detail": detail}).encode()]

        if not isinstance(files, list) or not files:
            raise ValueError("files must be a non-empty list of {name, text}")
        if len(files) > MAX_FILES:
            raise ValueError(f"max {MAX_FILES} files per batch call")

        results = []
        for f in files:
            name = str(f.get("name", "SKILL.md"))[:200]
            text = f.get("text", "")
            if not isinstance(text, str) or len(text) > 100_000:
                results.append({"name": name, "error": "text must be a string under 100,000 chars"})
                continue
            results.append({"name": name, **analyze(text)})

        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"payment": detail, "results": results}).encode()]

    except Exception as e:  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": str(e)}).encode()]


app = handle
