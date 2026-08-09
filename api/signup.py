"""
skillsmith-web /api/signup — Vercel Serverless (WSGI)
=======================================================
Creates a lightweight account (no email/password) so the same free-tier
quota and Pro status can be used from multiple devices: sign up once, copy
the API key shown, paste it into skillsmith-web on your phone too.

POST (empty body or {}) -> { "api_key": "sk_..." }

Also handles GET /api/signup?api_key=sk_... -> current account status
(tier, quota used/remaining) so the frontend can show "3/5 free scans left
today" etc.
"""
import json

from account import create_account, get_account, FREE_DAILY_LIMIT, PRO_DAILY_LIMIT, PRO_PRICE_USDC, PRO_DURATION_DAYS
import time

_CORS_HEADERS = [
    ("Access-Control-Allow-Origin", "*"),
    ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
    ("Access-Control-Allow-Headers", "Content-Type"),
    ("Access-Control-Max-Age", "86400"),
]


def _status_for(api_key: str) -> dict:
    record = get_account(api_key)
    if record is None:
        return {"error": "unknown api_key"}
    is_pro = record.get("pro_expires_at", 0) > time.time()
    today = time.strftime("%Y-%m-%d", time.gmtime())
    if is_pro:
        used = record.get("pro_used_count", 0) if record.get("pro_used_date") == today else 0
        return {
            "tier": "pro", "limit": PRO_DAILY_LIMIT, "used": used,
            "remaining": max(0, PRO_DAILY_LIMIT - used),
            "pro_expires_at": record.get("pro_expires_at"),
        }
    used = record.get("free_used_count", 0) if record.get("free_used_date") == today else 0
    return {
        "tier": "free", "limit": FREE_DAILY_LIMIT, "used": used,
        "remaining": max(0, FREE_DAILY_LIMIT - used),
        "pro_price_usdc": PRO_PRICE_USDC, "pro_duration_days": PRO_DURATION_DAYS,
    }


def handle(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET")
    if method == "OPTIONS":
        start_response("204 No Content", _CORS_HEADERS)
        return [b""]

    if method == "GET":
        qs = environ.get("QUERY_STRING", "")
        params = dict(p.split("=", 1) for p in qs.split("&") if "=" in p)
        api_key = params.get("api_key", "")
        if not api_key:
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "api_key query param required"}).encode()]
        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps(_status_for(api_key)).encode()]

    if method != "POST":
        start_response("405 Method Not Allowed", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": "GET or POST only"}).encode()]

    api_key, record = create_account()
    start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
    return [json.dumps({
        "api_key": api_key,
        "note": "Save this key. Paste it into skillsmith-web on any other device to share your quota (5 free scans/day, or Pro if activated). There is no email/password recovery for this key.",
        "free_daily_limit": FREE_DAILY_LIMIT,
        "pro_daily_limit": PRO_DAILY_LIMIT,
        "pro_price_usdc": PRO_PRICE_USDC,
        "pro_duration_days": PRO_DURATION_DAYS,
    }).encode()]


app = handle
