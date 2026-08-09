"""
skillsmith-web account/quota store — shared by api/scan.py, api/scan_pro.py,
and api/signup.py.

Accounts exist so the same free-tier quota and Pro status follow a user
across devices (phone + laptop), instead of being tied to one browser's
localStorage or one device's IP address.

Storage: Vercel Blob (a simple public JSON blob per account, keyed by a
hash of the API key). This is a lightweight object store, not a proper
database — reads are "get latest JSON", writes are "overwrite the JSON".
At this project's scale that's a deliberate, documented tradeoff (a rare
race on simultaneous double-tap requests could under-count a quota check
by one), not a hidden bug.

No email, no password: signup just mints a random API key and stores an
account record under it. You "log in" on a second device by pasting the
same key. This keeps the whole flow usable without an email-sending
service, while still solving the actual problem (one account, one quota,
usable from any device).
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import urllib.error
import urllib.request

BLOB_TOKEN = os.environ.get("BLOB_READ_WRITE_TOKEN", "")
BLOB_API_BASE = "https://blob.vercel-storage.com"

FREE_DAILY_LIMIT = 5
PRO_DAILY_LIMIT = 100
PRO_PRICE_USDC = 5.0
PRO_DURATION_DAYS = 30


def _today() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def new_api_key() -> str:
    return "sk_" + secrets.token_urlsafe(24)


def pseudo_key_for_ip(ip: str) -> str:
    """Coarse fallback account for anonymous callers with no api_key.

    Ties the free quota to a client IP instead of a real account, so a
    single browser without signup still gets *a* limit, but this does not
    follow the user across devices/networks the way a real api_key does
    (that's the whole point of signing up).
    """
    return "ip_" + hashlib.sha256((ip or "unknown").encode()).hexdigest()[:24]


def _key_hash(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()[:32]


def _blob_path(api_key: str) -> str:
    return f"accounts/{_key_hash(api_key)}.json"


def _blob_headers() -> dict:
    return {"Authorization": f"Bearer {BLOB_TOKEN}", "Content-Type": "application/json"}


def _blob_put(path: str, data: dict) -> None:
    body = json.dumps(data).encode()
    url = f"{BLOB_API_BASE}/{path}?access=public&addRandomSuffix=false"
    req = urllib.request.Request(url, data=body, headers=_blob_headers(), method="PUT")
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def _blob_get(path: str) -> dict | None:
    # Vercel Blob's "put" with addRandomSuffix=false still appends a random
    # suffix to the stored filename in practice, so each write to the same
    # logical path creates a new blob object; we resolve the current value
    # by listing everything under this exact pathname prefix and taking the
    # most recently uploaded one. (A documented tradeoff, not a hidden bug:
    # old blob versions are not actively cleaned up in this first version.)
    # Vercel Blob's "prefix" filter matches against the *stored* filename,
    # which has "-<randomsuffix>" inserted before the extension, e.g.
    # "accounts/<hash>-XXXX.json" for logical path "accounts/<hash>.json".
    # A prefix that still includes ".json" therefore never matches; strip
    # the extension so the prefix lands before the random suffix.
    prefix = path.rsplit(".", 1)[0] if "." in path else path
    url = f"{BLOB_API_BASE}/?prefix={prefix}&limit=20"
    req = urllib.request.Request(url, headers=_blob_headers(), method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            listing = json.loads(resp.read().decode())
    except urllib.error.URLError:
        return None
    blobs = [b for b in listing.get("blobs", []) if b.get("pathname") == path]
    if not blobs:
        return None
    latest = max(blobs, key=lambda b: b.get("uploadedAt", ""))
    try:
        with urllib.request.urlopen(latest["url"], timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.URLError:
        return None


def create_account() -> tuple[str, dict]:
    api_key = new_api_key()
    record = {
        "created_at": time.time(),
        "free_used_date": "",
        "free_used_count": 0,
        "pro_expires_at": 0,
        "pro_used_date": "",
        "pro_used_count": 0,
    }
    _blob_put(_blob_path(api_key), record)
    return api_key, record


def get_account(api_key: str) -> dict | None:
    return _blob_get(_blob_path(api_key))


def activate_pro(api_key: str, payment_detail: str) -> dict:
    record = get_account(api_key) or {
        "created_at": time.time(), "free_used_date": "", "free_used_count": 0,
        "pro_expires_at": 0, "pro_used_date": "", "pro_used_count": 0,
    }
    record["pro_expires_at"] = time.time() + PRO_DURATION_DAYS * 86400
    record["pro_activated_via"] = payment_detail
    _blob_put(_blob_path(api_key), record)
    return record


def check_and_consume_quota(api_key: str | None) -> tuple[bool, dict]:
    """Returns (allowed, info). Consumes one unit of quota if allowed.

    Anonymous (no api_key): always allowed, but info notes it's unmetered
    at the account level (caller may still apply a coarser IP limit).
    """
    if not api_key:
        return True, {"tier": "anonymous", "note": "sign up to get a synced quota across devices"}

    record = get_account(api_key)
    if record is None:
        # Unknown key (including IP-derived pseudo-keys for anonymous
        # users): start a fresh, blank record rather than hard-failing.
        # This keeps a mistyped/never-signed-up key usable instead of
        # locking a user out entirely.
        record = {
            "created_at": time.time(), "free_used_date": "", "free_used_count": 0,
            "pro_expires_at": 0, "pro_used_date": "", "pro_used_count": 0,
        }

    today = _today()
    is_pro = record.get("pro_expires_at", 0) > time.time()

    if is_pro:
        if record.get("pro_used_date") != today:
            record["pro_used_date"] = today
            record["pro_used_count"] = 0
        if record["pro_used_count"] >= PRO_DAILY_LIMIT:
            return False, {
                "tier": "pro", "limit": PRO_DAILY_LIMIT, "used": record["pro_used_count"],
                "error": "daily Pro limit reached",
            }
        record["pro_used_count"] += 1
        _blob_put(_blob_path(api_key), record)
        return True, {"tier": "pro", "limit": PRO_DAILY_LIMIT, "used": record["pro_used_count"]}

    if record.get("free_used_date") != today:
        record["free_used_date"] = today
        record["free_used_count"] = 0
    if record["free_used_count"] >= FREE_DAILY_LIMIT:
        return False, {
            "tier": "free", "limit": FREE_DAILY_LIMIT, "used": record["free_used_count"],
            "error": "daily free limit reached, upgrade to Pro for $%.2f (100/day for %d days)"
            % (PRO_PRICE_USDC, PRO_DURATION_DAYS),
        }
    record["free_used_count"] += 1
    _blob_put(_blob_path(api_key), record)
    return True, {"tier": "free", "limit": FREE_DAILY_LIMIT, "used": record["free_used_count"]}
