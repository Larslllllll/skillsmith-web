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
PAY_PER_USE_PRICE_USDC = 0.02  # buy a single extra scan without a Pro subscription

# GitHub user IDs (numeric, stable even if the username changes) that get
# unlimited scans, no payment. Intentionally a short hardcoded list, not a
# config surface -- this is "the project owner's own account", not a
# general admin/allowlist feature.
UNLIMITED_GITHUB_IDS = {"205042050"}  # Larslllllll


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
    # Audit finding P1-E: account records (OAuth provider/external id, email,
    # name, avatar, quota/Pro status) were previously written with
    # access=public to a public-access blob store, meaning anyone who
    # guessed or leaked a blob URL could read another user's account data
    # with no auth at all. This now writes to a *private* Vercel Blob store
    # (skillsmith-accounts): objects 403 for anonymous requests and only
    # resolve for requests carrying our BLOB_READ_WRITE_TOKEN, same as any
    # other server-side secret.
    #
    # Reliability fix: Vercel Blob's "uploadedAt" metadata only has
    # 1-SECOND resolution, so two writes to the same logical path within
    # the same second (very possible: e.g. check_and_consume_quota then
    # add_pay_per_use_credit in the same request) could tie, and picking
    # "the latest by uploadedAt" would then non-deterministically return
    # either version. Every record now carries its own nanosecond-resolution
    # "_v" field; _blob_get compares that instead of relying on blob
    # metadata timestamps.
    data = {**data, "_v": time.time_ns()}
    body = json.dumps(data).encode()
    url = f"{BLOB_API_BASE}/{path}"
    headers = {
        **_blob_headers(),
        "x-vercel-blob-access": "private",
        "x-add-random-suffix": "0",
        "x-content-type": "application/json",
    }
    req = urllib.request.Request(url, data=body, headers=headers, method="PUT")
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
    # uploadedAt has only 1s resolution (see _blob_put docstring), so when
    # more than one candidate exists we download every one of them (small
    # numbers in practice -- old versions aren't pruned yet, but a given
    # path rarely accumulates many writes in this project's traffic) and
    # pick by the nanosecond "_v" field embedded in the JSON itself.
    blobs.sort(key=lambda b: b.get("uploadedAt", ""), reverse=True)
    candidates = blobs[:5]
    best = None
    for b in candidates:
        try:
            dl_req = urllib.request.Request(b["url"], headers=_blob_headers(), method="GET")
            with urllib.request.urlopen(dl_req, timeout=10) as resp:
                doc = json.loads(resp.read().decode())
        except urllib.error.URLError:
            continue
        if best is None or doc.get("_v", 0) > best.get("_v", 0):
            best = doc
    return best


def _identity_path(provider: str, external_id: str) -> str:
    h = hashlib.sha256(f"{provider}:{external_id}".encode()).hexdigest()[:32]
    return f"identities/{h}.json"


def get_or_create_account_by_identity(provider: str, external_id: str, email: str = "", name: str = "", avatar_url: str = "") -> tuple[str, dict]:
    """Log in with GitHub/Google: resolve (provider, external_id) to a stable
    api_key so re-logging in on any device recovers the SAME account/quota,
    without the user having to copy-paste a key manually.
    """
    identity = _blob_get(_identity_path(provider, external_id))
    if identity and identity.get("api_key"):
        api_key = identity["api_key"]
        record = get_account(api_key) or {
            "created_at": time.time(), "free_used_date": "", "free_used_count": 0,
            "pro_expires_at": 0, "pro_used_date": "", "pro_used_count": 0,
        }
        unlimited = provider == "github" and external_id in UNLIMITED_GITHUB_IDS
        record.update({"provider": provider, "email": email, "name": name, "avatar_url": avatar_url})
        if unlimited:
            record["unlimited"] = True
        _blob_put(_blob_path(api_key), record)
        return api_key, record

    api_key = new_api_key()
    unlimited = provider == "github" and external_id in UNLIMITED_GITHUB_IDS
    record = {
        "created_at": time.time(), "free_used_date": "", "free_used_count": 0,
        "pro_expires_at": 0, "pro_used_date": "", "pro_used_count": 0,
        "provider": provider, "external_id": external_id,
        "email": email, "name": name, "avatar_url": avatar_url,
        "unlimited": unlimited,
    }
    _blob_put(_blob_path(api_key), record)
    _blob_put(_identity_path(provider, external_id), {"api_key": api_key})
    return api_key, record


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


def add_pay_per_use_credit(api_key: str, payment_detail: str) -> dict:
    """Buy a single extra scan for PAY_PER_USE_PRICE_USDC, no subscription.

    Credits are consumed by check_and_consume_quota before the account is
    ever blocked, so they work for both signed-up accounts that hit the
    5/day free limit and want exactly one more scan today, without forcing
    a $5 Pro commitment.
    """
    record = get_account(api_key) or {
        "created_at": time.time(), "free_used_date": "", "free_used_count": 0,
        "pro_expires_at": 0, "pro_used_date": "", "pro_used_count": 0,
    }
    record["bonus_credits"] = record.get("bonus_credits", 0) + 1
    record.setdefault("credit_purchases", []).append({"at": time.time(), "payment": payment_detail})
    _blob_put(_blob_path(api_key), record)
    return record


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
        # Audit finding P0-C: previously ANY unknown string was silently
        # accepted here and given a fresh blank quota record, which meant
        # "5 free scans/day" was trivially bypassed by sending a new random
        # api_key on every call. Real accounts (from /api/signup or OAuth
        # login, prefixed "sk_") must already exist -- an unknown "sk_..."
        # key is now rejected outright. Only the coarse per-IP pseudo-key
        # fallback (prefixed "ip_", generated server-side, never user
        # supplied) is allowed to start a fresh record on first use.
        if api_key.startswith("ip_"):
            record = {
                "created_at": time.time(), "free_used_date": "", "free_used_count": 0,
                "pro_expires_at": 0, "pro_used_date": "", "pro_used_count": 0,
            }
        else:
            return False, {"error": "unknown api_key, sign in again"}

    if record.get("unlimited"):
        return True, {"tier": "unlimited"}

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
        if record.get("bonus_credits", 0) > 0:
            record["bonus_credits"] -= 1
            _blob_put(_blob_path(api_key), record)
            return True, {"tier": "pay-per-use", "credits_remaining": record["bonus_credits"]}
        return False, {
            "tier": "free", "limit": FREE_DAILY_LIMIT, "used": record["free_used_count"],
            "error": "daily free limit reached: buy one more scan for $%.2f, or upgrade to Pro for $%.2f (100/day for %d days)"
            % (PAY_PER_USE_PRICE_USDC, PRO_PRICE_USDC, PRO_DURATION_DAYS),
        }
    record["free_used_count"] += 1
    _blob_put(_blob_path(api_key), record)
    return True, {"tier": "free", "limit": FREE_DAILY_LIMIT, "used": record["free_used_count"]}
