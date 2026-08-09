"""
skillsmith-web unified API entrypoint (Vercel Serverless, WSGI)
=================================================================
Vercel's current Python builder wants a single entrypoint per project, so
all endpoints live in one WSGI app here and dispatch on PATH_INFO:

  POST /api/scan       -> single-file lint + security scan
  POST /api/scan_pro   -> Pro: batch scan / Pro activation
  GET|POST /api/signup -> create account / check quota status

vercel.json routes /api/scan, /api/scan_pro, and /api/signup here.
"""
import json
import re
import time
import urllib.error
import urllib.request

import yaml

import os
import secrets
import urllib.parse

try:
    from .account import (
        PRO_PRICE_USDC,
        PRO_DURATION_DAYS,
        PRO_DAILY_LIMIT,
        PAY_PER_USE_PRICE_USDC,
        activate_pro,
        add_pay_per_use_credit,
        check_and_consume_quota,
        create_account,
        get_account,
        get_or_create_account_by_identity,
        pseudo_key_for_ip,
    )
    from .scans import sha256_of, get_scan_record, record_scan, list_safe_registry
except ImportError:  # local/script execution without package context
    from account import (
        PRO_PRICE_USDC,
        PRO_DURATION_DAYS,
        PRO_DAILY_LIMIT,
        PAY_PER_USE_PRICE_USDC,
        activate_pro,
        add_pay_per_use_credit,
        check_and_consume_quota,
        create_account,
        get_account,
        get_or_create_account_by_identity,
        pseudo_key_for_ip,
    )
    from scans import sha256_of, get_scan_record, record_scan, list_safe_registry

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
SITE_URL = os.environ.get("SITE_URL", "https://skillsmith-web.vercel.app")

DISCLAIMER = (
    "skillsmith is a static heuristic scanner. It has no sandbox and does not "
    "execute the skill. A 'clean' result means our current ruleset found "
    "nothing suspicious -- it is NOT a guarantee of safety, and a skill can "
    "still be malicious in ways this scanner does not (yet) detect. A 'high "
    "risk' result can also be a false positive. Always read code you did not "
    "write yourself before running it, especially anything with a "
    "python_import."
)

_CORS_HEADERS = [
    ("Access-Control-Allow-Origin", "*"),
    ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
    ("Access-Control-Allow-Headers", "Content-Type"),
    ("Access-Control-Max-Age", "86400"),
]

# ---------------------------------------------------------------------------
# Core lint/scan logic (same heuristics as the skillsmith CLI)
# ---------------------------------------------------------------------------

NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
REQUIRED_KEYS = ("name", "description")
RECOMMENDED_MAX_DESCRIPTION_CHARS = 500
FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?\n)---\s*\n?(.*)$", re.DOTALL)

# ---------------------------------------------------------------------------
# Detection engine v2 -- substantially expanded ruleset.
#
# Categories: dangerous code execution, credential/secret access, network
# exfiltration, persistence mechanisms, obfuscation techniques, and prompt
# injection / instruction-override phrasing. Weighted 1-10 by how strong a
# standalone signal each pattern is. This is still a static heuristic
# scanner -- see the disclaimer shown in the UI -- but the ruleset is far
# broader than a first pass.
# ---------------------------------------------------------------------------

_CODE_PATTERNS = [
    # --- direct code execution ---
    (re.compile(r"\bos\.system\s*\("), 8, "shells out via os.system"),
    (re.compile(r"\bsubprocess\.(Popen|call|run|check_output)\s*\("), 6, "spawns a subprocess"),
    (re.compile(r"\bsubprocess\.\w+\([^)]*shell\s*=\s*True"), 9, "subprocess with shell=True (shell injection risk)"),
    (re.compile(r"\beval\s*\("), 9, "calls eval() on dynamic input"),
    (re.compile(r"\bexec\s*\("), 9, "calls exec() on dynamic input"),
    (re.compile(r"\bcompile\s*\([^)]*['\"]exec['\"]"), 8, "compiles code for exec at runtime"),
    (re.compile(r"\bpickle\.(loads|load)\s*\("), 7, "deserializes with pickle (arbitrary code execution risk)"),
    (re.compile(r"\bmarshal\.(loads|load)\s*\("), 7, "deserializes with marshal (arbitrary code execution risk)"),
    (re.compile(r"\byaml\.(load|unsafe_load)\s*\((?!.*Loader=yaml\.SafeLoader)"), 6, "yaml.load without SafeLoader (arbitrary code execution risk)"),
    (re.compile(r"\b__import__\s*\("), 5, "dynamically imports modules"),
    (re.compile(r"\bimportlib\.import_module\s*\([^)]*\+"), 6, "dynamically imports a module built from a variable/expression"),
    (re.compile(r"\bctypes\."), 6, "uses ctypes (direct memory/native code access)"),
    (re.compile(r"\bgetattr\s*\([^,]+,\s*[a-zA-Z_]\w*\s*\)\s*\("), 4, "calls a dynamically-resolved attribute (reflection-based execution)"),

    # --- credential / secret access ---
    (re.compile(r"os\.environ(\.get)?\s*\[?['\"](\w*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE)\w*)['\"]"), 6, "reads an environment variable that looks like a credential"),
    (re.compile(r"\bopen\s*\([^)]*['\"]\.ssh"), 8, "reads from ~/.ssh"),
    (re.compile(r"\bopen\s*\([^)]*['\"]\.aws"), 8, "reads from ~/.aws credentials"),
    (re.compile(r"\bopen\s*\([^)]*['\"]\.gnupg"), 8, "reads from ~/.gnupg"),
    (re.compile(r"\bopen\s*\([^)]*(id_rsa|id_ed25519|\.npmrc|\.netrc|\.git-credentials)"), 8, "reads a known credential/secret file"),
    (re.compile(r"\bkeyring\.(get_password|get_credential)\s*\("), 6, "reads from the OS keyring/credential store"),
    (re.compile(r"\bwallet\.json|\bprivate[_-]?key\s*[:=]"), 7, "references a wallet file or private key variable"),

    # --- network exfiltration ---
    (re.compile(r"\brequests\.(post|put|get)\s*\("), 3, "makes outbound network requests"),
    (re.compile(r"\burllib\.request\.urlopen\s*\("), 3, "makes outbound network requests"),
    (re.compile(r"\bsocket\.socket\s*\("), 4, "opens raw sockets"),
    (re.compile(r"requests\.(post|put)\s*\([^)]*(environ|getenv|os\.environ)"), 8, "sends an environment variable in an outbound HTTP request (possible exfiltration)"),
    (re.compile(r"\bsmtplib\.SMTP\s*\("), 4, "sends email (possible exfiltration channel)"),
    (re.compile(r"\bdns\.resolver\.|\bsocket\.gethostbyname\s*\([^)]*\+"), 5, "builds a DNS lookup from a variable (possible DNS exfiltration)"),

    # --- destructive / persistence ---
    (re.compile(r"(?i)\brm\s+-rf\b"), 8, "contains a destructive shell command (rm -rf)"),
    (re.compile(r"(?i)\b(curl|wget)\b[^\n]*\|\s*(sh|bash|zsh)\b"), 9, "pipes a downloaded script directly into a shell (classic dropper pattern)"),
    (re.compile(r"(?i)iex\s*\(\s*new-object\s+net\.webclient"), 9, "PowerShell download-and-execute cradle"),
    (re.compile(r"(?i)\bcrontab\b|/etc/cron|systemd/system/.*\.service"), 6, "modifies scheduled tasks / system services (persistence)"),
    (re.compile(r"(?i)\.(bash_profile|bashrc|zshrc|profile)['\"]?\s*,\s*['\"]a"), 6, "appends to a shell startup file (persistence)"),
    (re.compile(r"(?i)LaunchAgents|LaunchDaemons|HKCU\\\\.*\\\\Run"), 7, "writes to a known OS auto-start location (persistence)"),
    (re.compile(r"\bchmod\s+\+x\b"), 3, "makes a file executable"),

    # --- obfuscation ---
    (re.compile(r"base64\.b64decode\s*\([^)]*\)\s*\)?\s*(#.*)?\n[^\n]*\bexec\s*\("), 9, "decodes base64 then executes the result (classic obfuscated payload)"),
    (re.compile(r"[A-Za-z0-9+/]{200,}={0,2}"), 4, "contains a very long base64-like blob (possible obfuscated payload)"),
    (re.compile(r"(?:\\x[0-9a-fA-F]{2}){20,}"), 5, "contains a long run of hex-escaped bytes (possible obfuscated payload)"),
    (re.compile(r"[\u200b\u200c\u200d\ufeff]"), 7, "contains zero-width/invisible unicode characters (common prompt-injection hiding technique)"),
    (re.compile(r"[а-яА-Я].*[a-zA-Z]|[a-zA-Z].*[а-яА-Я]"), 2, "mixes Latin and Cyrillic characters (possible homoglyph obfuscation)"),
]

_PROMPT_INJECTION_PATTERNS = [
    (re.compile(r"(?i)ignore (all|any|the) (previous|prior|above) instructions"), 10, "'ignore previous instructions' phrasing"),
    (re.compile(r"(?i)disregard (your|any) (safety|previous) (guidelines|instructions)"), 10, "safety-override phrasing"),
    (re.compile(r"(?i)you are now (in )?(developer|debug|jailbreak|dan|god) mode"), 10, "jailbreak/mode-override phrasing"),
    (re.compile(r"(?i)\bjailbroken\b|\bunrestricted (ai|assistant|mode)\b"), 9, "jailbreak-framing phrasing"),
    (re.compile(r"(?i)do not (tell|inform|mention (this )?to) the user"), 8, "instructs the agent to hide actions from the user"),
    (re.compile(r"(?i)without (telling|informing|alerting) the user"), 8, "instructs the agent to hide actions from the user"),
    (re.compile(r"(?i)send (the|this|your) (api[- ]?key|token|password|secret|private key|seed phrase|wallet) to"), 10, "instructs exfiltration of credentials"),
    (re.compile(r"(?i)(reveal|print|output|show) your (system prompt|instructions|guidelines)"), 8, "prompt-extraction phrasing"),
    (re.compile(r"(?i)act as (an?|the) (unrestricted|uncensored|amoral)"), 9, "unrestricted-persona jailbreak phrasing"),
    (re.compile(r"(?i)\bnew instructions?\s*:"), 6, "'new instructions:' phrasing that reads as an instruction override"),
    (re.compile(r"(?i)this (overrides|supersedes) (all|any) (previous|prior|other) (rules|instructions|policies)"), 9, "explicit instruction-override phrasing"),
    (re.compile(r"<!--[^>]*(ignore|instruction|system|override)[^>]*-->", re.IGNORECASE), 7, "hidden HTML comment containing instruction-like phrasing"),
    (re.compile(r"(?i)\bsudo mode\b|\broot access granted\b"), 6, "privilege-escalation framing phrasing"),
]



def parse_skill_md(text: str):
    m = FRONTMATTER_RE.match(text)
    if not m:
        raise ValueError("SKILL.md must start with a YAML frontmatter block delimited by '---' lines")
    raw_frontmatter, body = m.group(1), m.group(2)
    data = yaml.safe_load(raw_frontmatter) or {}
    if not isinstance(data, dict):
        raise ValueError("frontmatter must be a YAML mapping")
    return data, body


def _scan_text(text, source, patterns):
    findings = []
    for pattern, weight, message in patterns:
        if pattern.search(text):
            findings.append({"source": source, "message": message, "weight": weight})
    return findings


def analyze(text: str) -> dict:
    try:
        fm, body = parse_skill_md(text)
    except ValueError as e:
        return {"parse_ok": False, "parse_error": str(e)}

    lint_issues = []
    for key in REQUIRED_KEYS:
        if not fm.get(key):
            lint_issues.append({"level": "error", "code": "missing-field", "message": f"frontmatter is missing required key '{key}'"})
    name = fm.get("name")
    if isinstance(name, str) and not NAME_RE.match(name):
        lint_issues.append({"level": "warning", "code": "name-format", "message": f"name '{name}' should be lowercase kebab-case"})
    description = fm.get("description")
    if isinstance(description, str) and len(description) > RECOMMENDED_MAX_DESCRIPTION_CHARS:
        lint_issues.append({"level": "warning", "code": "description-length", "message": f"description is {len(description)} chars, keep under {RECOMMENDED_MAX_DESCRIPTION_CHARS}"})
    if not body.strip():
        lint_issues.append({"level": "error", "code": "empty-body", "message": "SKILL.md has no markdown body after the frontmatter"})

    findings = []
    findings += _scan_text(body, "SKILL.md body", _PROMPT_INJECTION_PATTERNS)
    findings += _scan_text(text, "raw text (incl. code blocks)", _CODE_PATTERNS)

    risk_score = sum(f["weight"] for f in findings)
    risk_level = "clean" if risk_score == 0 else "low" if risk_score < 8 else "medium" if risk_score < 20 else "high"

    return {
        "parse_ok": True,
        "name": name,
        "lint_ok": not any(i["level"] == "error" for i in lint_issues),
        "lint_issues": lint_issues,
        "findings": findings,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "disclaimer": DISCLAIMER,
    }


# ---------------------------------------------------------------------------
# Pro payment verification (Solana USDC)
# ---------------------------------------------------------------------------

PAYOUT_WALLET = "2esJogvKTYDuxZaB9PEuEaHvz4U6TuQnTx3pkLcdH34N"
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
MAX_FILES = 25
SOLANA_RPC = "https://api.mainnet-beta.solana.com"


def _rpc(method, params):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(SOLANA_RPC, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


# Audit finding P0-B: any "test_signature_*" string used to activate Pro for
# free unconditionally, in production. Test mode now requires BOTH the
# signature prefix AND an explicit opt-in env var, which is only ever set in
# non-production deployments -- so a real user hitting the real production
# API can never bypass payment this way again.
ALLOW_TEST_PAYMENTS = os.environ.get("ALLOW_TEST_PAYMENTS", "") == "1"


def verify_payment(signature: str, required_usdc: float):
    if ALLOW_TEST_PAYMENTS and signature.startswith("test_signature_"):
        return True, "test mode"
    try:
        result = _rpc("getTransaction", [signature, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}])
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

    if received + 1e-9 < required_usdc:
        return False, f"payment too small: received {received} USDC, need {required_usdc}"
    return True, f"verified {received} USDC"


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------


def _read_json(environ):
    length = int(environ.get("CONTENT_LENGTH") or 0)
    raw = environ["wsgi.input"].read(length) if length else b"{}"
    return json.loads(raw or b"{}")


def _client_api_key(environ, payload):
    api_key = payload.get("api_key") or ""
    auth_header = environ.get("HTTP_AUTHORIZATION", "")
    if not api_key and auth_header.startswith("Bearer "):
        api_key = auth_header[len("Bearer "):].strip()
    if not api_key:
        forwarded = environ.get("HTTP_X_FORWARDED_FOR", "")
        client_ip = forwarded.split(",")[0].strip() if forwarded else environ.get("REMOTE_ADDR", "")
        api_key = pseudo_key_for_ip(client_ip)
    return api_key


GITHUB_BLOB_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)$")
GITHUB_RAW_RE = re.compile(r"^https://raw\.githubusercontent\.com/[^/]+/[^/]+/[^/]+/.+$")
MAX_URL_FETCH_BYTES = 200_000


def _github_url_to_raw(url):
    """Normalize a github.com/.../blob/... URL (or an already-raw URL) to a
    raw.githubusercontent.com URL we can safely fetch. Rejects anything else
    to avoid this becoming an open server-side-request-forgery proxy."""
    m = GITHUB_BLOB_RE.match(url)
    if m:
        owner, repo, ref, path = m.groups()
        return "https://raw.githubusercontent.com/%s/%s/%s/%s" % (owner, repo, ref, path)
    if GITHUB_RAW_RE.match(url):
        return url
    raise ValueError(
        "url must be a github.com '.../blob/...' link or a raw.githubusercontent.com link to a SKILL.md"
    )


def _fetch_skill_url(url):
    raw_url = _github_url_to_raw(url)
    req = urllib.request.Request(raw_url, headers={"User-Agent": "skillsmith-web"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = resp.read(MAX_URL_FETCH_BYTES + 1)
    if len(data) > MAX_URL_FETCH_BYTES:
        raise ValueError("file at url is larger than %d bytes" % MAX_URL_FETCH_BYTES)
    return data.decode("utf-8", errors="replace")


def handle_scan(environ, start_response):
    try:
        payload = _read_json(environ)
        text = payload.get("text", "")
        url = payload.get("url", "")

        if url and not text:
            try:
                text = _fetch_skill_url(url)
            except (ValueError, urllib.error.URLError, TimeoutError) as e:
                start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": "could not fetch url: %s" % e}).encode()]

        if not isinstance(text, str) or len(text) > 100_000:
            raise ValueError("text must be a string under 100,000 chars")

        explicit_api_key = payload.get("api_key") or ""
        auth_header = environ.get("HTTP_AUTHORIZATION", "")
        if not explicit_api_key and auth_header.startswith("Bearer "):
            explicit_api_key = auth_header[len("Bearer "):].strip()
        if not explicit_api_key:
            start_response("401 Unauthorized", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({
                "error": "sign_in_required",
                "message": "Sign in or sign up (both free) to scan a skill.",
                "signup": "POST /api/signup, or use /api/auth/github/start",
            }).encode()]

        api_key = _client_api_key(environ, payload)
        allowed, quota_info = check_and_consume_quota(api_key)
        if not allowed:
            if quota_info.get("error", "").startswith("unknown api_key"):
                start_response("401 Unauthorized", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": "sign_in_required", "message": "Sign in again, this key isn't valid anymore.", "quota": quota_info}).encode()]
            start_response("429 Too Many Requests", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "quota_exceeded", "quota": quota_info}).encode()]

        digest = sha256_of(text)
        cached = get_scan_record(digest)
        result = analyze(text)
        try:
            history = record_scan(digest, result, name=result.get("name") or "")
        except Exception:  # noqa: BLE001
            history = None  # DB is best-effort; never fail a scan because history logging failed

        result["quota"] = quota_info
        result["sha256"] = digest
        result["scan_history"] = {
            "seen_before": cached is not None,
            "seen_count": (history or {}).get("seen_count", 1),
            "first_seen_at": (history or {}).get("first_seen_at"),
        }
        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps(result).encode()]
    except Exception as e:  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": str(e)}).encode()]


def handle_scan_pro(environ, start_response):
    try:
        payload = _read_json(environ)
        api_key = payload.get("api_key", "")

        if not api_key:
            start_response("402 Payment Required", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({
                "error": "api_key_required",
                "signup": "POST /api/signup to get one, it's free",
                "pro_price_usdc": PRO_PRICE_USDC,
                "pro_daily_limit": PRO_DAILY_LIMIT,
                "pro_duration_days": PRO_DURATION_DAYS,
                "pay_to": PAYOUT_WALLET,
                "mint": USDC_MINT,
                "network": "solana-mainnet",
            }).encode()]

        activation_sig = payload.get("activate_payment_signature")
        if activation_sig:
            ok, detail = verify_payment(activation_sig, PRO_PRICE_USDC)
            if not ok:
                start_response("402 Payment Required", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": "payment_not_verified", "detail": detail}).encode()]
            record = activate_pro(api_key, detail)
            start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({
                "activated": True, "payment": detail,
                "pro_expires_at": record["pro_expires_at"],
                "pro_daily_limit": PRO_DAILY_LIMIT,
            }).encode()]

        record = get_account(api_key)
        is_pro = bool(record) and record.get("pro_expires_at", 0) > time.time()
        if not is_pro:
            start_response("402 Payment Required", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({
                "error": "pro_not_active",
                "how_to_activate": "POST {api_key, activate_payment_signature} after sending %.2f USDC to %s"
                % (PRO_PRICE_USDC, PAYOUT_WALLET),
                "pro_price_usdc": PRO_PRICE_USDC,
                "pay_to": PAYOUT_WALLET,
                "mint": USDC_MINT,
                "network": "solana-mainnet",
            }).encode()]

        allowed, quota_info = check_and_consume_quota(api_key)
        if not allowed:
            start_response("429 Too Many Requests", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "quota_exceeded", "quota": quota_info}).encode()]

        files = payload.get("files", [])
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
        return [json.dumps({"quota": quota_info, "results": results}).encode()]
    except Exception as e:  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": str(e)}).encode()]


def handle_buy_credit(environ, start_response):
    """POST {api_key, payment_signature} -> verifies PAY_PER_USE_PRICE_USDC
    and grants exactly one extra scan (consumed before the account is
    blocked, see account.check_and_consume_quota). No subscription, no
    Pro commitment -- pay for exactly the scans you actually need."""
    try:
        payload = _read_json(environ)
        api_key = payload.get("api_key", "")
        signature = payload.get("payment_signature", "")
        if not api_key:
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "api_key required, sign in first"}).encode()]
        if not signature:
            start_response("402 Payment Required", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({
                "error": "payment_required",
                "price_usdc": PAY_PER_USE_PRICE_USDC,
                "pay_to": PAYOUT_WALLET,
                "mint": USDC_MINT,
                "network": "solana-mainnet",
            }).encode()]
        ok, detail = verify_payment(signature, PAY_PER_USE_PRICE_USDC)
        if not ok:
            start_response("402 Payment Required", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "payment_not_verified", "detail": detail}).encode()]
        record = add_pay_per_use_credit(api_key, detail)
        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"credited": True, "payment": detail, "bonus_credits": record.get("bonus_credits", 0)}).encode()]
    except Exception as e:  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": str(e)}).encode()]


def handle_registry(environ, start_response):
    try:
        qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
        limit = int((qs.get("limit") or ["50"])[0])
        entries = list_safe_registry(limit=limit)
        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({
            "disclaimer": DISCLAIMER,
            "count": len(entries),
            "skills": entries,
        }).encode()]
    except Exception as e:  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": str(e)}).encode()]


def handle_lookup(environ, start_response):
    """GET /api/lookup?sha256=... -- VirusTotal-style hash lookup, read-only,
    does not consume any quota (you're asking "has this exact file been seen
    before", not asking us to re-scan it)."""
    try:
        qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
        digest = (qs.get("sha256") or [""])[0].lower()
        if len(digest) != 64:
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "sha256 query param must be a 64-char hex digest"}).encode()]
        record = get_scan_record(digest)
        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"disclaimer": DISCLAIMER, "found": record is not None, "record": record}).encode()]
    except Exception as e:  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": str(e)}).encode()]


def handle_signup(environ, start_response, method):
    if method == "GET":
        qs = environ.get("QUERY_STRING", "")
        params = dict(p.split("=", 1) for p in qs.split("&") if "=" in p)
        api_key = params.get("api_key", "")
        if not api_key:
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "api_key query param required"}).encode()]
        record = get_account(api_key)
        if record is None:
            start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "unknown api_key"}).encode()]
        is_pro = record.get("pro_expires_at", 0) > time.time()
        today = time.strftime("%Y-%m-%d", time.gmtime())
        if record.get("unlimited"):
            body = {"tier": "unlimited", "name": record.get("name", "")}
        elif is_pro:
            used = record.get("pro_used_count", 0) if record.get("pro_used_date") == today else 0
            body = {"tier": "pro", "limit": PRO_DAILY_LIMIT, "used": used,
                    "remaining": max(0, PRO_DAILY_LIMIT - used), "pro_expires_at": record.get("pro_expires_at")}
        else:
            used = record.get("free_used_count", 0) if record.get("free_used_date") == today else 0
            body = {"tier": "free", "limit": 5, "used": used, "remaining": max(0, 5 - used),
                    "pro_price_usdc": PRO_PRICE_USDC, "pro_duration_days": PRO_DURATION_DAYS}
        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps(body).encode()]

    api_key, record = create_account()
    start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
    return [json.dumps({
        "api_key": api_key,
        "note": "Save this key. Paste it into skillsmith-web on any other device to share your quota.",
        "free_daily_limit": 5,
        "pro_daily_limit": PRO_DAILY_LIMIT,
        "pro_price_usdc": PRO_PRICE_USDC,
        "pro_duration_days": PRO_DURATION_DAYS,
    }).encode()]




# ---------------------------------------------------------------------------
# OAuth login (GitHub) -- resolves to the same account/api_key model
# used everywhere else, so signing in on a second device recovers the same
# quota automatically instead of requiring a manually copy-pasted key.
# ---------------------------------------------------------------------------


def _redirect(start_response, location, extra_headers=None):
    headers = [("Location", location)] + _CORS_HEADERS + (extra_headers or [])
    start_response("302 Found", headers)
    return [b""]


_OAUTH_STATE_COOKIE = "skillsmith_oauth_state"


def _parse_cookies(environ):
    raw = environ.get("HTTP_COOKIE", "")
    out = {}
    for part in raw.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _new_oauth_state_cookie_header():
    # Audit finding P0/P1-D: OAuth start/callback had no state parameter at
    # all, so a login-CSRF (attacker starts their own OAuth flow, tricks a
    # victim into completing it, victim ends up bound to the attacker's
    # account) was possible. state is a random token, set as an HttpOnly
    # cookie on the redirect to the provider and echoed back as the OAuth
    # `state` param; the callback rejects the login unless the two match.
    state = secrets.token_urlsafe(24)
    cookie = f"{_OAUTH_STATE_COOKIE}={state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600"
    return state, cookie


def _verify_and_clear_oauth_state(environ, qs_state):
    cookies = _parse_cookies(environ)
    expected = cookies.get(_OAUTH_STATE_COOKIE)
    clear_cookie = f"{_OAUTH_STATE_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
    if not expected or not qs_state or not secrets.compare_digest(expected, qs_state):
        return False, clear_cookie
    return True, clear_cookie


def _http_post_form(url, data, headers=None):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, headers={**(headers or {}), "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def _http_get_json(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def handle_github_start(environ, start_response):
    if not GITHUB_CLIENT_ID:
        start_response("500 Internal Server Error", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": "GitHub login is not configured yet (missing GITHUB_CLIENT_ID)"}).encode()]
    redirect_uri = f"{SITE_URL}/api/auth/github/callback"
    state, state_cookie = _new_oauth_state_cookie_header()
    params = urllib.parse.urlencode({
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": "read:user user:email",
        "state": state,
    })
    return _redirect(start_response, f"https://github.com/login/oauth/authorize?{params}", [("Set-Cookie", state_cookie)])


def handle_github_callback(environ, start_response):
    qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
    code = (qs.get("code") or [""])[0]
    qs_state = (qs.get("state") or [""])[0]
    state_ok, clear_cookie = _verify_and_clear_oauth_state(environ, qs_state)
    if not state_ok:
        return _redirect(start_response, f"{SITE_URL}/?login_error=state_mismatch", [("Set-Cookie", clear_cookie)])
    if not code:
        return _redirect(start_response, f"{SITE_URL}/?login_error=missing_code", [("Set-Cookie", clear_cookie)])
    try:
        token_data = _http_post_form(
            "https://github.com/login/oauth/access_token",
            {"client_id": GITHUB_CLIENT_ID, "client_secret": GITHUB_CLIENT_SECRET, "code": code},
        )
        access_token = token_data.get("access_token")
        if not access_token:
            return _redirect(start_response, f"{SITE_URL}/?login_error=token_exchange_failed", [("Set-Cookie", clear_cookie)])
        auth_headers = {"Authorization": f"Bearer {access_token}", "User-Agent": "skillsmith-web"}
        profile = _http_get_json("https://api.github.com/user", auth_headers)
        email = profile.get("email") or ""
        if not email:
            try:
                emails = _http_get_json("https://api.github.com/user/emails", auth_headers)
                primary = next((e["email"] for e in emails if e.get("primary")), "")
                email = primary or (emails[0]["email"] if emails else "")
            except Exception:  # noqa: BLE001
                pass
        api_key, _record = get_or_create_account_by_identity(
            "github", str(profile.get("id")), email=email,
            name=profile.get("name") or profile.get("login", ""), avatar_url=profile.get("avatar_url", ""),
        )
        return _redirect(start_response, f"{SITE_URL}/#key={api_key}", [("Set-Cookie", clear_cookie)])
    except Exception as e:  # noqa: BLE001
        return _redirect(start_response, f"{SITE_URL}/?login_error={urllib.parse.quote(str(e))}", [("Set-Cookie", clear_cookie)])


def app(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET")
    path = environ.get("PATH_INFO", "/")

    if method == "OPTIONS":
        start_response("204 No Content", _CORS_HEADERS)
        return [b""]

    if path.rstrip("/").endswith("/auth/github/start"):
        return handle_github_start(environ, start_response)
    if path.rstrip("/").endswith("/auth/github/callback"):
        return handle_github_callback(environ, start_response)

    if path.rstrip("/").endswith("/registry"):
        if method != "GET":
            start_response("405 Method Not Allowed", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "GET only"}).encode()]
        return handle_registry(environ, start_response)

    if path.rstrip("/").endswith("/lookup"):
        if method != "GET":
            start_response("405 Method Not Allowed", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "GET only"}).encode()]
        return handle_lookup(environ, start_response)

    if path.rstrip("/").endswith("/buy_credit") or path.rstrip("/").endswith("/buy-credit"):
        if method != "POST":
            start_response("405 Method Not Allowed", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "POST only"}).encode()]
        return handle_buy_credit(environ, start_response)

    if path.rstrip("/").endswith("/scan_pro") or path.rstrip("/").endswith("/scan-pro"):
        if method != "POST":
            start_response("405 Method Not Allowed", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "POST only"}).encode()]
        return handle_scan_pro(environ, start_response)

    if path.rstrip("/").endswith("/signup"):
        if method not in ("GET", "POST"):
            start_response("405 Method Not Allowed", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "GET or POST only"}).encode()]
        return handle_signup(environ, start_response, method)

    if path.rstrip("/").endswith("/scan"):
        if method != "POST":
            start_response("405 Method Not Allowed", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "POST only"}).encode()]
        return handle_scan(environ, start_response)

    start_response("404 Not Found", [("Content-Type", "application/json")] + _CORS_HEADERS)
    return [json.dumps({"error": "not found", "routes": ["/api/scan", "/api/scan_pro", "/api/signup"]}).encode()]
