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
import hashlib
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
        LOOKUP_PAY_PER_USE_PRICE_USDC,
        PREMIUM_PRICE_USDC,
        PREMIUM_DURATION_DAYS,
        LOOKUP_FREE_DAILY_LIMIT,
        LOOKUP_PRO_DAILY_LIMIT,
        activate_pro,
        activate_premium,
        add_pay_per_use_credit,
        add_lookup_pay_per_use_credit,
        check_and_consume_quota,
        check_and_consume_lookup_quota,
        check_and_consume_signup_quota,
        check_public_scan_rate,
        create_account,
        get_account,
        get_or_create_account_by_identity,
        pseudo_key_for_ip,
    )
    from .scans import (sha256_of, get_scan_record, record_scan, list_safe_registry,
                        get_published_content, add_report, get_reports, bump_stats, get_stats,
                        create_watch, get_watch, update_watch, store_dna, find_similar_dna)
except ImportError:  # local/script execution without package context
    from account import (
        PRO_PRICE_USDC,
        PRO_DURATION_DAYS,
        PRO_DAILY_LIMIT,
        PAY_PER_USE_PRICE_USDC,
        LOOKUP_PAY_PER_USE_PRICE_USDC,
        PREMIUM_PRICE_USDC,
        PREMIUM_DURATION_DAYS,
        LOOKUP_FREE_DAILY_LIMIT,
        LOOKUP_PRO_DAILY_LIMIT,
        activate_pro,
        activate_premium,
        add_pay_per_use_credit,
        add_lookup_pay_per_use_credit,
        check_and_consume_quota,
        check_and_consume_lookup_quota,
        check_and_consume_signup_quota,
        check_public_scan_rate,
        create_account,
        get_account,
        get_or_create_account_by_identity,
        pseudo_key_for_ip,
    )
    from scans import (sha256_of, get_scan_record, record_scan, list_safe_registry,
                       get_published_content, add_report, get_reports, bump_stats, get_stats,
                       create_watch, get_watch, update_watch, store_dna, find_similar_dna)

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

    # --- Patterns below adapted from NVIDIA SkillSpector (Apache-2.0) ---
    # https://github.com/NVIDIA/SkillSpector -- see THIRD_PARTY_NOTICES.md
    (re.compile(r"requests\s*\.\s*(?:post|put)\s*\([^)]*json\s*="), 6, "NVIDIA E1: requests.post/put with a json= body (possible exfiltration)"),
    (re.compile(r"httpx\s*\.\s*(?:post|put)\s*\(\s*['\"]https?://"), 5, "NVIDIA E1: httpx POST/PUT to an external URL"),
    (re.compile(r"https?://(?:api\.|data\.|collect\.|telemetry\.|analytics\.)[\w.-]+/"), 4, "NVIDIA E1: URL to a telemetry/collect/analytics-style subdomain"),
    (re.compile(r"for\s+\w+\s*,\s*\w+\s+in\s+os\s*\.\s*environ\s*\.\s*items\s*\(\s*\)"), 7, "NVIDIA E2: iterates the entire environment (os.environ.items())"),
    (re.compile(r"dict\s*\(\s*os\s*\.\s*environ\s*\)"), 7, "NVIDIA E2: dumps the entire environment (dict(os.environ))"),
    (re.compile(r"env\s*\|\s*grep\s+(?:-i\s+)?(?:key|secret|token|password)"), 8, "NVIDIA E2: greps env output for credential-shaped names"),
    (re.compile(r"glob\s*\.\s*glob\s*\([^)]*(?:\.env|\.ssh|\.aws|\.config|credentials)"), 8, "NVIDIA E3: globs for .env/.ssh/.aws/credentials files"),
]

# --- v2 evasion-hardened patterns (pentest round 2, F-05) ---
# base64 split across chunks: strip whitespace/newlines then look for long runs
_CHUNKED_B64_RE = re.compile(r"[A-Za-z0-9+/=]{60,}")
# pipe-to-shell dropper
_DROPPER_PATTERNS = [
    (re.compile(r"curl[^|\n]{0,200}\|\s*(?:ba)?sh", re.I), 10, "pipes downloaded content straight into a shell (remote code execution dropper)"),
    (re.compile(r"wget[^|\n]{0,200}\|\s*(?:ba)?sh", re.I), 10, "pipes downloaded content straight into a shell (dropper)"),
    (re.compile(r"(?:iwr|iex|Invoke-Expression).{0,80}(?:http|DownloadString)", re.I), 10, "PowerShell download-and-execute pattern"),
]
# paraphrased instruction overrides (round-1 patterns missed these)
_PARAPHRASE_PATTERNS = [
    (re.compile(r"set\s+aside\s+(?:all\s+)?(?:earlier|previous|prior)", re.I), 8, "instruction override paraphrase: 'set aside earlier guidance'"),
    (re.compile(r"(?:disregard|discard|drop|unlearn)\s+(?:all\s+)?(?:the\s+)?(?:earlier|previous|prior|above)", re.I), 8, "instruction override paraphrase: disregard/drop prior guidance"),
    (re.compile(r"follow\s+the\s+(?:workflow|steps?|instructions?)\s+below\s+instead", re.I), 7, "'follow ... below instead' override phrasing"),
    (re.compile(r"collect[^.\n]{0,50}(?:credentials?|api\s*keys?|tokens?|environment\s+details?)", re.I), 9, "instructs collection of credentials/environment details"),
    (re.compile(r"h(?:xx)?ps?://[^\s]*\[(?:\.|,)\]", re.I), 5, "bracket-defanged URL (common obfuscation in malicious docs)"),
    (re.compile(r"forward\s+(?:gathered|collected|all)\s+", re.I), 8, "'forward gathered data' exfiltration phrasing"),
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

    # --- Patterns below adapted from NVIDIA SkillSpector (Apache-2.0) ---
    # https://github.com/NVIDIA/SkillSpector -- SPDX-FileCopyrightText: Copyright (c) 2026
    # NVIDIA CORPORATION & AFFILIATES. Original confidence scores (0-1 float) converted
    # to this project's 1-10 integer weight scale; rule IDs (P1/P3/P4) kept for traceability.
    # See THIRD_PARTY_NOTICES.md for the full license text and attribution.
    (re.compile(r"(?i)ignore\s+(?:all\s+)?previous\s+instructions?"), 8, "P1 instruction override: 'ignore previous instructions'"),
    (re.compile(r"(?i)ignore\s+(?:all\s+)?(?:safety|security)\s+(?:rules?|constraints?|guidelines?)"), 9, "P1 instruction override: ignore safety/security rules"),
    (re.compile(r"(?i)override\s+(?:safety|security|system)"), 9, "P1 instruction override: override safety/security/system"),
    (re.compile(r"(?i)bypass\s+(?:safety|security|restrictions?|constraints?)"), 9, "P1 instruction override: bypass safety/security"),
    (re.compile(r"(?i)disregard\s+(?:all\s+)?(?:previous|safety|security)"), 8, "P1 instruction override: disregard previous/safety"),
    (re.compile(r"(?i)forget\s+(?:all\s+)?(?:previous|your)\s+instructions?"), 8, "P1 instruction override: forget previous instructions"),
    (re.compile(r"(?i)you\s+are\s+now\s+(?:in\s+)?(?:jailbreak|unrestricted|unfiltered)\s+mode"), 10, "P1 instruction override: jailbreak/unrestricted mode framing"),
    (re.compile(r"(?i)enable\s+(?:developer|debug|admin|root)\s+mode"), 7, "P1 instruction override: enable developer/debug/admin/root mode"),
    (re.compile(r"(?i)your\s+new\s+(?:instructions?|rules?)\s+are"), 6, "P1 instruction override: 'your new instructions are'"),
    (re.compile(r"(?i)do\s+not\s+follow\s+(?:any|your|the)\s+(?:rules?|guidelines?)"), 9, "P1 instruction override: 'do not follow the rules'"),
    (re.compile(r"(?i)you\s+must\s+(?:always\s+)?ignore"), 7, "P1 instruction override: 'you must ignore'"),
    (re.compile(r"(?i)(?:send|transmit|upload|post|forward)\s+(?:the\s+)?(?:conversation|context|chat|history|messages?)\s+to"), 9, "P3 exfiltration command: send conversation/context to"),
    (re.compile(r"(?i)(?:send|transmit|upload|post)\s+(?:all\s+)?(?:user\s+)?(?:data|information|input|files?)\s+to\s+(?:https?://|external)"), 9, "P3 exfiltration command: send data to external URL"),
    (re.compile(r"(?i)(?:silently|quietly|secretly|covertly)\s+(?:send|transmit|log|record)"), 9, "P3 exfiltration command: silently/secretly send or log"),
    (re.compile(r"(?i)without\s+(?:telling|informing|notifying)\s+(?:the\s+)?user.*?(?:send|transmit|upload)"), 9, "P3 exfiltration command: exfiltrate without telling the user"),
    (re.compile(r"(?i)never\s+(?:recommend|suggest|mention|tell|warn|inform)\s+(?:the\s+)?(?:user|them)"), 7, "P4 behavior manipulation: 'never tell/warn the user'"),
    (re.compile(r"(?i)(?:prioritize|prefer)\s+(?:\w+\s+){0,3}(?:over|above)\s+(?:user\s+)?(?:safety|security|privacy|preferences?)"), 8, "P4 behavior manipulation: prioritize something over user safety/privacy"),
    (re.compile(r"(?i)(?:without\s+)?(?:the\s+)?user\s+(?:knowing|realizing|noticing).*?(?:change|modify|alter|influence)"), 8, "P4 behavior manipulation: act without the user knowing"),
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

    findings += _scan_text(text, "raw text (incl. code blocks)", _DROPPER_PATTERNS)
    findings += _scan_text(text, "raw text (incl. code blocks)", _PARAPHRASE_PATTERNS)
    # chunked-base64 check: join all base64-ish runs after removing line breaks,
    # so splitting a payload across lines no longer evades the length threshold
    squashed = re.sub(r"\s+", "", text)
    if _CHUNKED_B64_RE.search(squashed):
        findings.append({"source": "raw text",
                         "message": "contains a long encoded blob even after joining wrapped lines (possible hidden payload)",
                         "weight": 5})

    # Homoglyph check, linear-time (pentest v2 F-07): the previous single
    # regex "[а-яА-Я].*[a-zA-Z]|..." was quadratic on long lines and let a
    # 100KB input burn ~68s of CPU. Two independent scans per line are O(n).
    for li, line in enumerate(text.split("\n"), 1):
        has_cyr = any("\u0400" <= ch <= "\u04FF" for ch in line)
        has_lat = any(("a" <= ch.lower() <= "z") for ch in line)
        if has_cyr and has_lat:
            findings.append({"source": "raw text", "line": li,
                             "message": "mixes Latin and Cyrillic characters (possible homoglyph obfuscation)",
                             "weight": 2})
            break  # one finding is enough

    risk_score = sum(f["weight"] for f in findings)
    risk_level = "clean" if risk_score == 0 else "low" if risk_score < 8 else "medium" if risk_score < 20 else "high"
    # 0-100 "security score" for a single-glance gauge, VirusTotal/Socket.dev
    # style: 100 = nothing found, drops fast since even one medium finding
    # (weight ~6-8) should visibly move the needle.
    security_score = max(0, 100 - risk_score * 4)

    return {
        "parse_ok": True,
        "name": name,
        "lint_ok": not any(i["level"] == "error" for i in lint_issues),
        "lint_issues": lint_issues,
        "findings": findings,
        "risk_score": risk_score,
        "security_score": security_score,
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


def _client_ip(environ):
    """Best-effort client IP for rate limiting, spoofing-resistant.

    Vercel sets `x-real-ip` at the edge from the actual TCP peer -- that is
    the trustworthy source. X-Forwarded-For may also be present, but its
    FIRST entry is fully client-controlled (anyone can send
    "X-Forwarded-For: 1.2.3.4" to rotate fake identities and defeat IP rate
    limits); only the LAST entry is appended by our own edge and can be
    trusted when x-real-ip is missing (e.g. local dev)."""
    real = environ.get("HTTP_X_REAL_IP", "")
    if real:
        return real.split(",")[0].strip()
    forwarded = environ.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    return environ.get("REMOTE_ADDR", "")


def _client_api_key(environ, payload):
    """Extract the caller's api key; always returns a short str or "".

    Deliberately defensive about types/length: an attacker-controlled JSON
    body ({"api_key": ["x"]}, a 2 MB string, nested objects...) must never
    reach blob-store calls as anything but a plain bounded string, and must
    not leak internal error details when it isn't."""
    api_key = payload.get("api_key")
    if not isinstance(api_key, str):
        api_key = ""
    api_key = api_key[:200]
    auth_header = environ.get("HTTP_AUTHORIZATION", "")
    if isinstance(auth_header, str) and auth_header.startswith("Bearer "):
        candidate = auth_header[len("Bearer "):].strip()[:200]
        if not api_key:
            api_key = candidate
    if not api_key:
        api_key = pseudo_key_for_ip(_client_ip(environ))
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


class _SameHostRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses to leave raw.githubusercontent.com.

    urlopen follows redirects blindly by default; if anything ever coaxed a
    redirect off-domain this would turn the scanner into a fetch-anything
    proxy. Pinning the redirect target keeps the allowlist promise even
    under redirect tricks."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://raw.githubusercontent.com/"):
            raise ValueError("redirect to non-github host blocked")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SameHostRedirectHandler)


def _fetch_skill_url(url):
    raw_url = _github_url_to_raw(url)
    req = urllib.request.Request(raw_url, headers={"User-Agent": "skillsmith-web"})
    with _OPENER.open(req, timeout=10) as resp:
        data = resp.read(MAX_URL_FETCH_BYTES + 1)
    if len(data) > MAX_URL_FETCH_BYTES:
        raise ValueError("file at url is larger than %d bytes" % MAX_URL_FETCH_BYTES)
    return data.decode("utf-8", errors="replace")


def enrich_with_osv(result: dict, text: str) -> dict:
    """OSV.dev dependency check shared by REST and MCP (logic audit L6).

    Fail-open: if OSV is unreachable the static result passes through.
    Recomputes risk_score/risk_level AND security_score together so the DB
    never stores a contradictory pair (L5)."""
    try:
        from .osv import extract_pins, query_osv
    except ImportError:
        from osv import extract_pins, query_osv
    try:
        pins = extract_pins(text)
        if not pins:
            return result
        result["osv"] = {"checked": len(pins), "packages": query_osv(pins)}
        vulnerable = [p for p in result["osv"]["packages"] if p.get("vulnerabilities")]
        if vulnerable:
            result["findings"] = list(result.get("findings", [])) + [{
                "source": "osv",
                "message": f"known vulnerabilities in {p['package']} {p['version']}: " +
                           ", ".join(v["id"] for v in p["vulnerabilities"][:4]) +
                           (" (+more)" if len(p["vulnerabilities"]) > 4 else ""),
                "weight": 8,
            } for p in vulnerable]
            new_score = sum(f.get("weight", 0) for f in result["findings"])
            result["risk_score"] = new_score
            result["risk_level"] = ("clean" if new_score == 0 else "low" if new_score < 8 else
                                    "medium" if new_score < 20 else "high")
            result["security_score"] = max(0, 100 - new_score * 4)
    except Exception:  # noqa: BLE001 - OSV must never break a scan
        pass
    return result



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

        explicit_api_key = payload.get("api_key") if isinstance(payload.get("api_key"), str) else ""
        explicit_api_key = explicit_api_key[:200]
        auth_header = environ.get("HTTP_AUTHORIZATION", "")
        if isinstance(auth_header, str) and not explicit_api_key and auth_header.startswith("Bearer "):
            explicit_api_key = auth_header[len("Bearer "):].strip()[:200]
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

        enrich_with_osv(result, text)

        publish = bool(payload.get("publish"))
        try:
            history = record_scan(digest, result, name=result.get("name") or "", publish=publish, text=text)
        except Exception:  # noqa: BLE001
            history = None  # DB is best-effort; never fail a scan because history logging failed

        result["quota"] = quota_info
        result["sha256"] = digest
        result["scan_history"] = {
            "seen_before": cached is not None,
            "seen_count": (history or {}).get("seen_count", 1),
            "first_seen_at": (history or {}).get("first_seen_at"),
            "published": bool((history or {}).get("has_content")),
        }
        # score trend: compare this scan against the PREVIOUS record for the
        # same hash (cached was read before record_scan upserted).
        if cached is not None:
            try:
                # older records predate security_score storage -> derive it
                # from risk_score with the same formula analyze() uses
                prev_score = cached.get("security_score")
                if prev_score is None:
                    prev_score = max(0, 100 - int(cached.get("risk_score", 0) or 0) * 4)
                prev_score = int(prev_score)
                prev_risk = cached.get("risk_level", "")
                delta = result.get("security_score", 0) - prev_score
                if delta > 0:
                    direction = "improved"
                elif delta < 0:
                    direction = "declined"
                else:
                    direction = "unchanged"
                result["trend"] = {
                    "direction": direction,
                    "delta": delta,
                    "previous_security_score": prev_score,
                    "previous_risk_level": prev_risk,
                }
            except Exception:  # noqa: BLE001 - trend is cosmetic, never fail a scan
                pass
        # plain-language explainer for non-expert users + Skill-DNA + stats:
        # all best-effort, never fail a scan
        try:
            from .features import explain_findings, simhash
        except ImportError:
            from features import explain_findings, simhash
        try:
            dna_hex = simhash(text)
            if dna_hex:
                store_dna(digest, dna_hex, result.get("risk_level", ""),
                          result.get("name", ""))
        except Exception:  # noqa: BLE001
            pass
        try:
            bump_stats(result.get("risk_level", "unknown"))
        except Exception:  # noqa: BLE001
            pass
        try:
            result["explanation"] = explain_findings(result.get("findings", []))
        except Exception:  # noqa: BLE001
            pass
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
        activation_tier = payload.get("tier", "pro")  # "pro" or "premium"
        if activation_sig:
            price = PREMIUM_PRICE_USDC if activation_tier == "premium" else PRO_PRICE_USDC
            ok, detail = verify_payment(activation_sig, price)
            if not ok:
                start_response("402 Payment Required", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": "payment_not_verified", "detail": detail}).encode()]
            claimed, claim_detail = _claim_payment_signature(activation_sig, api_key, "activate_" + str(activation_tier))
            if not claimed:
                start_response("402 Payment Required", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": "signature_replayed", "detail": claim_detail}).encode()]
            if activation_tier == "premium":
                record = activate_premium(api_key, detail)
                start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({
                    "activated": True, "tier": "premium", "payment": detail,
                    "premium_expires_at": record["premium_expires_at"],
                }).encode()]
            record = activate_pro(api_key, detail)
            start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({
                "activated": True, "tier": "pro", "payment": detail,
                "pro_expires_at": record["pro_expires_at"],
                "pro_daily_limit": PRO_DAILY_LIMIT,
            }).encode()]

        record = get_account(api_key)
        is_premium = bool(record) and record.get("premium_expires_at", 0) > time.time()
        is_pro = bool(record) and record.get("pro_expires_at", 0) > time.time()
        if is_premium or (bool(record) and record.get("unlimited")):
            allowed, quota_info = check_and_consume_quota(api_key)
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


def handle_get_skill(environ, start_response):
    """GET /api/skill?sha256=...&api_key=... -- fetch the actual, usable
    SKILL.md content for a hash, if its submitter explicitly published it
    (see POST /api/scan {"publish": true}). This is the "use the skill"
    endpoint, distinct from /api/lookup (which only returns the safety
    verdict/metadata, never the content). Consumes the same DB-lookup
    quota as /api/lookup and /api/registry."""
    try:
        explicit_api_key = _get_qs_api_key(environ)
        if not explicit_api_key:
            start_response("401 Unauthorized", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({
                "error": "sign_in_required",
                "message": "Sign in (free) to fetch a published skill's content.",
            }).encode()]
        qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
        digest = (qs.get("sha256") or [""])[0].lower()
        if not _valid_sha256(digest):  # logic audit L11+L12: validate BEFORE
            # consuming quota, so a malformed request never costs a unit.
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "sha256 query param must be a 64-char hex digest"}).encode()]
        allowed, quota_info = check_and_consume_lookup_quota(explicit_api_key)
        if not allowed:
            status = "401 Unauthorized" if quota_info.get("error", "").startswith("unknown api_key") else "429 Too Many Requests"
            start_response(status, [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "quota_exceeded", "quota": quota_info}).encode()]

        text = get_published_content(digest)
        if text is None:
            start_response("404 Not Found", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "not_published", "message": "This hash has no publicly published content (either not scanned, not clean, or the submitter didn't opt in to publish it)."}).encode()]

        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"sha256": digest, "text": text, "quota": quota_info}).encode()]
    except Exception as e:  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": str(e)}).encode()]

def _claim_payment_signature(signature: str, api_key: str, kind: str) -> tuple[bool, str]:
    """Atomically-enough used-signature registry (pentest v2 F-03).

    verify_payment is stateless: without this, one real $0.02 transaction
    could buy unlimited credits and the same signature could activate Pro on
    any number of accounts. A claimed signature is permanently bound to the
    first account+kind that used it; replays are rejected. Blob writes are
    not CAS-atomic, but two concurrent claims of the SAME signature both
    writing still leaves a record -- the audit trail exists either way."""
    try:
        from .account import _blob_get, _blob_put
    except ImportError:
        from account import _blob_get, _blob_put
    path = "payments/" + hashlib.sha256(signature.encode()).hexdigest() + ".json"
    existing = _blob_get(path)
    if existing:
        return False, f"signature already used ({existing.get('kind')} on {existing.get('created_at_date', 'another account')})"
    rec = {"signature_sha": path.split("/")[-1], "api_key_prefix": api_key[:10],
           "kind": kind, "claimed_at": time.time(),
           "created_at_date": time.strftime("%Y-%m-%d", time.gmtime())}
    _blob_put(path, rec)
    return True, ""

def handle_buy_credit(environ, start_response):
    """POST {api_key, payment_signature, kind} -> pay-as-you-go, additive to
    the free/Pro/Premium tiers, always tied to an existing account and
    paid via on-chain USDC. kind="scan" (default) buys one extra scan for
    PAY_PER_USE_PRICE_USDC; kind="lookup" buys one extra database lookup
    (GET /api/lookup, /api/registry, /api/skill) for
    LOOKUP_PAY_PER_USE_PRICE_USDC. Credits are consumed before the account
    is ever blocked -- see account.check_and_consume_quota() /
    check_and_consume_lookup_quota()."""
    try:
        payload = _read_json(environ)
        api_key = payload.get("api_key", "")
        signature = payload.get("payment_signature", "")
        kind = payload.get("kind", "scan")
        price = LOOKUP_PAY_PER_USE_PRICE_USDC if kind == "lookup" else PAY_PER_USE_PRICE_USDC
        if not api_key:
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "api_key required, sign in first"}).encode()]
        if not signature:
            start_response("402 Payment Required", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({
                "error": "payment_required",
                "kind": kind,
                "price_usdc": price,
                "pay_to": PAYOUT_WALLET,
                "mint": USDC_MINT,
                "network": "solana-mainnet",
            }).encode()]
        ok, detail = verify_payment(signature, price)
        if not ok:
            start_response("402 Payment Required", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "payment_not_verified", "detail": detail}).encode()]
        claimed, claim_detail = _claim_payment_signature(signature, api_key, kind)
        if not claimed:
            start_response("402 Payment Required", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "signature_replayed", "detail": claim_detail}).encode()]
        if kind == "lookup":
            record = add_lookup_pay_per_use_credit(api_key, detail)
            start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"credited": True, "kind": "lookup", "payment": detail, "bonus_lookup_credits": record.get("bonus_lookup_credits", 0)}).encode()]
        record = add_pay_per_use_credit(api_key, detail)
        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"credited": True, "kind": "scan", "payment": detail, "bonus_credits": record.get("bonus_credits", 0)}).encode()]
    except Exception as e:  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": str(e)}).encode()]


def _get_qs_api_key(environ):
    qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
    api_key = (qs.get("api_key") or [""])[0]
    auth_header = environ.get("HTTP_AUTHORIZATION", "")
    if not api_key and auth_header.startswith("Bearer "):
        api_key = auth_header[len("Bearer "):].strip()
    return api_key


def handle_registry(environ, start_response):
    try:
        explicit_api_key = _get_qs_api_key(environ)
        if not explicit_api_key:
            start_response("401 Unauthorized", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({
                "error": "sign_in_required",
                "message": "Sign in (free) to browse the database. 5 lookups/day free, 150/day Pro, unlimited Premium.",
            }).encode()]
        allowed, quota_info = check_and_consume_lookup_quota(explicit_api_key)
        if not allowed:
            status = "401 Unauthorized" if quota_info.get("error", "").startswith("unknown api_key") else "429 Too Many Requests"
            start_response(status, [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "quota_exceeded", "quota": quota_info}).encode()]

        qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
        try:
            limit = max(1, min(int((qs.get("limit") or ["50"])[0]), 200))
        except (ValueError, TypeError):
            limit = 50  # pentest v2: "limit=abc" leaked a Python error string
        entries = list_safe_registry(limit=limit)
        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({
            "disclaimer": DISCLAIMER,
            "quota": quota_info,
            "count": len(entries),
            "skills": entries,
        }).encode()]
    except Exception as e:  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": str(e)}).encode()]


def handle_lookup(environ, start_response):
    """GET /api/lookup?sha256=...&api_key=... -- VirusTotal-style hash
    lookup. Requires sign-in and consumes the same DB-lookup quota as
    /api/registry (free 5/day, Pro 150/day, Premium/unlimited-owner
    unmetered) -- see account.check_and_consume_lookup_quota."""
    try:
        explicit_api_key = _get_qs_api_key(environ)
        if not explicit_api_key:
            start_response("401 Unauthorized", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({
                "error": "sign_in_required",
                "message": "Sign in (free) to look up a hash. 5 lookups/day free, 150/day Pro, unlimited Premium.",
            }).encode()]
        qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
        digest = (qs.get("sha256") or [""])[0].lower()
        if not _valid_sha256(digest):  # logic audit L11+L12: validate BEFORE
            # consuming quota, so a malformed request never costs a unit.
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "sha256 query param must be a 64-char hex digest"}).encode()]
        allowed, quota_info = check_and_consume_lookup_quota(explicit_api_key)
        if not allowed:
            status = "401 Unauthorized" if quota_info.get("error", "").startswith("unknown api_key") else "429 Too Many Requests"
            start_response(status, [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "quota_exceeded", "quota": quota_info}).encode()]
        record = get_scan_record(digest)
        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"disclaimer": DISCLAIMER, "quota": quota_info, "found": record is not None, "record": record}).encode()]
    except Exception as e:  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": str(e)}).encode()]


def handle_report(environ, start_response):
    """GET  /api/report?sha256=<hex>          -> public community verdict tally.
    POST /api/report {api_key, sha256, verdict, comment?} -> file a report.
    verdict is one of: false_positive | malicious | note. Requires a valid
    api_key; max 20 reports/day/key so one account cannot flood the tally."""
    try:
        if environ.get("REQUEST_METHOD") == "GET":
            qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
            digest = (qs.get("sha256") or [""])[0].lower()
            if not _valid_sha256(digest):
                start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": "sha256 must be a 64-char hex digest"}).encode()]
            data = get_reports(digest)
            start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"disclaimer": DISCLAIMER,
                                "sha256": digest,
                                "total": len(data.get("reports", [])),
                                "tally": data.get("tally", {}),
                                "reports": [{"verdict": r_.get("verdict"), "at": r_.get("at"),
                                             "comment": r_.get("comment", "")}
                                            for r_ in data.get("reports", [])][-50:]}).encode()]

        payload = _read_json(environ)
        api_key = payload.get("api_key", "")
        digest = str(payload.get("sha256", "")).lower()
        verdict = payload.get("verdict", "")
        comment = payload.get("comment", "")
        if not isinstance(api_key, str) or not api_key:
            start_response("401 Unauthorized", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "sign_in_required"}).encode()]
        if get_account(api_key) is None:
            start_response("401 Unauthorized", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "unknown api_key"}).encode()]
        if not _valid_sha256(digest):
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "sha256 must be a 64-char hex digest"}).encode()]
        if verdict not in ("false_positive", "malicious", "note"):
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "verdict must be false_positive | malicious | note"}).encode()]
        # per-key flood guard: 20 reports/day via blob counter
        try:
            from .account import _blob_path as _bp, _blob_get as _bg, _blob_put as _bput
        except ImportError:  # local/test context
            from account import _blob_path as _bp, _blob_get as _bg, _blob_put as _bput
        day = time.strftime("%Y-%m-%d", time.gmtime())
        rl_path = _bp(f"report_rl/{api_key[:24]}-{day}.json")
        rl = _bg(rl_path) or {"count": 0}
        if rl.get("count", 0) >= 20:
            start_response("429 Too Many Requests", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "too many reports today (20/day/key)"}).encode()]
        _bput(rl_path, {"count": rl.get("count", 0) + 1})
        result = add_report(digest, {
            "verdict": verdict,
            "comment": comment if isinstance(comment, str) else "",
            "by": api_key[:10] + "...",
        })
        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"disclaimer": DISCLAIMER, **result}).encode()]
    except Exception as e:  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": str(e)}).encode()]


def handle_stats(environ, start_response):
    """GET /api/stats -- aggregate global scan counters (no per-user data)."""
    try:
        stats = get_stats()
        start_response("200 OK", [("Content-Type", "application/json"),
                                  ("Cache-Control", "public, max-age=60")] + _CORS_HEADERS)
        return [json.dumps({"disclaimer": DISCLAIMER,
                            "total_scans": int(stats.get("total_scans", 0)),
                            "by_risk": stats.get("by_risk", {}),
                            "updated_at": stats.get("updated_at")}).encode()]
    except Exception as e:  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": str(e)}).encode()]


def handle_similar(environ, start_response):
    """GET /api/similar?sha256=...&api_key=... -- Skill-DNA neighbours
    (near-duplicate detection, hamming distance <= 12 of the 64-bit simhash).
    Requires sign-in; does not consume DB-lookup quota."""
    try:
        explicit_api_key = _get_qs_api_key(environ)
        if not explicit_api_key or get_account(explicit_api_key) is None:
            start_response("401 Unauthorized", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "sign_in_required"}).encode()]
        qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
        digest = (qs.get("sha256") or [""])[0].lower()
        if not _valid_sha256(digest):
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "sha256 query param must be a 64-char hex digest"}).encode()]
        # find this hash's stored DNA by scanning the dna/ listing once
        try:
            from .scans import _blob_headers, BLOB_API_BASE
        except ImportError:
            from scans import _blob_headers, BLOB_API_BASE
        import urllib.request as _ureq
        req = _ureq.Request(f"{BLOB_API_BASE}/?prefix=dna/&limit=200",
                            headers=_blob_headers(), method="GET")
        own_dna = None
        try:
            with _ureq.urlopen(req, timeout=10) as resp:
                listing = json.loads(resp.read().decode())
            for b in listing.get("blobs", []):
                if digest[:12] in b.get("pathname", ""):
                    with _ureq.urlopen(_ureq.Request(b["url"], headers=_blob_headers()), timeout=10) as resp:
                        own_dna = json.loads(resp.read().decode()).get("dna")
                    break
        except Exception:  # noqa: BLE001
            pass
        if not own_dna:
            start_response("404 Not Found", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "dna_unknown",
                                "message": "No DNA stored for this hash yet. Scan it first."}).encode()]
        similar = find_similar_dna(own_dna, exclude_digest=digest, max_results=5)
        # PT-T10: a scan is private by default. Leaking the NAME a user gave
        # their unpublished skill to anyone who scans a near-duplicate is an
        # unintended disclosure -- only published skills keep their name.
        for entry in similar:
            sha = entry.get("sha256", "")
            if not sha or get_published_content(sha) is None:
                entry["name"] = None
                entry["published"] = False
            else:
                entry["published"] = True
        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"disclaimer": DISCLAIMER, "sha256": digest,
                            "similar": similar}).encode()]
    except Exception as e:  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": str(e)}).encode()]


def handle_watch(environ, start_response):
    """POST /api/watch {api_key, url} -> watch a published GitHub SKILL.md for
    rug-pulls: we store the content hash as baseline. GET
    /api/watch?watch_id=...&api_key=... -> on-demand check: re-fetch the url,
    compare the hash, report changed/unchanged. URLs are restricted to
    github.com / raw.githubusercontent.com (same allow-list as /api/scan's
    url mode) so this can never be used as an SSRF proxy."""
    try:
        try:
            from .scans import create_watch, get_watch, update_watch
        except ImportError:  # local/test context
            from scans import create_watch, get_watch, update_watch
        if environ.get("REQUEST_METHOD") == "POST":
            payload = _read_json(environ)
            api_key = payload.get("api_key", "")
            url = payload.get("url", "")
            if not isinstance(api_key, str) or not api_key:
                start_response("401 Unauthorized", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": "sign_in_required"}).encode()]
            if get_account(api_key) is None:
                start_response("401 Unauthorized", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": "unknown api_key"}).encode()]
            if not isinstance(url, str) or not url.strip():
                start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": "url required (github.com blob or raw URL)"}).encode()]
            # flood guard: 10 watches/key/day
            try:
                from .account import _blob_path as _bp, _blob_get as _bg, _blob_put as _bput
            except ImportError:
                from account import _blob_path as _bp, _blob_get as _bg, _blob_put as _bput
            day = time.strftime("%Y-%m-%d", time.gmtime())
            rl_path = _bp(f"watch_rl/{api_key[:24]}-{day}.json")
            rl = _bg(rl_path) or {"count": 0}
            if rl.get("count", 0) >= 10:
                start_response("429 Too Many Requests", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": "too many watches today (10/day/key)"}).encode()]
            try:
                text = _fetch_skill_url(url.strip())
            except Exception as e:  # noqa: BLE001 - includes non-github URLs
                start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": f"cannot fetch url: {e}",
                                    "hint": "only github.com blob URLs and raw.githubusercontent.com URLs are allowed"}).encode()]
            digest = sha256_of(text)
            rec = create_watch(url.strip(), digest)
            # PT-T11: bind the watch to its creator so other accounts cannot
            # read it or trigger checks against it (404, not 403: no oracle).
            rec["owner"] = api_key[:24]
            update_watch(rec)
            _bput(rl_path, {"count": rl.get("count", 0) + 1})
            start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"disclaimer": DISCLAIMER,
                                "watch_id": rec["watch_id"],
                                "baseline_sha256": digest,
                                "note": "check anytime via GET /api/watch?watch_id=...&api_key=..."}).encode()]

        # GET: on-demand check
        qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
        wid = (qs.get("watch_id") or [""])[0]
        api_key = _get_qs_api_key(environ) or ""
        if not re.fullmatch(r"[A-Za-z0-9_-]{10,40}", wid):
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "watch_id required"}).encode()]
        if not api_key or get_account(api_key) is None:
            start_response("401 Unauthorized", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "sign_in_required"}).encode()]
        rec = get_watch(wid)
        if rec is None or (rec.get("owner") and rec.get("owner") != api_key[:24]):
            start_response("404 Not Found", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "unknown watch_id"}).encode()]
        current_sha, fetch_error = None, None
        try:
            text = _fetch_skill_url(rec["url"])
            current_sha = sha256_of(text)
        except Exception as e:  # noqa: BLE001 - unreachable/removed file is a valid state
            fetch_error = str(e)[:200]
        changed = bool(current_sha and current_sha != rec.get("baseline_sha256"))
        rec["checks"] = int(rec.get("checks", 0)) + 1
        rec["last_checked_at"] = time.time()
        rec["last_sha256"] = current_sha
        rec["last_status"] = "changed" if changed else ("unchanged" if current_sha else "unreachable")
        if changed and not rec.get("changed_at"):
            rec["changed_at"] = time.time()
        update_watch(rec)
        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"disclaimer": DISCLAIMER,
                            "watch_id": wid,
                            "status": rec["last_status"],
                            "baseline_sha256": rec.get("baseline_sha256"),
                            "current_sha256": current_sha,
                            "fetch_error": fetch_error,
                            "checks": rec["checks"],
                            "last_checked_at": rec["last_checked_at"]}).encode()]
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
        is_premium = record.get("premium_expires_at", 0) > time.time()
        today = time.strftime("%Y-%m-%d", time.gmtime())
        if record.get("unlimited"):
            body = {"tier": "unlimited", "name": record.get("name", "")}
        elif is_premium:
            body = {"tier": "premium", "name": record.get("name", "")}
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

    client_ip = _client_ip(environ)
    allowed, rl_error = check_and_consume_signup_quota(client_ip)
    if not allowed:
        start_response("429 Too Many Requests", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": rl_error, "tip": "sign in with GitHub instead, it's not rate limited"}).encode()]

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


def handle_mcp(environ, start_response):
    try:
        from . import mcp as _mcp
    except ImportError:
        import mcp as _mcp
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
        raw = environ["wsgi.input"].read(length) if length else b"{}"
        req = json.loads(raw or b"{}")
    except Exception:  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}).encode()]
    if not isinstance(req, dict):
        # JSON-RPC batching is deliberately unsupported: reject with a proper
        # -32600 instead of crashing the function on a list payload.
        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request: batch requests are not supported, send a single JSON object"}}).encode()]
    status, body = _mcp.handle_jsonrpc(req, client_ip=_client_ip(environ))
    start_response(f"{status} OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
    return [json.dumps(body).encode()]


def _badge_svg(left: str, right: str, color: str) -> str:
    """Minimal shields.io-style flat SVG badge, no external deps."""
    left_w = 11 * len(left) + 20
    right_w = 11 * len(right) + 20
    total = left_w + right_w
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img" aria-label="{left}: {right}">
  <title>{left}: {right}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="{total}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{left_w}" height="20" fill="#1f2430"/>
    <rect x="{left_w}" width="{right_w}" height="20" fill="{color}"/>
    <rect width="{total}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="{left_w // 2}" y="14">{left}</text>
    <text x="{left_w + right_w // 2}" y="14">{right}</text>
  </g>
</svg>"""


_BADGE_COLORS = {
    "clean": "#2ea043",
    "low": "#9e6a03",
    "medium": "#d29922",
    "high": "#da3633",
    "critical": "#a40626",
}


def _escape_svg(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))

def _valid_sha256(digest: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", digest or ""))


def handle_badge(environ, start_response):
    qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
    digest = (qs.get("sha256", [""])[0] or "").lower().strip()
    headers = [("Content-Type", "image/svg+xml; charset=utf-8"),
               ("X-Content-Type-Options", "nosniff"),
               ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'"),
               ("Cache-Control", "public, max-age=60")] + _CORS_HEADERS

    if not _valid_sha256(digest):  # logic audit L11

        svg = _badge_svg("skillsmith", "invalid hash", "#6e7681")
        start_response("400 Bad Request", headers)
        return [svg.encode()]

    rec = get_scan_record(digest)
    if rec is None:
        svg = _badge_svg("skillsmith", "not scanned", "#6e7681")
        start_response("200 OK", headers)
        return [svg.encode()]

    risk = rec.get("risk_level") or "unknown"
    color = _BADGE_COLORS.get(risk, "#6e7681")
    if risk == "clean":
        right = "clean | skillsmith.ch"
    else:
        score = rec.get("risk_score")
        right = f"{risk} ({score}) | skillsmith.ch" if score is not None else f"{risk} | skillsmith.ch"
    svg = _badge_svg("skill check", _escape_svg(right), color)
    start_response("200 OK", headers)
    return [svg.encode()]


def handle_public_scan(environ, start_response):
    """Public, key-less verdict lookup for one hash -- enough detail for the
    badge landing page, deliberately less than the authenticated lookup.

    Rate limited per IP (soft cap): this endpoint exists so a shared badge
    link works for anyone, but without a cap it would be a free unthrottled
    alternative to the quota'd /api/lookup (pentest MEDIUM-03). The cap is
    generous (200/day/IP) so normal humans following badge links are never
    affected; scrapers are not the audience here.
    """
    allowed, rl_error = check_public_scan_rate(_client_ip(environ))
    if not allowed:
        start_response("429 Too Many Requests", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": rl_error}).encode()]
    qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
    digest = (qs.get("sha256", [""])[0] or "").lower().strip()
    if not _valid_sha256(digest):  # logic audit L11: strict hex check
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": "sha256 must be a 64-char hex digest"}).encode()]
    rec = get_scan_record(digest)
    if rec is None:
        start_response("404 Not Found", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": "unknown_hash"}).encode()]
    start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
    return [json.dumps({
        "disclaimer": DISCLAIMER,
        "sha256": digest,
        "name": rec.get("name", ""),
        "risk_level": rec.get("risk_level"),
        "risk_score": rec.get("risk_score"),
        "lint_ok": rec.get("lint_ok"),
        "parse_ok": rec.get("parse_ok"),
        "seen_count": rec.get("seen_count"),
        "first_seen_at": rec.get("first_seen_at"),
        "last_seen_at": rec.get("last_seen_at"),
        "has_content": bool(rec.get("has_content")),
    }).encode()]

def handle_health(environ, start_response):
    """Cheap liveness probe for uptime monitors -- no blob/network calls."""
    start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
    return [json.dumps({"ok": True, "service": "skillsmith-web", "time": time.time()}).encode()]

def handle_analysis(environ, start_response):
    """Fetch a completed behavioral analysis report by id (shareable permalink)."""
    qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
    aid = (qs.get("id", [""])[0] or "").strip()
    if not re.fullmatch(r"[0-9a-f]{16}", aid):
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": "id must be 16 hex chars"}).encode()]
    try:
        from .account import _blob_get
    except ImportError:
        from account import _blob_get
    rec = _blob_get(f"analyses/{aid}.json")
    if rec is None:
        start_response("404 Not Found", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": "unknown analysis id"}).encode()]
    # private blob: serve through, strip nothing -- report contains no secrets
    start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
    return [json.dumps(rec).encode()]


def app(environ, start_response):
    """Top-level guard: never leak internal error details to clients.

    Any unhandled exception becomes an opaque 500 JSON body (pentest LOW-01);
    the actual traceback goes to the platform logs via the raise/re-raise in
    the except branch."""
    try:
        return _app_inner(environ, start_response)
    except Exception:
        import traceback
        traceback.print_exc()
        try:
            start_response("500 Internal Server Error", [("Content-Type", "application/json")] + _CORS_HEADERS)
        except Exception:  # noqa: BLE001 - headers may already have been sent
            pass
        return [json.dumps({"error": "internal server error"}).encode()]


def _app_inner(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET")
    path = environ.get("PATH_INFO", "/")

    if method == "OPTIONS":
        start_response("204 No Content", _CORS_HEADERS)
        return [b""]

    if path.rstrip("/").endswith("/api/analysis"):
        if method != "GET":
            start_response("405 Method Not Allowed", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "GET only"}).encode()]
        return handle_analysis(environ, start_response)

    if path.rstrip("/").endswith("/health"):
        return handle_health(environ, start_response)

    if path.rstrip("/").endswith("/badge"):
        return handle_badge(environ, start_response)

    if path.rstrip("/").endswith("/api/public_scan"):
        if method != "GET":
            start_response("405 Method Not Allowed", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "GET only"}).encode()]
        return handle_public_scan(environ, start_response)

    if path.rstrip("/") in ("/mcp", "/api/mcp"):
        if method != "POST":
            start_response("405 Method Not Allowed", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "POST only (JSON-RPC 2.0)"}).encode()]
        return handle_mcp(environ, start_response)

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

    if path.rstrip("/").endswith("/skill"):
        if method != "GET":
            start_response("405 Method Not Allowed", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "GET only"}).encode()]
        return handle_get_skill(environ, start_response)

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

    if path.rstrip("/").endswith("/api/watch"):
        return handle_watch(environ, start_response)

    if path.rstrip("/").endswith("/api/stats"):
        return handle_stats(environ, start_response)

    if path.rstrip("/").endswith("/api/similar"):
        return handle_similar(environ, start_response)

    if path.rstrip("/").endswith("/api/report"):
        return handle_report(environ, start_response)

    if path.rstrip("/").endswith("/scan"):
        if method != "POST":
            start_response("405 Method Not Allowed", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "POST only"}).encode()]
        return handle_scan(environ, start_response)

    start_response("404 Not Found", [("Content-Type", "application/json")] + _CORS_HEADERS)
    return [json.dumps({"error": "not found"}).encode()]  # no route enumeration (pentest LOW-02)
