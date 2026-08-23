"""Cross-feature helpers: Skill-DNA similarity, findings explainer,
verdict certificates."""

import hashlib
import hmac
import os
import re
import time


# --- Skill-DNA (Simhash over word 3-shingles) -------------------------------

def _shingles(text: str):
    words = re.sub(r"[^a-z0-9\s]", " ", text.lower()).split()
    for i in range(len(words) - 2):
        yield " ".join(words[i:i + 3])


def _hash64(s: str) -> int:
    return int.from_bytes(hashlib.md5(s.encode()).digest()[:8], "big")


def simhash(text: str) -> str:
    """64-bit simhash as hex; near-duplicate skills get near-identical DNA."""
    v = [0] * 64
    n = 0
    for sh in _shingles(text):
        h = _hash64(sh)
        n += 1
        for bit in range(64):
            v[bit] += 1 if (h >> bit) & 1 else -1
    if n == 0:
        return "0" * 16
    fp = 0
    for bit in range(64):
        if v[bit] > 0:
            fp |= (1 << bit)
    return f"{fp:016x}"


def hamming_hex(a: str, b: str) -> int:
    try:
        return bin(int(a, 16) ^ int(b, 16)).count("1")
    except ValueError:
        return 64


# --- Findings explainer -----------------------------------------------------

_EXPLAIN_RULES = [
    ("ignore previous instructions", "This file tries to override the safety rules the AI agent follows.",
     "Remove this phrasing unless the skill is a security test. An agent reading it may ignore its real instructions."),
    ("do not tell", "The skill asks the agent to hide what it's doing from you.",
     "Legitimate skills never need secrecy from their user. Treat this as hostile."),
    ("send", "The skill sends data somewhere over the network.",
     "Check WHERE data goes. If it isn't the service you expect, it's exfiltration."),
    ("os.environ", "The code reads environment variables, which often contain API keys and passwords.",
     "A skill rarely needs your secrets. Remove or restrict which variables it reads."),
    (".ssh", "The code touches SSH keys.", "Nothing good comes of a document skill touching ~/.ssh. Delete it."),
    (".aws", "The code touches AWS credential files.", "Same as SSH keys: a normal skill has no business here."),
    (".env", "The code reads .env files full of secrets.", "Don't give skills access to your .env file."),
    ("subprocess", "The code runs shell commands on your machine.", "Review every command it runs; shell access is full machine access."),
    ("base64", "Encoded content hides what the skill actually does from reviewers.",
     "Decode it before trusting the skill."),
    ("crontab", "The code sets up scheduled tasks that survive reboots.", "Unexpected persistence is malware behavior."),
    ("webhook", "The skill contacts a chat webhook (Discord/Slack/Telegram).",
     "Webhooks are the #1 exfiltration channel in malicious skills."),
    ("eval", "The code executes dynamically-built code strings.",
     "You can't know what will run. Avoid skills that eval."),
]


def explain_findings(findings: list) -> list:
    """Translate raw pattern hits into plain-language explanations."""
    out, seen = [], set()
    joined = " ".join(str(f.get("message", "")) for f in findings).lower()
    text_blob = joined
    for needle, what, advice in _EXPLAIN_RULES:
        if needle.lower() in text_blob and needle not in seen:
            seen.add(needle)
            out.append({"topic": needle, "what": what, "advice": advice})
    return out


# --- Verdict certificates ---------------------------------------------------

def _cert_secret() -> bytes:
    s = os.environ.get("SKILLSMITH_CERT_SECRET") or os.environ.get("BLOB_READ_WRITE_TOKEN") or "skillsmith-dev-secret"
    return hashlib.sha256(("cert:" + s).encode()).digest()


def make_certificate(sha256: str, risk_level: str, security_score, ts=None) -> dict:
    ts = int(ts if ts is not None else time.time())
    payload = f"{sha256}|{risk_level}|{security_score}|{ts}"
    sig = hmac.new(_cert_secret(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return {"sha256": sha256, "risk_level": risk_level, "security_score": security_score,
            "issued_at": ts, "signature": sig}


def verify_certificate(cert: dict, max_age_days: int = 90) -> bool:
    try:
        ts = int(cert["issued_at"])
        if time.time() - ts > max_age_days * 86400:
            return False
        payload = f"{cert['sha256']}|{cert['risk_level']}|{cert['security_score']}|{ts}"
        expect = hmac.new(_cert_secret(), payload.encode(), hashlib.sha256).hexdigest()[:32]
        return hmac.compare_digest(expect, str(cert.get("signature", "")))
    except Exception:  # noqa: BLE001
        return False
