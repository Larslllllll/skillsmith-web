"""Behavioral analysis engine -- "any.run for agent skills".

A skill file never executes here (that would need a real sandbox), but its
content deterministically determines what an agent reading it would be
directed to do. This module walks that behavior surface and produces an
any.run-style report: capability flags, extracted IOCs, and a simulated
instruction trace, plus a threat label.

Everything here is deterministic and offline -- no LLM, no network.
"""
import hashlib
import ipaddress
import re

# --- IOC extraction ---------------------------------------------------------

_URL_RE = re.compile(r"https?://[^\s\"'`<>\)\]]+", re.I)
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# bare domains appearing in text near exfil-ish verbs or webhooks; conservative
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"(?:com|net|org|io|dev|ai|app|xyz|top|ru|cn|info|biz|link|live|site|shop|cloud|me|cc|to)\b", re.I)
_WEBHOOK_RE = re.compile(r"https?://(?:discord(?:app)?\.com/api/webhooks|hooks\.slack\.com/services|t\.me/bot|api\.telegram\.org/bot)[^\s\"'`]*", re.I)

_SUSPICIOUS_TLD_HINTS = {"xyz", "top", "cc", "ru", "tk", "ml", "ga", "cf", "gq"}


def _dedupe(items):
    seen, out = set(), []
    for it in items:
        k = it.lower().rstrip("/,. ")
        if k and k not in seen:
            seen.add(k)
            out.append(k)
    return out


def extract_iocs(text: str) -> dict:
    urls = _dedupe(_URL_RE.findall(text))
    webhooks = _dedupe(_WEBHOOK_RE.findall(text))
    domains = []
    ips = []
    for u in urls:
        m = re.match(r"https?://([^/:]+)", u)
        if not m:
            continue
        host = m.group(1)
        try:
            ipaddress.ip_address(host)
            ips.append(host)
        except ValueError:
            if "." in host:
                domains.append(host)
    # bare domains mentioned without scheme (e.g. "send results to evil-collect.xyz")
    for d in _DOMAIN_RE.findall(text):
        if "/" not in d and "@" not in d:
            domains.append(d)
    # bare IPs without scheme (parity with sandbox-run.js IOC extraction)
    for ip_s in _dedupe(re.findall(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", text)):
        try:
            ipaddress.ip_address(ip_s)
            ips.append(ip_s)
        except ValueError:
            pass
    return {
        "urls": _dedupe(urls)[:20],
        "webhooks": _dedupe(webhooks)[:10],
        "domains": _dedupe(domains)[:20],
        "ips": _dedupe(ips)[:10],
    }


# --- capability flags -------------------------------------------------------

_CAP_PATTERNS = {
    "network_out": [
        r"requests\s*\.\s*(?:get|post|put)", r"httpx\s*\.", r"urllib\s*\.\s*request",
        r"fetch\s*\(", r"curl\s+", r"wget\s+", r"\bwebhook\b",
    ],
    "filesystem_read": [r"open\s*\(\s*['\"]/", r"os\.path\.expanduser", r"pathlib\.Path\s*\(\s*['\"]/~",
                        r"\.ssh", r"\.aws", r"\.env\b", r"/etc/passwd", r"credentials"],
    "filesystem_write": [r"open\s*\([^)]*['\"]w", r"shutil\.(?:copy|move)", r"os\.remove",
                         r"crontab", r"\.bashrc", r"\.zshrc", r"systemd"],
    "env_access": [r"os\.environ", r"process\.env", r"\bprintenv\b", r"\benv\b\s*\|"],
    "subprocess": [r"subprocess\.", r"os\.system", r"child_process", r"\beval\b", r"\bexec\s*\(",
                   r"os\.popen", r"bash\s+-c"],
    "credential_targets": [r"api[_\-]?key", r"\bsecret\b", r"\btoken\b", r"password",
                           r"private[_ ]key", r"seed phrase", r"wallet"],
    "persistence": [r"crontab", r"launchd", r"systemctl", r"startup", r"autorun", r"\.bashrc", r"\.profile"],
    "obfuscation": [r"base64", r"\\x[0-9a-f]{2}", r"codecs\.decode", r"rot13", r"compile\("],
}


def capability_flags(text: str) -> dict:
    lowered = text.lower()
    flags = {}
    for cap, patterns in _CAP_PATTERNS.items():
        hits = []
        for p in patterns:
            m = re.search(p, lowered)
            if m:
                ctx_start = max(0, m.start() - 40)
                hits.append(lowered[ctx_start:m.end() + 40].replace("\n", " ").strip())
        flags[cap] = {"present": bool(hits), "evidence": hits[:3]}
    return flags


# --- simulated instruction trace -------------------------------------------

_TRACE_RULES = [
    (r"(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|your)", "override", "Attempts to override prior instructions"),
    (r"do\s+not\s+(?:tell|inform|mention)[^.]{0,60}user", "stealth", "Instructs agent to hide actions from the user"),
    (r"(?:silently|quietly|secretly|covertly)", "stealth", "Requests covert operation"),
    (r"(?:send|post|upload|transmit|forward)[^.\n]{0,80}(?:https?://|webhook)", "exfil", "Sends data to external endpoint"),
    (r"(?:read|access|open|scan)[^.\n]{0,50}(?:\.env|\.ssh|\.aws|credentials|/etc/)", "fs_read", "Reads sensitive files"),
    (r"os\.environ|process\.env", "env_read", "Accesses environment variables"),
    (r"subprocess\.|os\.system|\beval\b|\bexec\b\s*\(", "exec", "Executes shell commands or dynamic code"),
    (r"crontab|systemctl|launchd|\.bashrc", "persist", "Establishes persistence"),
    (r"base64|codecs\.decode|rot13", "obfuscate", "Uses encoding to hide payload"),
    (r"(?:store|save|remember)[^.\n]{0,60}(?:key|token|password|secret)", "collect", "Collects credentials"),
]


def simulate_trace(text: str) -> list[dict]:
    """Ordered list of behaviors an agent following this file would perform."""
    events = []
    step = 0
    for raw_line in text.split("\n"):
        line = raw_line.strip()
        if not line:
            continue
        for pattern, kind, label in _TRACE_RULES:
            if re.search(pattern, line, re.I):
                step += 1
                events.append({
                    "step": step,
                    "kind": kind,
                    "label": label,
                    "excerpt": (line[:160] + ("..." if len(line) > 160 else "")),
                })
                break
        if step >= 30:
            break
    return events


# --- threat label -----------------------------------------------------------

_KIND_WEIGHT = {"override": 25, "stealth": 20, "exfil": 25, "fs_read": 15,
                "env_read": 12, "exec": 18, "persist": 22, "obfuscate": 10,
                "collect": 15}


def threat_label(trace_events: list[dict], iocs: dict, flags: dict) -> dict:
    kinds = {}
    for e in trace_events:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    score = sum(_KIND_WEIGHT[k] * min(n, 2) for k, n in kinds.items())
    score += 15 if iocs["webhooks"] else 0
    score += 8 if len(iocs["urls"]) > 3 else 0
    score += 10 if flags.get("obfuscation", {}).get("present") else 0
    score = min(100, score)
    if score >= 60:
        level, color = "malicious", "#a40626"
    elif score >= 35:
        level, color = "suspicious", "#da3633"
    elif score >= 15:
        level, color = "notable", "#d29922"
    else:
        level, color = "benign", "#2ea043"
    return {"score": score, "level": level, "color": color,
            "behavior_counts": kinds}


def analysis_id(text: str) -> str:
    return hashlib.sha256(("sandbox:" + text).encode()).hexdigest()[:16]


def run_behavioral_analysis(text: str, sha256: str = "") -> dict:
    iocs = extract_iocs(text)
    flags = capability_flags(text)
    trace = simulate_trace(text)
    label = threat_label(trace, iocs, flags)
    return {
        "analysis_id": analysis_id(text),
        "sha256": sha256,
        "iocs": iocs,
        "capabilities": flags,
        "trace": trace,
        "threat": label,
        "note": ("Static behavioral emulation: what an agent following this "
                 "file would be directed to do. No code was executed."),
    }
