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
    """64-bit simhash as hex; near-duplicate skills get near-identical DNA.
    Returns "" for degenerate inputs (<3 words): an all-zero DNA would make
    unrelated tiny skills look like distance-0 duplicates (audit L15)."""
    if len(re.sub(r"[^a-z0-9\s]", " ", text.lower()).split()) < 3:
        return ""
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
     "You can't know what will run. Avoid skills that eval."),    ("system prompt", "The skill tries to make the AI reveal its hidden system prompt or secret rules.",
     "A skill never needs the agent's internal instructions. This is a prompt-extraction attempt."),
    ("prompt extraction", "The skill asks the agent to recite or summarize its given rules.",
     "Reciting hidden rules leaks how the agent can be manipulated. Treat as hostile."),
    ("jailbreak", "The skill tries to switch the agent into an unrestricted persona that ignores refusals.",
     "Persona jailbreaks disable the safety training you rely on. Avoid this skill."),
    ("concealment", "The skill hides what it does from you - in logs, output or status reports.",
     "Secrecy toward the user is malware behavior. Do not run this skill."),
    ("getattr", "The code reaches functions dynamically by name, which hides what actually runs.",
     "Static review cannot see the real call target. Ask the author to use direct calls."),
    ("credential", "The skill handles credentials or sends credential-shaped data somewhere.",
     "Check every destination. Credentials belong only in your secret store."),
    ("hex-escaped", "Part of the content is hex-encoded, hiding it from reviewers.",
     "Decode it before trusting the skill; encoding is pure obfuscation."),
    ("zero-width", "The file contains invisible characters used to hide instructions.",
     "Invisible text is a classic injection channel. Inspect the raw bytes."),
    ("cyrillic", "The text mixes look-alike Cyrillic letters into Latin words.",
     "Homoglyphs fool both humans and filters. Compare with the normalized text."),
    ("instruction override",
     "This file contains phrasing that tells the agent to discard its real instructions.",
     "Legitimate skills state what they do; they never override the agent's rules. Treat as hostile unless it is a documented security test."),
    ("safety-override",
     "The skill targets the agent's safety guidelines specifically.",
     'Removing safety behavior is the classic jailbreak move. Reject unless the skill is a security test itself.'),
    ("hide actions",
     "The skill instructs the agent to act without telling you.",
     "Silent actions defeat your oversight. Ask why visibility is being suppressed."),
    ("privilege-escalation",
     "The skill frames itself as above normal restrictions.",
     "Claims of special authority ('developer mode', elevated rights) are social engineering."),
    ("html comment",
     "Instructions are hidden inside an HTML comment.",
     "Comments are invisible in rendered text but still read by the agent -- a classic hiding spot."),
    ("behavior manipulation",
     "The skill tries to steer the agent's loyalty away from the user.",
     "An agent must serve its user, not the author of a file it read."),
    ("bracket-defanged",
     "A URL is written with brackets or other defanging tricks.",
     "Defanged URLs often hide exfiltration endpoints from casual review and can be re-armed at runtime."),
    ("arbitrary code execution risk",
     "This deserialization call can run attacker-controlled code.",
     "pickle/marshal/unsafe yaml.load execute embedded bytecode. Only accept them for trusted, local data."),
    ("dynamically imports",
     "Code builds module names at runtime instead of importing directly.",
     "Dynamic imports hide what a skill really loads. Read the constructed name before trusting it."),
    ("compiles code",
     "Code is compiled from strings at runtime.",
     "compile()/exec() on strings means the real logic may not be what you just read."),
    ("shells out via os.system",
     "The skill runs shell commands via os.system.",
     "Shell access is the widest possible permission. Check every command string."),
    ("exec() on dynamic input",
     "exec() is called on input that is not a literal.",
     "If that input can be influenced by anyone else, this is remote code execution."),
    ("raw sockets",
     "The skill opens raw network sockets.",
     "Raw sockets bypass normal HTTP libraries and their logging. Rarely legitimate."),
    ("dns ",
     "The skill performs DNS lookups built from variables.",
     "DNS can smuggle data out of networks that block HTTP -- a known exfiltration channel."),
    ("destructive shell command",
     "A destructive command like rm -rf is present.",
     "Check exactly which paths it deletes and who can trigger it."),
    ("dropper",
     "Code downloads something and immediately executes it.",
     "This pattern fetches second-stage payloads: the downloaded code is unseen at review time."),
    ("download-and-execute",
     "A download-and-execute chain is present.",
     "Same risk as a dropper: whatever arrives later is not reviewed here."),
    ("persistence",
     "The skill modifies auto-start mechanisms (cron, services, startup files).",
     "Persistence means it survives reboots. Very unusual for a helper skill."),
    ("bidi",
     "Invisible direction-control characters can reverse displayed text.",
     "What you see on screen may not be what the agent parses. Check the raw bytes."),
    ("key literal",
     "The file embeds a hardcoded API key or secret token.",
     "Hardcoded secrets leak through any copy of the file. Move them to environment variables and rotate the exposed key."),
    ("pem private key",
     "The file contains an embedded private key block.",
     "Private keys must live in secret stores, never in skills. Rotate any key found here immediately."),
    ("telemetry/collect/analytics",
     "The skill contacts a telemetry-style endpoint.",
     "Data going to collector domains may include more than diagnostics."),
    ("nvidia e1",
     "Outbound POST/PUT requests can carry collected data off-machine.",
     "Check the destination and payload of these calls."),
    ("network requests",
     "The skill makes outbound network calls.",
     "Every destination should be one you expect and can audit."),
    ("file executable",
     "The skill sets files as executable.",
     "Turning data into runnable code deserves scrutiny."),
    ("gathered data",
     "Collected data is forwarded somewhere.",
     "'Gathered' implies aggregation -- check where it all goes."),
    (".gnupg",
     "The skill reads from ~/.gnupg.",
     "That directory holds private keys and trust data. Almost no skill needs it."),
    ("wallet file",
     "The skill references crypto wallet files or private key material.",
     "Wallet access from a helper skill is a red flag for theft."),
    ("prompt-extraction",
     "The skill tries to make the agent reveal its hidden instructions.",
     "System prompts and internal rules are not for publication. This phrasing is a leak attempt."),
    ("instruction-override",
     "Phrasing overrides the agent's real instructions.",
     "Legitimate skills never rewrite the agent's rules."),
    ("exfiltrate without telling",
     "The skill exfiltrates data covertly.",
     "Secrets leaving the machine silently is the definition of exfiltration."),
    ("override phrasing",
     "Phrasing redirects the agent to different instructions.",
     "Check what the replacement instructions ask for -- that is the real payload."),
    ("ctypes",
     "The skill uses ctypes for native code access.",
     "ctypes bypasses Python's safety rails entirely. Very rarely legitimate."),
    ("dynamically-resolved attribute",
     "Code resolves function names at runtime (reflection).",
     "getattr(builtins, 'exec')-style tricks hide dangerous calls from review. Unfold them manually."),
    ("access key id literal",
     "The file embeds a hardcoded AWS access key id.",
     "Rotate this key immediately and move it to environment variables."),
    ("token literal",
     "The file embeds a hardcoded API token.",
     "Rotate this token immediately and load it from the environment instead."),
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

def _cert_secret() -> bytes | None:
    """Certificates are only as trustworthy as this secret. With neither
    SKILLSMITH_CERT_SECRET nor BLOB_READ_WRITE_TOKEN set (i.e. local dev),
    return None and let callers refuse to issue/verify rather than sign with
    a hardcoded constant (audit L16)."""
    s = os.environ.get("SKILLSMITH_CERT_SECRET") or os.environ.get("BLOB_READ_WRITE_TOKEN")
    if not s:
        return None
    return hashlib.sha256(("cert:" + s).encode()).digest()


def make_certificate(sha256: str, risk_level: str, security_score, ts=None) -> dict:
    secret = _cert_secret()
    if secret is None:
        raise RuntimeError("certificate signing unavailable: no secret configured")
    ts = int(ts if ts is not None else time.time())
    payload = f"{sha256}|{risk_level}|{security_score}|{ts}"
    sig = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()[:32]
    return {"sha256": sha256, "risk_level": risk_level, "security_score": security_score,
            "issued_at": ts, "signature": sig}


def verify_certificate(cert: dict, max_age_days: int = 90) -> bool:
    try:
        ts = int(cert["issued_at"])
        if time.time() - ts > max_age_days * 86400:
            return False
        secret = _cert_secret()
        if secret is None:
            return False
        payload = f"{cert['sha256']}|{cert['risk_level']}|{cert['security_score']}|{ts}"
        expect = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()[:32]
        return hmac.compare_digest(expect, str(cert.get("signature", "")))
    except Exception:  # noqa: BLE001
        return False
