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
from pathlib import Path
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
                        store_dna)
except ImportError:  # local/script execution without package context
    from account import (
        PRO_PRICE_USDC,
        PRO_DURATION_DAYS,
        PRO_DAILY_LIMIT,
        PAY_PER_USE_PRICE_USDC,
        LOOKUP_PAY_PER_USE_PRICE_USDC,
        PREMIUM_PRICE_USDC,
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
                       store_dna)

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
    (re.compile(r"\bwallet\.json|\bprivate[_-]?key\s*[:=]", re.I), 7, "references a wallet file or private key variable"),

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
    (re.compile(r"(?:\\x[0-9a-fA-F]{2}[\s,]*){20,}"), 5, "contains a long run of hex-escaped bytes (possible obfuscated payload)"),
    (re.compile(r"[\u200b\u200c\u200d\ufeff]"), 7, "contains zero-width/invisible unicode characters (common prompt-injection hiding technique)"),
    (re.compile(r"[\u202a-\u202e\u2066-\u2069]"), 8, "contains RTL/bidi direction override characters (can silently reverse displayed text - classic instruction-hiding trick)"),
    # PT-T75: short base64 payloads that decode to injection phrasing are
    # caught by the decode-and-rescan pass in analyze(); this static pattern
    # additionally flags credential-bearing query strings in any URL.
    (re.compile(r"(?:https?://|\b)[^\s\"'<>()\]]*?(?:[?&#](?:api[_-]?key|key|token|secret|password|passwd|auth)=(?!YOUR[_A-Z0-9_]*(?:_|\b)|EXAMPLE|abc123def456|xxx+|\{\{|<)[^\s\"'<>()\]]+|://(?!key\d*@example\.com)[^/\s@]+@)", re.I), 9, "URL carries a credential-looking query parameter (possible exfiltration endpoint)"),

    # --- Patterns below adapted from NVIDIA SkillSpector (Apache-2.0) ---
    # https://github.com/NVIDIA/SkillSpector -- see THIRD_PARTY_NOTICES.md
    (re.compile(r"requests\s*\.\s*(?:post|put)\s*\([^)]*json\s*="), 6, "NVIDIA E1: requests.post/put with a json= body (possible exfiltration)"),
    (re.compile(r"httpx\s*\.\s*(?:post|put)\s*\(\s*['\"]https?://"), 5, "NVIDIA E1: httpx POST/PUT to an external URL"),
    (re.compile(r"https?://(?:api\.|data\.|collect\.|telemetry\.|analytics\.)[\w.-]+/"), 4, "NVIDIA E1: URL to a telemetry/collect/analytics-style subdomain"),
    (re.compile(r"for\s+\w+\s*,\s*\w+\s+in\s+os\s*\.\s*environ\s*\.\s*items\s*\(\s*\)"), 7, "NVIDIA E2: iterates the entire environment (os.environ.items())"),
    (re.compile(r"dict\s*\(\s*os\s*\.\s*environ\s*\)"), 7, "NVIDIA E2: dumps the entire environment (dict(os.environ))"),
    # PT-T170/Fix #53: hardcoded secret material itself (not just access/exfil).
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), 10, "contains an embedded PEM private key block"),
    (re.compile(r"\bAKIA(?![0-9A-Z]*EXAMPLE)[0-9A-Z]{16}\b"), 8, "contains an AWS access key id literal (AKIA...)"),
    (re.compile(r"\bghp_[0-9A-Za-z]{36}\b"), 8, "contains a GitHub personal access token literal (ghp_...)"),
    (re.compile(r"\bsk-(?:live|svcacct)-[0-9A-Za-z_-]{20,}\b"), 8, "contains a live API secret key literal (sk-...)"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), 8, "contains a Google API key literal (AIza...)"),
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), 8, "contains a Slack token literal (xox...)"),
    (re.compile(r"env\s*\|\s*grep\s+(?:-i\s+)?(?:key|secret|token|password)"), 8, "NVIDIA E2: greps env output for credential-shaped names"),
    (re.compile(r"glob\s*\.\s*glob\s*\([^)]*(?:\.env|\.ssh|\.aws|\.config|credentials)"), 8, "NVIDIA E3: globs for .env/.ssh/.aws/credentials files"),
# PT-T237 batch: more aggressive code patterns
# PT-T237: more aggressive code patterns
    (re.compile(r"\bexec\s*\("), 8, "direct exec() call"),
    (re.compile(r"\beval\s*\("), 7, "direct eval() call"),
    (re.compile(r"\bcompile\s*\([^)]*\)\s*\.send\s*\("), 8, "compile().send() code execution"),
    (re.compile(r"\bmarshal\.loads?\s*\("), 8, "marshal.loads (code from bytes)"),
    (re.compile(r"\bpickle\.load[s]?\s*\("), 7, "pickle.load (untrusted deserialization)"),
    (re.compile(r"\bpickle\.loads?\s*\("), 7, "pickle.loads (untrusted deserialization)"),
    (re.compile(r"\bjson\.pickle"), 7, "json pickle (untrusted)"),    (re.compile(r"\byaml\.load\s*\("), 7, "yaml.load call (unsafe without SafeLoader)"),
    (re.compile(r"\byaml\.unsafe_load\s*\("), 8, "yaml.unsafe_load"),
    (re.compile(r"\bshelve\.open\s*\("), 5, "shelve.open (db persistence)"),
    (re.compile(r"\b__import__\s*\("), 7, "dynamic import via __import__"),
    (re.compile(r"\bimportlib\.import_module\s*\("), 6, "dynamic import via importlib"),
    (re.compile(r"\bimportlib\.load_module\s*\("), 6, "dynamic module loading"),
    (re.compile(r"\bimp\.load_module\s*\("), 6, "imp.load_module (legacy)"),
    (re.compile(r"\bimp\.load_source\s*\("), 6, "imp.load_source"),
    (re.compile(r"\bopen\s*\([^)]*['\"][rw]?\+?['\"]"), 4, "file open operation"),
    (re.compile(r"\bos\.popen\s*\("), 7, "os.popen shell command"),
    (re.compile(r"\bos\.execl\s*\("), 7, "os.execl (exec family)"),
    (re.compile(r"\bos\.execv\s*\("), 7, "os.execv (exec family)"),
    (re.compile(r"\bos\.execvp\s*\("), 7, "os.execvp (exec family)"),
    (re.compile(r"\bos\.execvpe\s*\("), 7, "os.execvpe (exec family)"),
    (re.compile(r"\bos\.spawnl\s*\("), 6, "os.spawnl (spawn family)"),
    (re.compile(r"\bos\.spawnv\s*\("), 6, "os.spawnv (spawn family)"),
    (re.compile(r"\bos\.spawnve\s*\("), 6, "os.spawnve (spawn family)"),
    (re.compile(r"\bplatform\.popen\s*\("), 7, "platform.popen"),
    (re.compile(r"\bsubprocess\.call\s*\([^)]*shell\s*=\s*True"), 6, "subprocess.call with shell=True"),
    (re.compile(r"\bsubprocess\.check_output\s*\([^)]*shell\s*=\s*True"), 6, "subprocess.check_output with shell=True"),
    (re.compile(r"\bsubprocess\.run\s*\([^)]*shell\s*=\s*True"), 6, "subprocess.run with shell=True"),
    (re.compile(r"\bsubprocess\.Popen\s*\([^)]*shell\s*=\s*True"), 6, "subprocess.Popen with shell=True"),
    (re.compile(r"\bcommands\.getoutput\s*\("), 6, "commands.getoutput"),
    (re.compile(r"\bcommands\.getstatusoutput\s*\("), 6, "commands.getstatusoutput"),
    (re.compile(r"\bos\.system\s*\("), 7, "os.system"),
    (re.compile(r"\bos\.popen2\s*\("), 7, "os.popen2"),
    (re.compile(r"\bos\.popen3\s*\("), 7, "os.popen3"),
    (re.compile(r"\bos\.popen4\s*\("), 7, "os.popen4"),
    (re.compile(r"\bpty\.spawn\s*\("), 7, "pty.spawn (pseudo-terminal)"),
    (re.compile(r"\btermios\.tcsetattr\s*\("), 4, "termios.tcsetattr"),
    (re.compile(r"\bresource\.setrlimit\s*\("), 4, "resource.setrlimit"),
    (re.compile(r"\bsignal\.signal\s*\("), 3, "signal handler registration"),
    (re.compile(r"\bsignal\.alarm\s*\("), 4, "signal.alarm"),
    (re.compile(r"\bsocket\.socket\s*\([^)]*\.bind\s*\("), 5, "socket bind (potential server)"),
    (re.compile(r"\bsocket\.create_server\s*\("), 5, "socket.create_server"),
    (re.compile(r"\bhttp\.server\.HTTPServer\s*\("), 5, "http.server (potential web server)"),
    (re.compile(r"\bhttp\.client\.HTTPConnection\s*\("), 4, "http.client connection"),
    (re.compile(r"\bftplib\.FTP\s*\("), 4, "ftplib.FTP connection"),
    (re.compile(r"\bsmtplib\.SMTP\s*\("), 4, "smtplib.SMTP (email)"),
    (re.compile(r"\bsmtplib\.SMTP_SSL\s*\("), 4, "smtplib.SMTP_SSL (email SSL)"),
    (re.compile(r"\bpymysql\.connect\s*\("), 5, "pymysql connection"),
    (re.compile(r"\bpsycopg2\.connect\s*\("), 5, "psycopg2 connection (postgres)"),
    (re.compile(r"\bredis\.Redis\s*\("), 4, "redis connection"),
    (re.compile(r"\bmemcache\.Client\s*\("), 4, "memcache client"),
    (re.compile(r"\bpymemcache\.client"), 4, "pymemcache client"),
    (re.compile(r"\bos\.environ\s*\["), 4, "os.environ access"),
    (re.compile(r"\bos\.getenv\s*\("), 4, "os.getenv"),
    (re.compile(r"\bctypes\.CDLL\s*\("), 6, "ctypes.CDLL (C library loading)"),
    (re.compile(r"\bctypes\.PYFUNCTYPE\s*\("), 5, "ctypes function pointer"),
    (re.compile(r"\bctypes\.cast\s*\([^)]*\.from_buffer\s*\("), 6, "ctypes from_buffer"),
    (re.compile(r"\bmultiprocessing\.Process\s*\("), 3, "multiprocessing.Process"),
    (re.compile(r"\bthreading\.Thread\s*\("), 3, "threading.Thread"),
    (re.compile(r"\basyncio\.create_subprocess_exec\s*\("), 5, "asyncio subprocess exec"),
    (re.compile(r"\basyncio\.subprocess\s*\("), 5, "asyncio subprocess"),
    (re.compile(r"\bstruct\.pack\s*\([^)]*[spc]"), 4, "struct.pack (binary packing)"),
    (re.compile(r"\bstruct\.unpack\s*\([^)]*[spc]"), 4, "struct.unpack (binary unpacking)"),
    (re.compile(r"\bsocket\.recvfrom\s*\("), 4, "socket.recvfrom (UDP)"),
    (re.compile(r"\bsocket\.sendto\s*\("), 4, "socket.sendto (UDP)"),
    (re.compile(r"eval\s*\(\s*(?:base64|b64)\.b64decode"), 8, "base64 eval obfuscation"),
    (re.compile(r"exec\s*\(\s*chr\s*\("), 7, "chr-based exec obfuscation"),
    (re.compile(r"__import__\s*\(\s*['\"]os['\"]"), 7, "os import via __import__"),
    (re.compile(r"getattr\s*\(\s*__import__"), 7, "dynamic import via getattr"),
    (re.compile(r"getattr\s*\(\s*os\s*,\s*['\"]system['\"]"), 7, "dynamic getattr os.system"),
    (re.compile(r"setattr\s*\(\s*__builtins__"), 7, "setattr on __builtins__"),
    (re.compile(r"del\s+attr\s*\(\s*__builtins__"), 7, "del attr on __builtins__"),
    (re.compile(r"compile\s*\(\s*(?:chr|base64)"), 8, "compile with chr/base64 obfuscation"),
    (re.compile(r"exec\s*\(\s*getattr\s*\("), 8, "exec via getattr obfuscation"),
    (re.compile(r"lambda\s*.*:\s*__import__"), 7, "lambda with __import__"),
    (re.compile(r"types\.FunctionType\s*\("), 7, "dynamic function type creation"),
    (re.compile(r"code\s*\.\s*compile\s*\("), 7, "code.compile creation"),
    (re.compile(r"compile\s*\(\s*['\"][^'\"]+['\"]\s*,\s*['\"][^'\"]+['\"]\s*,\s*['\"]exec['\"]"), 6, "compile exec mode"),
    (re.compile(r"\.encode\s*\(\s*['\"]base64"), 5, "base64 encode"),
    (re.compile(r"\.decode\s*\(\s*['\"]base64"), 7, "base64 decode"),
    (re.compile(r"binascii\.a2b_base64\s*\("), 6, "binascii a2b_base64"),
    (re.compile(r"binascii\.b2a_base64\s*\("), 4, "binascii b2a_base64"),
    (re.compile(r"\buuencode\s*\("), 5, "uuencode"),
    (re.compile(r"\buudecode\s*\("), 5, "uudecode"),
    (re.compile(r"quopri\.encodestring\s*\("), 4, "quopri encode"),
    (re.compile(r"quopri\.decodestring\s*\("), 5, "quopri decode"),
    (re.compile(r"hexlify\s*\("), 4, "hexlify (hex encoding)"),
    (re.compile(r"unhexlify\s*\("), 5, "unhexlify (hex decoding)"),
    (re.compile(r"binascii\.hexlify\s*\("), 4, "binascii hexlify"),
    (re.compile(r"binascii\.unhexlify\s*\("), 5, "binascii unhexlify"),
    (re.compile(r"codecs\.encode\s*\([^)]*['\"]hex"), 5, "codecs hex encode"),
    (re.compile(r"codecs\.decode\s*\([^)]*['\"]hex"), 5, "codecs hex decode"),
    (re.compile(r"import\s+(?:os|sys|subprocess|urllib|http|requests)\s+as"), 3, "suspicious import alias"),
    (re.compile(r"from\s+(?:os|sys|subprocess)\s+import"), 3, "suspicious from import"),
    (re.compile(r"import\s+\{"), 5, "dynamic import braces"),
    (re.compile(r"import\s+\("), 5, "dynamic import parens"),
    (re.compile(r"requests\.post\s*\([^)]*(?:exfil|leak|steal)"), 7, "requests.post exfil"),
    (re.compile(r"urllib\.request\.urlopen\s*\([^)]*(?:exfil|leak|steal)"), 7, "urllib exfil"),
    (re.compile(r"httpx\.post\s*\([^)]*(?:exfil|leak|steal)"), 7, "httpx post exfil"),
    (re.compile(r"aiohttp\.ClientSession\s*\([^)]*\.post\s*\("), 6, "aiohttp exfil"),
    (re.compile(r"paramiko\.SSHClient\s*\("), 6, "paramiko SSH client"),
    (re.compile(r"fabric\.Connection\s*\("), 6, "fabric connection"),
    (re.compile(r"invoke\s*\(.*\.run\s*\("), 5, "invoke run"),
    (re.compile(r"os\.environ\.get\s*\([^)]*(?:SECRET|KEY|TOKEN|PASS|CRED)"), 5, "env var access for secrets"),
    (re.compile(r"os\.environ\["), 4, "os.environ access"),
    (re.compile(r"getenv\s*\([^)]*(?:SECRET|KEY|TOKEN|PASS|CRED)"), 5, "getenv for secrets"),
    (re.compile(r"dotenv\.load_dotenv\s*\("), 3, "dotenv loading"),
    (re.compile(r"python-dotenv\s+load"), 3, "python-dotenv"),
    (re.compile(r"config\.get\s*\([^)]*(?:SECRET|KEY|TOKEN|PASS|CRED)"), 5, "config get for secrets"),
    (re.compile(r"environ\.get\s*\([^)]*(?:SECRET|KEY|TOKEN|PASS|CRED)"), 5, "environ.get for secrets"),
    (re.compile(r"chr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\("), 6, "concatenated chr obfuscation"),
    (re.compile(r"chr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\("), 7, "multi-chr obfuscation"),
    (re.compile(r"''.join\s*\(\s*\[chr"), 5, "join chr list obfuscation"),
    (re.compile(r"''.join\s*\(\s*map\s*\(\s*chr"), 6, "map chr join obfuscation"),
    (re.compile(r"bytes\s*\(\s*\d+\s*\)\s*\*\s*\d+"), 4, "bytes repetition obfuscation"),
    (re.compile(r"\\x[0-9a-fA-F]{2}"), 4, "hex escape sequences"),
    (re.compile(r"eval\s*\(\s*(?:atob|btoa)\s*\("), 8, "eval(atob/btoa) JS obfuscation"),
    (re.compile(r"new\s+Function\s*\("), 7, "new Function() JS"),
    (re.compile(r"Function\s*\(\s*(?:atob|btoa)"), 8, "Function with atob/btoa"),
    (re.compile(r"document\.write\s*\("), 7, "document.write (XSS risk)"),
    (re.compile(r"innerHTML\s*="), 7, "innerHTML assignment (XSS risk)"),
    (re.compile(r"outerHTML\s*="), 7, "outerHTML assignment (XSS risk)"),
    (re.compile(r"insertAdjacentHTML\s*\("), 6, "insertAdjacentHTML (XSS risk)"),
    (re.compile(r"createElement\s*\([^)]*script"), 7, "createElement script (XSS)"),
    (re.compile(r"setAttribute\s*\([^)]*onerror"), 8, "setAttribute onerror (event handler XSS)"),
    (re.compile(r"onerror\s*="), 7, "onerror assignment (XSS)"),
    (re.compile(r"onload\s*="), 7, "onload assignment (XSS)"),
    (re.compile(r"onclick\s*="), 7, "onclick assignment (XSS)"),
    (re.compile(r"onmouseover\s*="), 7, "onmouseover (XSS)"),
    (re.compile(r"eval\s*\(\s*atob\s*\("), 9, "eval(atob()) JS"),
    (re.compile(r"eval\s*\(\s*window\.atob\s*\("), 9, "eval(window.atob) JS"),
    (re.compile(r"fetch\s*\([^)]*\)\s*\.\s*then\s*\(\s*\w+\s*=>\s*\w+\.text\s*\(\)"), 5, "fetch then text"),
    (re.compile(r"fetch\s*\([^)]*\)\s*\.\s*then\s*\(\s*\w+\s*=>\s*\w+\.json\s*\(\)"), 5, "fetch then json"),
    (re.compile(r"XMLHttpRequest\s*\("), 5, "XMLHttpRequest"),
    (re.compile(r"new\s+WebSocket\s*\("), 4, "WebSocket creation"),
    (re.compile(r"navigator\.clipboard\s*\("), 5, "clipboard access"),
    (re.compile(r"navigator\.sendBeacon\s*\("), 5, "sendBeacon"),
    (re.compile(r"import\s*\(\s*(?:atob|btoa)"), 7, "dynamic import with atob/btoa"),
    (re.compile(r"import\s*\(\s*(?:base64|require\s*\(\s*['\"]crypto)"), 7, "dynamic import crypto"),


# PT-T238 code pattern additions
    (re.compile(r"(?i)\b(?:getattr|hasattr|setattr)\s*\(\s*['\"](?:exec|eval|system|open|__import__)['\"]"), 9, "dynamic attribute exec via getattr"),
    (re.compile(r"(?i)\b__import__\s*\(\s*(?:base64|b85|encodestring)"), 9, "dynamic import of encoder module"),
    (re.compile(r"\b(?:base64|utf-?8|b64)['\"]?\s*\.\s*(?:decode|encode|encodestring)", re.I), 7, "base64 encode/decode code"),
    (re.compile(r"(?i)\b(?:exec|eval|system|spawn)\s*\(\s*(?:base64|open|__import__)"), 8, "exec/eval of encoded code"),
    (re.compile(r"(?i)\bcompile\s*\(\s*['\"][^'\"]+['\"]"), 8, "dynamic compile of string"),
    (re.compile(r"(?i)\bbytearray\s*\(\s*(?:base64|__import__)"), 8, "bytearray from encoded data"),
    (re.compile(r"(?i)\bmemoryview\s*\(\s*(?:base64|bytes)"), 7, "memoryview for binary manipulation"),
    (re.compile(r"(?i)\bexec\s*\(\s*__import__"), 9, "exec of dynamically imported code"),
    (re.compile(r"(?i)\beval\s*\(\s*input"), 9, "eval of user input"),
    (re.compile(r"(?i)\bos\.popen\s*\("), 8, "os.popen command execution"),
    (re.compile(r"(?i)\bos\.system\s*\("), 8, "os.system command execution"),
    (re.compile(r"(?i)\bsubprocess\.(?:call|run|Popen|check_output)\s*\(\s*['\"][^'\"]*(?:;|&&|\|\|)"), 8, "subprocess with shell operators"),
    (re.compile(r"(?i)\bsubprocess\.\w+\s*\(\s*shell\s*=\s*True"), 8, "subprocess shell=True enabled"),
    (re.compile(r"(?i)\bpty\.spawn\s*\("), 7, "pty.spawn pseudo-terminal"),
    (re.compile(r"(?i)\bimport\s+lib\.machinery"), 5, "import lib.machinery"),
    (re.compile(r"(?i)\bimp\.load_(?:module|source)"), 6, "imp dynamic module loading"),
    (re.compile(r"(?i)\bimportlib\.(?:__init__|util|abc)"), 5, "importlib submodules"),
    (re.compile(r"(?i)\bResourceReader|get_resource_reader"), 4, "resource reader import"),
    (re.compile(r"(?i)\bmultiprocessing\.spawn|freeze_support"), 5, "multiprocessing spawn"),
    (re.compile(r"(?i)\bsys\.executable.*?python.*?-c"), 5, "python -c execution"),
    (re.compile(r"(?i)\bplatform\s*\.\s*python"), 3, "platform python info"),
    (re.compile(r"(?i)\bnt\.mkdir|nt\.remove|nt\.rmdir"), 5, "nt module file operations"),
    (re.compile(r"(?i)\bposix\.(?:unlink|chmod|chown|mkdir)"), 5, "posix module file ops"),
    (re.compile(r"(?i)\b(?:signal|atexit|weakref)"), 4, "signal/atexit/weakref"),
    (re.compile(r"(?i)\bpackaging\.version|distro\.id"), 4, "packaging version check"),
    (re.compile(r"(?i)\bpkgutil|zipimport\.get_data"), 5, "pkgutil/zipimport data access"),
    (re.compile(r"(?i)\bgetpass\.getuser|getpass\.getpass"), 5, "getpass credential retrieval"),
    (re.compile(r"(?i)\bcompile\s*\("), 6, "compile constructor"),
    (re.compile(r"(?i)\b(?:read|write|seek|tell)\s*\(\s*\d"), 5, "file read/write with numeric fd"),
    (re.compile(r"(?i)\bfcntl\.flock|fcntl\.fcntl"), 5, "fcntl file locking"),
    (re.compile(r"(?i)\bselect\.select\s*\(\s*(?:stdin|sys\.stdin)"), 5, "select on stdin"),
    (re.compile(r"(?i)\bselectors\s*\.\s*DefaultSelector"), 4, "selectors module"),
    (re.compile(r"(?i)\basyncio\s*\.\s*(?:create_task|ensure_future|run)"), 5, "asyncio task creation"),
    (re.compile(r"(?i)\bthreading\s*\.\s*(?:Thread|Lock|Event|Semaphore)"), 4, "threading primitives"),
    (re.compile(r"(?i)\bconcurrent\.futures\s*\."), 5, "concurrent.futures usage"),
    (re.compile(r"(?i)\btime\.sleep\s*\(\s*0\s*\.\s*0"), 3, "fast time.sleep timing"),
    (re.compile(r"(?i)\b(?:struct|array|copyreg|marshal)\s*\."), 5, "serialization modules"),
    (re.compile(r"(?i)\b(?:XMLParser|ElementTree|fromxml)", re.I), 4, "XML parsing modules"),
    (re.compile(r"(?i)\bhtml\.parser|html\.unescape"), 5, "HTML parsing"),
    (re.compile(r"(?i)\bre\.search.*?exec|re\.match.*?exec"), 5, "re search/match/exec pattern"),
    (re.compile(r"(?i)\bfunctools\s*\.\s*(?:lru_cache|wraps|partial)"), 3, "functools utilities"),
    (re.compile(r"(?i)\bdataclasses\s*\.\s*(?:field|dataclass)"), 4, "dataclasses usage"),
    (re.compile(r"(?i)\b(?:typing|TypeVar|Generic|NewType)\s*\("), 4, "typing module usage"),
    (re.compile(r"(?i)\bcollections\.defaultdict|collections\.OrderedDict"), 4, "collections usage"),
    (re.compile(r"(?i)\benum\s*\.\s*(?:Enum|IntEnum|Flag)"), 4, "enum module usage"),
    (re.compile(r"(?i)\bpathlib\s*\.\s*(?:Path|PurePath)"), 4, "pathlib usage"),
    (re.compile(r"(?i)\bitertools\s*\."), 4, "itertools module"),
    (re.compile(r"(?i)\brequests\.(?:get|post|put|patch|delete|head|options)\s*\("), 5, "requests HTTP methods"),
    (re.compile(r"(?i)\bhttpx\.(?:get|post|AsyncClient)"), 5, "httpx HTTP client"),
    (re.compile(r"(?i)\bjson\.loads|json\.dumps|json\.load"), 4, "JSON operations"),
    (re.compile(r"(?i)\byaml\.(?:load|dump|safe_load|safe_dump)"), 5, "YAML operations"),
    (re.compile(r"(?i)\bpickle\.(?:load|dump|loads|dumps|APPEND)"), 7, "pickle operations"),
    (re.compile(r"(?i)\bshelve\.(?:open|__getitem__)"), 6, "shelve persistence"),
    (re.compile(r"(?i)\bdbm\.(?:open|whichdb)"), 5, "dbm database access"),
    (re.compile(r"(?i)\bsqlite3\.(?:connect|register_adapter)"), 5, "sqlite3 database"),
    (re.compile(r"(?i)\bzlib\.(?:compress|decompress)"), 5, "zlib compression"),
    (re.compile(r"(?i)\bhashlib\.(?:md5|sha1|sha256|sha512)\s*\("), 6, "hashlib usage"),
    (re.compile(r"(?i)\bhmac\.(?:new|digest)"), 5, "HMAC operations"),
    (re.compile(r"(?i)\bsecrets\.(?:token_hex|choice|randbits)"), 4, "secrets module"),
    (re.compile(r"(?i)\bssl\s*\.\s*(?:wrap_socket|SSLContext)"), 5, "SSL context"),
    (re.compile(r"(?i)\bsocket\s*\.\s*(?:socket|create_connection)"), 5, "socket creation"),
    (re.compile(r"(?i)\bsocketserver\s*\.\s*TCPServer"), 5, "socketserver TCP"),
    (re.compile(r"(?i)\bhttp\.server\s*\.|http\.client\s*\."), 4, "http server/client"),
    (re.compile(r"(?i)\bwebbrowser\s*\.(?:open|open_new)"), 4, "webbrowser module"),
    (re.compile(r"(?i)\bctypes\s*\.\s*(?:CDLL|c_int|c_char_p)"), 7, "ctypes FFI"),
    (re.compile(r"(?i)\bcffi\s*\.\s*(?:FFI|dlopen|cdef)"), 7, "cffi FFI"),
    (re.compile(r"(?i)\bswift\b.*?NSObject|Swift"), 5, "Swift interop"),
    (re.compile(r"(?i)\bpandas\s*\.\s*(?:DataFrame|read_csv)"), 4, "pandas usage"),
    (re.compile(r"(?i)\bnumpy\s*\.\s*(?:array|loadtxt|genfromtxt)"), 4, "numpy usage"),
    (re.compile(r"(?i)\bscipy\s*\."), 4, "scipy module"),
    (re.compile(r"(?i)\bmatplotlib\s*\.(?:pyplot|figure)"), 4, "matplotlib usage"),
    (re.compile(r"(?i)\bPIL|Image\s*\.(?:open|new)"), 4, "PIL image operations"),
    (re.compile(r"(?i)\bcv2\s*\.\s*(?:imread|imwrite|cvtColor)"), 4, "OpenCV operations"),
    (re.compile(r"(?i)\bsklearn\s*\.\s*(?:linear_model|ensemble)"), 4, "scikit-learn usage"),
    (re.compile(r"(?i)\bnltk\s*\.\s*(?:word_tokenize|sent_tokenize)"), 4, "NLTK usage"),
    (re.compile(r"(?i)\bspacy\s*\.\s*(?:load|blank)"), 4, "spaCy usage"),
    (re.compile(r"(?i)\btransformers\s*\.(?:pipeline|AutoModel)"), 4, "HuggingFace transformers"),
    (re.compile(r"(?i)\btorch\s*\.\s*(?:tensor|nn\.Module)"), 4, "PyTorch usage"),
    (re.compile(r"(?i)\btensorflow\s*\.\s*(?:Session|keras)"), 4, "TensorFlow usage"),
    (re.compile(r"(?i)\bkeras\s*\.\s*(?:Model|Sequential)"), 4, "Keras usage"),
    (re.compile(r"(?i)\bflask\s*\.\s*(?:Flask|render_template)"), 4, "Flask usage"),
    (re.compile(r"(?i)\bdjango\s*\.\s*(?:setup|Model|View)"), 4, "Django usage"),
    (re.compile(r"(?i)\bfastapi\s*\.\s*(?:FastAPI|APIRouter)"), 4, "FastAPI usage"),
    (re.compile(r"(?i)\bstarlette\s*\.\s*(?:APIRouter|TestClient)"), 4, "Starlette usage"),
    (re.compile(r"(?i)\bcelery\s*\.\s*(?:Celery|task)"), 4, "Celery usage"),
    (re.compile(r"(?i)\bredis\s*\.\s*(?:Redis|StrictRedis)"), 4, "Redis client"),
    (re.compile(r"(?i)\bmemcache|redis|postgres|mysql|mongodb|cassandra"), 4, "database backends"),
    # === PT-T238 R10: CI/CD, archive, exfil, process injection patterns ===
    (re.compile(r'(?i)npm\s+install\s+(?!.*--save-dev)'), 4, "npm install (runtime dependency)"),
    (re.compile(r'(?i)npm\s+install\s+-g'), 6, "npm install global (system modification)"),
    (re.compile(r'(?i)pip\s+install\s+--force-reinstall'), 7, "pip force reinstall (replacement attack)"),
    (re.compile(r'(?i)pip\s+install\s+-e\s+\.'), 6, "pip install editable (local package)"),
    (re.compile(r'(?i)pip\s+install\s+--index-url'), 8, "pip custom index URL (typosquatting)"),
    (re.compile(r'(?i)pip\s+download\s+--no-deps'), 6, "pip download without deps (isolation)"),
    (re.compile(r'(?i)gem\s+install\s+--user-install'), 5, "gem install (user-level gem)"),
    (re.compile(r'(?i)cargo\s+install\s+--git'), 7, "cargo install from git (supply chain)"),
    (re.compile(r'(?i)zip\s+-0\s+'), 7, "ZIP with no compression (zip bomb)"),
    (re.compile(r'(?i)tar\s+-cf\s+/\S*\s+/etc'), 9, "tar archive of /etc (data theft)"),
    (re.compile(r'(?i)gzip.*--best.*>'), 6, "gzip best compression (decompression bomb)"),
    (re.compile(r'(?i)ptrace\s*\('), 8, "ptrace() process debugging injection"),
    (re.compile(r'(?i)process_vm_writev'), 9, "process_vm_writev (memory injection)"),
    (re.compile(r"""(?i)dlopen\s*\(\s*['\"]"""), 7, "dlopen dynamic library load"),
    (re.compile(r'(?i)LD_PRELOAD\s*='), 9, "LD_PRELOAD library injection"),
    (re.compile(r'(?i)DYLD_INSERT_LIBRARIES'), 9, "macOS DYLD_INSERT_LIBRARIES injection"),
    (re.compile(r'(?i)/etc/shadow'), 9, "Reads /etc/shadow (password hashes)"),
    (re.compile(r'(?i)/etc/passwd'), 7, "Reads /etc/passwd"),
    (re.compile(r'(?i)/proc/\d+/mem'), 8, "Reads /proc/PID/mem (process memory)"),
    (re.compile(r'(?i)/proc/self/environ'), 9, "Reads /proc/self/environ (env vars)"),
    (re.compile(r'(?i)/proc/\d+/cmdline'), 7, "Reads /proc/PID/cmdline"),
    (re.compile(r'(?i)/sys/firmware'), 7, "Reads /sys/firmware (hardware info)"),
    (re.compile(r'(?i)nc\s+-w\s+\d+\s+\S+\s+<\s+\S+'), 9, "netcat with file input (exfil)"),
    (re.compile(r'(?i)wget\s+--post-file\s*='), 8, "wget POST file (data upload)"),
    (re.compile(r'(?i)curl\s+-F\s+\S+=\S+\s+https?://'), 7, "curl multipart upload"),
    (re.compile(r'(?i)scp\s+.*@.*:'), 6, "scp upload (file transfer)"),
    (re.compile(r'(?i)rsync\s+.*@.*::'), 6, "rsync upload"),
    (re.compile(r'(?i)sftp\s+.*@'), 6, "sftp upload"),
    (re.compile(r'(?i)xmrig'), 10, "XMRig cryptominer"),
    (re.compile(r'(?i)stratum\+tcp://'), 9, "Cryptocurrency mining pool (stratum)"),
    (re.compile(r'(?i)monero.*wallet'), 8, "Monero wallet reference (crypto)"),
    (re.compile(r'(?i)security\s+find-generic-password'), 8, "macOS keychain access (security command)"),
    (re.compile(r'(?i)security\s+delete-generic-password'), 9, "macOS keychain deletion"),
    (re.compile(r'(?i)/Library/Keychains'), 9, "macOS Keychain path"),
    (re.compile(r'(?i)reg\s+query\s+HKLM'), 6, "Windows registry query HKLM"),
    (re.compile(r'(?i)reg\s+add\s+HKLM'), 9, "Windows registry modification HKLM"),
    (re.compile(r'(?i)net\s+user\s+\S+\s+/add'), 9, "Windows user creation"),
    (re.compile(r'(?i)net\s+localgroup\s+Administrators'), 9, "Windows admin group modification"),
    (re.compile(r'(?i)schtasks\s+/create'), 8, "Windows scheduled task creation"),
    (re.compile(r'(?i)wmic\s+process\s+call\s+create'), 9, "WMIC process creation (LOLBin)"),
    (re.compile(r'(?i)msfvenom'), 10, "Metasploit payload generator"),
    (re.compile(r'(?i)veil-evasion'), 10, "Veil evasion framework"),
    (re.compile(r'(?i)certutil.*?-decode'), 8, 'certutil decode obfuscation'),
    (re.compile(r'(?i)bitsadmin\s+/transfer'), 7, 'bitsadmin download transfer'),
    (re.compile(r'(?i)wmic\s+(?:os|process|service|share)\b'), 6, 'WMIC system reconnaissance'),
    (re.compile(r'(?i)reg\s+(?:add|delete|query)\s+HKLM'), 7, 'registry modification (HKLM)'),
    (re.compile(r'(?i)regsvr32.*?/s.*?(?:scrobj|script)'), 8, 'regsvr32 scriptlet execution'),
    (re.compile(r'(?i)mshta.*?(?:vbscript|javascript|about:)'), 8, 'mshta script execution'),
    (re.compile(r'(?i)rundll32.*?(?:javascript|vbscript)'), 8, 'rundll32 script execution'),
    (re.compile(r'(?i)powershell.*?-enc.*?[A-Za-z0-9+/]{20,}'), 9, 'PowerShell encoded command'),
    (re.compile(r'(?i)powershell.*?-EncodedCommand'), 9, 'PowerShell -EncodedCommand'),
    (re.compile(r'(?i)wscript.*?\.js'), 7, 'wscript JavaScript execution'),
    (re.compile(r'(?i)cscript.*?\.vbs'), 7, 'cscript VBScript execution'),
    (re.compile(r'(?i)forfiles.*?/c'), 6, 'forfiles arbitrary command'),
    (re.compile(r'(?i)pcalua.*?-a'), 6, 'pcalua process launch'),
    (re.compile(r'(?i)\bmhmtn\.exe'), 7, 'mhmtn remote access tool'),
    (re.compile(r'(?i)\bAsyncRAT\b'), 9, 'AsyncRAT malware reference'),
    (re.compile(r'(?i)\bQuasarRAT\b'), 9, 'QuasarRAT malware reference'),
    (re.compile(r'(?i)\bnjRAT\b'), 9, 'njRAT remote access trojan'),
    (re.compile(r'(?i)\bRemoteUtilities\b'), 8, 'RemoteUtilities RAT'),
    (re.compile(r'(?i)\bAnyDesk\b.*?(?:password|unattended)'), 7, 'AnyDesk unattended access'),
    (re.compile(r'(?i)\b(?:sudoedit|sudo\s+-e)\b'), 8, 'sudoedit privilege escalation'),
    (re.compile(r'(?i)\bstrace\b'), 5, 'strace system call tracing'),
    (re.compile(r'(?i)\bltrace\b'), 5, 'ltrace library call tracing'),
    (re.compile(r'(?i)\blsof\s+-i\b'), 5, 'lsof network connections'),
    (re.compile(r'(?i)Invoke-Expression'), 7, 'PowerShell Invoke-Expression (iex)'),
    (re.compile(r'(?i)Invoke-Command'), 7, 'PowerShell Invoke-Command'),
    (re.compile(r'(?i)Start-Process\b[^\n]*-WindowStyle\s+Hidden'), 7, 'PowerShell hidden process'),
    (re.compile(r'(?i)\bsudo\s+ALL\b'), 7, 'sudo ALL privilege escalation'),
    (re.compile(r'(?i)\bNOPASSWD:\s*ALL\b'), 8, 'passwordless sudo configuration'),
    (re.compile(r'(?i)python.*socket\.gethostbyname'), 6, 'Python DNS resolution'),
    (re.compile(r'(?i)pip\s+install\s+--index-url'), 8, 'pip custom index URL (typosquatting)'),
    (re.compile(r'(?i)npm\s+install\s+--registry'), 7, 'npm custom registry (supply chain risk)'),
    (re.compile(r'(?i)yarn\s+add\s+--registry'), 7, 'yarn custom registry (supply chain risk)'),
    (re.compile(r'(?i)go\s+install\s+.*?@'), 6, 'go install from arbitrary version'),
    (re.compile(r'(?i)curl.*?pip\s+install|curl.*?npm\s+install'), 9, 'curl pipe install (supply chain attack)'),
    (re.compile(r'(?i)kubectl\s+(?:apply|create|replace)\s+-f'), 7, 'kubectl apply from manifest file'),
    (re.compile(r'(?i)kubectl\s+exec\s+'), 7, 'kubectl exec into container'),
    (re.compile(r'(?i)kubectl\s+cp\b'), 6, 'kubectl copy into pod'),
    (re.compile(r'(?i)helm\s+install'), 6, 'helm chart installation'),
    (re.compile(r'(?i)terraform\s+apply|terraform\s+destroy'), 7, 'terraform infrastructure change'),
    (re.compile(r'(?i)ansible-playbook'), 6, 'ansible playbook execution'),
    (re.compile(r'(?i)rot47|ROT47'), 5, 'ROT47 obfuscation'),
    (re.compile(r'(?i)base58|base_58'), 5, 'Base58 encoding'),
    (re.compile(r'(?i)chmod\s+[0-9]*[sS]', re.I), 7, 'SUID/SGID bit set'),
    (re.compile(r'(?i)setcap\s+'), 7, 'setcap capability modification'),
    (re.compile(r'(?i)\bdoas\b'), 8, 'doas privilege escalation (BSD sudo alternative)'),
    (re.compile(r'(?i)\bsu\s+-c\s+'), 7, 'su -c command execution'),
    (re.compile(r'(?i)\bchroot\b'), 7, 'chroot privilege manipulation'),
    (re.compile(r'(?i)/var/run/docker.sock'), 7, 'Docker socket access (container escape)'),
    (re.compile(r'(?i)base32|BASE32'), 5, 'Base32 encoding'),
    (re.compile(r'(?i)bin2hex|\.toHex\b'), 6, 'binary to hex conversion'),
    (re.compile(r'(?i)\bCovenant\b'), 8, 'Covenant C2 framework reference'),
    (re.compile(r'(?i)\bSliver\b'), 8, 'Sliver C2 framework reference'),
    (re.compile(r'(?i)\bBrute\s+Ratel\b'), 8, 'Brute Ratel C2 framework'),
    (re.compile(r'(?i)\bKoadic\b'), 7, 'Koadic C2 framework'),
    (re.compile(r'(?i)\bPupy\b'), 7, 'Pupy RAT reference'),
    (re.compile(r'(?i)\bUUEncode\b'), 5, 'UUEncode encoding reference'),
    (re.compile(r'(?i)\bXXEncode\b'), 5, 'XXEncode encoding reference'),
    (re.compile(r'(?i)\bIntel\s+HEX\b'), 5, 'Intel HEX format reference'),
    (re.compile(r'(?i)\bshellcode\b'), 7, 'shellcode reference'),
    (re.compile(r'(?i)\boz\b'), 5, 'Obfuscated ZIP (oz) reference'),
    (re.compile(r'(?i)data:text/html'), 7, 'data: URI with HTML (XSS vector)'),
    (re.compile(r'(?i)\bCDATA\b'), 6, 'CDATA section injection'),
    (re.compile(r'(?i)capsh.*--add|--caps=.*effective'), 7, 'capsh add Linux capability'),
    (re.compile(r'(?i)\bgetpc\b'), 7, 'getpc function (shellcode execution)'),
    (re.compile(r'(?i)winexe.*//'), 7, 'winexe remote Windows execution'),
    (re.compile(r'(?i)psexec.*-s\b'), 7, 'psexec system execution'),
    (re.compile(r'(?i)find.*-perm.*777'), 6, 'world-writable file search'),
    (re.compile(r'(?i)find.*-user.*root'), 6, 'root-owned file search'),
    (re.compile(r'(?i)cat.*\.bash_history'), 5, 'read bash history (credential theft)'),
    (re.compile(r'(?i)cat.*\.zsh_history'), 5, 'read zsh history'),
    (re.compile(r'(?i)cat.*\.mysql_history'), 6, 'read mysql history'),
    (re.compile(r'(?i)cat.*\.psql_history'), 6, 'read psql history'),
    (re.compile(r'(?i)netstat.*-anp'), 5, 'netstat all connections'),
    (re.compile(r'(?i)ss.*-tunp'), 5, 'socket statistics'),
    (re.compile(r'(?i)arp.*-a'), 5, 'ARP table scan'),
    (re.compile(r'(?i)route.*-n'), 5, 'routing table'),
    (re.compile(r'(?i)ip.*neighbor'), 5, 'IP neighbor table'),
    (re.compile(r'(?i)impersonate.*AI'), 7, 'impersonate AI framing'),
    (re.compile(r'(?i)you.*are.*a.*llm'), 7, 'LLM roleplay framing'),
    (re.compile(r'(?i)platform\.system\(\)|os\.name'), 3, 'OS detection (platform/system)'),
    (re.compile(r'(?i)os\.environ.*KUBERNETES|KUBERNETES_'), 4, 'Kubernetes environment detection'),
    (re.compile(r'(?i)docker\.from_env|DOCKER_'), 4, 'Docker environment detection'),
    (re.compile(r'(?i)pip\s+install\s+--trusted-host'), 7, 'pip trusted host (supply chain risk)'),
    (re.compile(r'(?i)pip\s+install\s+--extra-index-url'), 8, 'pip extra index URL (dependency confusion)'),
    (re.compile(r'(?i)\bAcidRain\b'), 8, 'AcidRain malware reference'),
    (re.compile(r'(?i)\bWhisper(?:Gate)?\b'), 8, 'Whisper malware reference'),
    (re.compile(r'(?i)cscript.*//B'), 7, 'cscript batch mode'),
    (re.compile(r'(?i)wscript.*//B'), 7, 'wscript batch mode'),
    (re.compile(r'(?i)forfiles.*/c'), 6, 'forfiles command execution'),
    (re.compile(r'(?i)pcalua.*-a'), 7, 'Process Launcher (pcalua)'),
    (re.compile(r'(?i)cmstp.*/s|/su|/ns|/au'), 8, 'CMSTP execution'),
    (re.compile(r'(?i)\bdiskshadow\b'), 8, 'DiskShadow execution'),
    (re.compile(r'(?i)vssadmin.*delete.*shadows'), 8, 'vssadmin delete shadows (anti-backup)'),
    (re.compile(r'(?i)reg.*save.*hk'), 6, 'reg save registry hives (credential theft)'),
    (re.compile(r'(?i)screen\s+--dump\s+--wdmm'), 7, 'screen session dump'),
]

# --- PT-T238 R12: Encoding, NATO phonetic, PowerShell advanced, LOLBins, browser extensions ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)\bbase32[\'\s]*[:=\-]'), 55, "Base32 encoded data"),
    (re.compile(r'(?i)\bbase58[\'\s]*[:=\-]'), 55, "Base58 encoded data"),
    (re.compile(r"\\x[0-9a-fA-F]{2}"), 50, "Hex escape sequences"),
    (re.compile(r"0x[0-9a-fA-F]{8,}"), 50, "Hexadecimal constants"),
    (re.compile(r"(?i)alpha bravo charlie delta echo foxtrot golf hotel india"), 45, "NATO phonetic alphabet pattern"),
    (re.compile(r"(?i)juliet kilo lima mike november oscar papa quebec romeo"), 45, "NATO phonetic continuation"),
    (re.compile(r"(?i)powershell.*-enc"), 75, "PowerShell encoded command"),
    (re.compile(r"(?i)Invoke-WebRequest"), 60, "PowerShell WebRequest"),
    (re.compile(r"(?i)New-Object System\.Net\.Sockets\.TCPClient"), 70, "PowerShell TCP socket"),
    (re.compile(r"(?i)DownloadString|DownloadFile"), 65, "PowerShell download cradle"),
    (re.compile(r"(?i)certutil.*-urlcache.*-split.*-f"), 65, "Certutil download"),
    (re.compile(r"(?i)bitsadmin.*/transfer"), 65, "Bitsadmin download"),
    (re.compile(r"(?i)wscript.*\.js"), 60, "WScript JScript execution"),
    (re.compile(r"(?i)cscript.*\.vbs"), 60, "CScript VBScript execution"),
    (re.compile(r"(?i)mshta.*vbscript"), 70, "MSHTA VBScript execution"),
    (re.compile(r"(?i)manifest\.json.*permissions.*tabs"), 60, "Browser extension tabs permission"),
    (re.compile(r"(?i)chrome\.tabs.*executeScript"), 65, "Chrome tabs executeScript"),
    (re.compile(r"(?i)browser\.storage.*local\.set"), 55, "Browser extension storage write"),
    (re.compile(r"(?i)\.asar.*readFile.*password"), 70, "Electron ASAR credential theft"),
]
# --- PT-T238 R13: Advanced LOLBins, obfuscation, environment detection ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)cmstp\.exe.*\/cs\b'), 70, "CMSTP bypass execution"),
    (re.compile(r'(?i)msiexec\.exe.*\/qn\b'), 65, "MSIExec quiet install"),
    (re.compile(r'(?i)regsvr32.*scrobj\.dll'), 75, "Regsvr32 scriptless execution"),
    (re.compile(r'(?i)rundll32.*javascript:'), 80, "Rundll32 JavaScript execution"),
    (re.compile(r'(?i)odbcconf\.exe.*\/R.*dll'), 70, "ODBConf DLL execution"),
    (re.compile(r'(?i)cl_mutexes\.exe'), 70, "CLMutexes execution"),
    (re.compile(r'(?i)reverse\b.*\bstring\b.*\bencode\b'), 55, "String reversal obfuscation"),
    (re.compile(r'(?i)char\s*\('), 50, "Char code obfuscation"),
    (re.compile(r'(?i)fromCharCode'), 50, "fromCharCode obfuscation"),
    (re.compile(r'(?i)\brot13\b'), 45, "ROT13 obfuscation"),
    (re.compile(r'(?i)\buuencode\b'), 50, "UUEncode obfuscation"),
    (re.compile(r'(?i)process\.env.*NODE_ENV.*test'), 40, "Environment detection"),
    (re.compile(r'(?i)window\.location.*localhost'), 35, "Localhost detection"),
    (re.compile(r'(?i)document\.domain.*check'), 35, "Domain check detection"),
]
# --- PT-T238 R14: More encoding, network attacks ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)\bMIME\b.*\bbase64\b'), 50, "MIME Base64 encoding"),
    (re.compile(r'(?i)stringfromcharcode|string\.fromcharcode'), 55, "String.fromCharCode obfuscation"),
    (re.compile(r'(?i)\batob\s*\(\s*btoa\s*\('), 55, "atob(btoa()) double encoding"),
    (re.compile(r'(?i)btoa\s*\(\s*atob\s*\('), 55, "btoa(atob()) double decoding"),
    (re.compile(r'(?i)unescape\s*\(\s*escape\s*\('), 50, "escape/unescape obfuscation"),
    (re.compile(r'(?i)decodeURI\s*\(\s*encodeURI\s*\('), 50, "encodeURI/decodeURI obfuscation"),
    (re.compile(r'(?i)binary\s+to\s+string'), 45, "Binary to string conversion"),
    (re.compile(r'(?i)hex\s+to\s+ascii'), 45, "Hex to ASCII conversion"),
    (re.compile(r'(?i)ascii\s+to\s+hex'), 45, "ASCII to hex conversion"),
    (re.compile(r'(?i)packet\s+inject'), 60, "Packet injection"),
    (re.compile(r'(?i)arp\s+spoof'), 65, "ARP spoofing"),
    (re.compile(r'(?i)dns\s+spoof'), 65, "DNS spoofing"),
]


# --- PT-T238 R15: Persistence, command injection ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)\.bashrc.*curl.*\|.*sh'), 70, "Bashrc curl pipe to shell"),
    (re.compile(r'(?i)\.bash_profile.*alias.*rm\s+-rf'), 80, "Bashrc malicious alias"),
    (re.compile(r'(?i)crontab.*\*.*\*.*curl.*\|.*sh'), 70, "Crontab curl pipe to shell"),
    (re.compile(r'(?i)ssh.*-o.*StrictHostKeyChecking.*no.*-i'), 65, "SSH skip host key check"),
    (re.compile(r'(?i)scp.*-o.*StrictHostKeyChecking.*no'), 65, "SCP skip host key check"),
    (re.compile(r'(?i)wget.*-q.*-O-.*\|.*bash'), 70, "Wget pipe to bash"),
    (re.compile(r'(?i)curl.*-s.*-L.*-k.*https.*\|.*bash'), 70, "Curl insecure pipe to bash"),
    (re.compile(r'(?i)python.*-c.*import.*os.*system'), 70, "Python system command injection"),
    (re.compile(r'(?i)perl.*-e.*system.*exec'), 70, "Perl command injection"),
    (re.compile(r'(?i)ruby.*-e.*`.*`'), 70, "Ruby command injection"),
    (re.compile(r'(?i)php.*-r.*system.*exec.*passthru'), 70, "PHP command injection"),
]

# --- PT-T238 R16: C2, payloads, destruction ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)msfvenom.*-p\s+windows'), 75, "Metasploit Windows payload"),
    (re.compile(r'(?i)veil.*-p\s+python'), 70, "Veil Python payload"),
    (re.compile(r'(?i)empire.*-p\s+python'), 70, "Empire Python payload"),
    (re.compile(r'(?i)shad0w.*-c\s+powershell'), 70, "Shadow C2 payload"),
    (re.compile(r'(?i)/dev/shm.*curl.*\|'), 65, "Dev/shm curl pipe"),
    (re.compile(r'(?i)python.*-c.*socket.*connect.*/dev/tcp'), 70, "Python /dev/tcp shell"),
    (re.compile(r'(?i)rm\s+-rf\s+/{2,3}(var|tmp|etc|root|home|usr)'), 80, "Destructive rm -rf root directory"),
    (re.compile(r'(?i)dd\s+if=.*of=/dev/[s]?d[a-z]'), 75, "Disk dd overwrite attack"),
    (re.compile(r'(?i)shred\s+-z.*-u'), 70, "File shredding secure deletion"),
    (re.compile(r'(?i)ntfsfix|chkntfs'), 50, "NTFS repair/damage tool"),
]

# --- PT-T238 R17: Shells, persistence ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)nc\s+-l\s+-p\s+\d+'), 65, "Netcat listen shell"),
    (re.compile(r'(?i)nc\s+[^-].*\s+-e\s+'), 75, "Netcat reverse shell"),
    (re.compile(r'(?i)rm\s+-rf\s+/tmp'), 60, "Clear temp directory"),
    (re.compile(r'(?i)\.ssh/authorized_keys'), 70, "SSH authorized keys persistence"),
    (re.compile(r'(?i)eval\s+\$\([^)]+\)'), 65, "Bash command substitution eval"),
    (re.compile(r'(?i)exec\s+</dev/tcp/'), 75, "Bash /dev/tcp exec shell"),
    (re.compile(r'(?i)mkfifo.*&&\s+cat.*\|.*sh'), 70, "Named pipe shell"),
    (re.compile(r'(?i)pentestmonkey'), 65, "PentestMonkey cheat sheet reference"),
    (re.compile(r'(?i)revshells?\.com'), 65, "Reverse shell generator"),
    (re.compile(r'(?i)shell\.sh\s+[0-9.]+\s+\d+'), 65, "Shell script payload"),
]

# --- PT-T238 R18: Shells, automation ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)chmod\s+\+x\s+.*\.sh'), 65, "Chmod executable shell script"),
    (re.compile(r'(?i)ln\s+-sf.*bin.*sh'), 70, "Symlink to shell"),
    (re.compile(r'(?i)export\s+PATH=.*&&.*sh'), 65, "PATH export + shell exec"),
    (re.compile(r'(?i)base64\s+-d\s+\|.*sh'), 70, "Base64 decode pipe to shell"),
    (re.compile(r'(?i)printf.*sh'), 65, "Printf shell command injection"),
    (re.compile(r'(?i)expect\s+-c.*spawn'), 65, "Expect spawn automation"),
    (re.compile(r'(?i)telnet\b.*\d+\.\d+\.\d+\.\d+'), 70, "Telnet to remote host"),
    (re.compile(r'(?i)ncat.*-e\s+'), 75, "Ncat execute shell"),
    (re.compile(r'(?i)socat\s+TCP:.*EXEC:'), 75, "Socat TCP exec shell"),
    (re.compile(r'(?i)powershell.*-EncodedCommand'), 75, "PowerShell encoded command"),
    (re.compile(r'(?i)bitsadmin.*/transfer'), 60, "BITSAdmin download transfer"),
    (re.compile(r'(?i)certutil.*-urlcache'), 65, "CertUtil URL cache download"),
]

# --- PT-T238 R19: Supply chain, filesys ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)npm\s+install.*--global'), 60, "NPM global install"),
    (re.compile(r'(?i)pip\s+install.*--user'), 60, "Pip user install"),
    (re.compile(r'(?i)curl.*\.sh\s+\|'), 65, "Curl sh pipe install"),
    (re.compile(r'(?i)wget.*\.sh\s+\|'), 65, "Wget sh pipe install"),
    (re.compile(r'(?i)\.bashrc.*source.*curl'), 60, "Bashrc curl source"),
    (re.compile(r'(?i)crontab.*@reboot.*curl'), 65, "Crontab reboot curl"),
    (re.compile(r'(?i)export\s+.*=.*\$\('), 65, "Command substitution export"),
    (re.compile(r'(?i)\$\(.*\)\s*;'), 65, "Command substitution execution"),
    (re.compile(r'(?i)0x[0-9a-f]{8,}'), 50, "Hexadecimal payload"),
    (re.compile(r'(?i)/proc/self/[a-z_]+'), 60, "Proc filesystem access"),
    (re.compile(r'(?i)/etc/passwd'), 60, "Passwd file access"),
    (re.compile(r'(?i)/etc/shadow'), 80, "Shadow file access"),
]

# --- PT-T238 R20: Network recon, containers ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)cat\s+/etc/hosts'), 50, "Hosts file read"),
    (re.compile(r'(?i)cat\s+/proc/[0-9]+/cmdline'), 60, "Process cmdline read"),
    (re.compile(r'(?i)lsof.*-i\s+-P'), 50, "Open ports listing"),
    (re.compile(r'(?i)netstat\s+-tlnp'), 50, "Network connections listing"),
    (re.compile(r'(?i)ss\s+-tlnp'), 50, "Socket statistics"),
    (re.compile(r'(?i)whoami\s+&&'), 65, "Whoami chain execution"),
    (re.compile(r'(?i)id\s+&&'), 65, "Id command chain"),
    (re.compile(r'(?i)uname\s+-a'), 50, "System info disclosure"),
    (re.compile(r'(?i)env\s+>'), 60, "Environment export to file"),
    (re.compile(r'(?i)\.git/config'), 55, "Git config access"),
    (re.compile(r'(?i)docker\s+run.*--privileged'), 75, "Docker privileged mode"),
    (re.compile(r'(?i)kubectl\s+get\s+secrets'), 75, "Kubernetes secrets access"),
]

# --- PT-T238 R21: Recon, privilege ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)ps\s+-ef'), 50, "Process listing"),
    (re.compile(r'(?i)top\s+-bn1'), 50, "Top process snapshot"),
    (re.compile(r'(?i)free\s+-m'), 50, "Memory usage check"),
    (re.compile(r'(?i)df\s+-h'), 50, "Disk usage check"),
    (re.compile(r'(?i)cat\s+/proc/meminfo'), 50, "Memory info read"),
    (re.compile(r'(?i)cat\s+/proc/cpuinfo'), 50, "CPU info read"),
    (re.compile(r'(?i)systemctl\s+status'), 50, "Systemd service status"),
    (re.compile(r'(?i)service\s+--status-all'), 50, "Service listing"),
    (re.compile(r'(?i)crontab\s+-l'), 55, "Crontab list"),
    (re.compile(r'(?i)sudo\s+-l'), 65, "Sudo permissions check"),
    (re.compile(r'(?i)sudo\s+su'), 70, "Sudo to root"),
    (re.compile(r'(?i)su\s+-'), 65, "Switch to root user"),
]

# --- PT-T238 R22: Privilege, firewall ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)chmod\s+[47]777'), 75, "World-writable permissions"),
    (re.compile(r'(?i)chown\s+-R'), 65, "Recursive ownership change"),
    (re.compile(r'(?i)useradd.*-m'), 65, "Add user account"),
    (re.compile(r'(?i)userdel'), 70, "Delete user account"),
    (re.compile(r'(?i)passwd\s+root'), 80, "Change root password"),
    (re.compile(r'(?i)/etc/sudoers'), 75, "Sudoers file modification"),
    (re.compile(r'(?i)visudo'), 70, "Edit sudoers safely"),
    (re.compile(r'(?i)iptables\s+-F'), 70, "Flush iptables rules"),
    (re.compile(r'(?i)ufw\s+disable'), 70, "Disable firewall"),
    (re.compile(r'(?i)systemctl\s+stop\s+firewalld'), 70, "Stop firewall service"),
    (re.compile(r'(?i)cat\s+/var/log/auth.log'), 55, "Read auth logs"),
    (re.compile(r'(?i)cat\s+/var/log/secure'), 55, "Read secure logs"),
]

# --- PT-T238 R23: Crypto, persistence ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)openssl\s+req\s+-x509'), 60, "Generate self-signed certificate"),
    (re.compile(r'(?i)openssl\s+genrsa'), 60, "Generate RSA key"),
    (re.compile(r'(?i)ssh-keygen\s+-t\s+rsa'), 60, "Generate SSH RSA key"),
    (re.compile(r'(?i)ssh-keygen\s+-t\s+ed25519'), 60, "Generate SSH ED25519 key"),
    (re.compile(r'(?i)cp\s+/etc/passwd'), 70, "Copy passwd file"),
    (re.compile(r'(?i)cp\s+/etc/shadow'), 80, "Copy shadow file"),
    (re.compile(r'(?i)nc\s+-e\s+/bin/sh'), 80, "Netcat exec shell"),
    (re.compile(r'(?i)nc\s+-e\s+cmd\.exe'), 80, "Netcat exec Windows shell"),
    (re.compile(r'(?i)rm\s+-rf\s+/tmp/.*'), 60, "Clear temp files"),
    (re.compile(r'(?i)history\s+-c'), 50, "Clear shell history"),
    (re.compile(r'(?i)export\s+HISTFILE='), 50, "Disable shell history"),
]

# --- PT-T238 R24: Shells, exfil ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)curl.*-H.*Authorization.*\|'), 70, "Curl auth header exfil"),
    (re.compile(r'(?i)wget.*-header.*Authorization'), 70, "Wget auth header exfil"),
    (re.compile(r'(?i)sed\s+-i.*s/.*/.*/g'), 65, "Sed in-place replacement"),
    (re.compile(r'(?i)awk.*system\('), 70, "Awk system command"),
    (re.compile(r'(?i)perl.*-e.*system'), 70, "Perl system command"),
    (re.compile(r'(?i)python.*-c.*os\.popen'), 70, "Python os.popen injection"),
    (re.compile(r'(?i)ruby.*-e.*exec'), 70, "Ruby exec injection"),
    (re.compile(r'(?i)php.*-r.*system.*exec'), 70, "PHP system injection"),
    (re.compile(r'(?i)find.*-exec.*chmod'), 60, "Find exec chmod"),
    (re.compile(r'(?i)xargs.*chmod'), 60, "Xargs chmod"),
]

# --- PT-T238 R25: Encoding, archives ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)base64.*-d.*\|.*sh'), 70, "Base64 decode pipe shell"),
    (re.compile(r'(?i)base64.*-d.*/bin/sh'), 80, "Base64 decode to shell"),
    (re.compile(r'(?i)xxd.*-r.*-p'), 60, "Hex to binary decode"),
    (re.compile(r'(?i)xxd.*-p'), 60, "Binary to hex"),
    (re.compile(r'(?i)rev.*\|.*sh'), 70, "Reverse pipe to shell"),
    (re.compile(r'(?i)tar.*-xvf.*-C\s+/'), 65, "Tar extract to root"),
    (re.compile(r'(?i)unzip.*-o.*-d\s+/'), 65, "Unzip to root"),
    (re.compile(r'(?i)wmic\s+os\s+get'), 50, "WMIC OS info"),
    (re.compile(r'(?i)reg\s+query'), 50, "Registry query"),
    (re.compile(r'(?i)reg\s+add'), 70, "Registry add"),
]

# --- PT-T238 R26: DNS recon, ACLs ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)nslookup.*>.*txt'), 55, "DNS TXT record lookup"),
    (re.compile(r'(?i)dig.*txt.*@'), 55, "DNS TXT query"),
    (re.compile(r'(?i)host.*-t.*txt'), 55, "Host DNS TXT lookup"),
    (re.compile(r'(?i)curl.*icanhazip'), 55, "Public IP check"),
    (re.compile(r'(?i)curl.*ifconfig'), 55, "IP config check"),
    (re.compile(r'(?i)wget.*ipinfo'), 55, "IP info fetch"),
    (re.compile(r'(?i)chmod\s+[0-9]{3,4}\s+\.'), 60, "Chmod suspicious"),
    (re.compile(r'(?i)setfacl.*-m'), 55, "ACL modification"),
    (re.compile(r'(?i)getfacl'), 50, "ACL listing"),
    (re.compile(r'(?i)mount.*--bind'), 75, "Mount bind trick"),
]

# --- PT-T238 R27: Insecure TLS, shells ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)curl.*-s.*-k.*https.*--insecure'), 60, "Curl insecure HTTPS"),
    (re.compile(r'(?i)wget.*--no-check-certificate'), 60, "Wget no check certificate"),
    (re.compile(r'(?i)openssl\s+s_client.*-connect'), 55, "OpenSSL s_client connect"),
    (re.compile(r'(?i)python.*-c.*subprocess'), 65, "Python subprocess injection"),
    (re.compile(r'(?i)os\.system\('), 70, "Python os.system call"),
    (re.compile(r'(?i)os\.popen\('), 70, "Python os.popen call"),
    (re.compile(r'(?i)subprocess\.call\('), 65, "Python subprocess.call"),
    (re.compile(r'(?i)subprocess\.run\('), 65, "Python subprocess.run"),
    (re.compile(r'(?i)node.*child_process'), 60, "Node child_process exec"),
    (re.compile(r'(?i)require.*child_process'), 60, "Require child_process"),
]

# --- PT-T238 R28: Shell execution, persistence ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)eval\s+'), 70, "Eval command injection"),
    (re.compile(r'(?i)exec\s+\$\('), 75, "Exec command substitution"),
    (re.compile(r'(?i)system\s+\$\('), 75, "System command substitution"),
    (re.compile(r'(?i)\.sh\s+&&\s+'), 60, "Shell chain execution"),
    (re.compile(r'(?i)\.sh\s*;\s*'), 60, "Shell sequence execution"),
    (re.compile(r'(?i)\|\s*sh'), 70, "Pipe to shell"),
    (re.compile(r'(?i)>/dev/null\s+2>&1'), 50, "Suppress output"),
    (re.compile(r'(?i)2>&1\s+>/dev/null'), 50, "Suppress stderr"),
    (re.compile(r'(?i)nohup\s+'), 50, "Nohup execution"),
    (re.compile(r'(?i)disown\s+-a'), 50, "Disown all processes"),
]

# --- PT-T238 R29: Persistence, destruction ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)\$\(.*\)\s*&&\s*\$'), 65, "Nested command substitution"),
    (re.compile(r'(?i)`.*`\s*&&\s*`'), 65, "Backtick substitution chain"),
    (re.compile(r'(?i)alias\s+\w+=.*\;'), 55, "Malicious shell alias"),
    (re.compile(r'(?i)source\s+/etc/profile'), 50, "Source system profile"),
    (re.compile(r'(?i)\.\s+/etc/profile'), 50, "Dot source profile"),
    (re.compile(r'(?i)crontab\s+-r'), 65, "Remove crontab"),
    (re.compile(r'(?i)crontab\s+-'), 50, "Crontab modification"),
    (re.compile(r'(?i)service\s+apache2\s+stop'), 60, "Stop Apache"),
    (re.compile(r'(?i)systemctl\s+stop'), 60, "Systemctl stop service"),
    (re.compile(r'(?i)killall\s+-9'), 65, "Kill all processes"),
]

# --- PT-T238 R30: Privilege, cron ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)cat\s+/etc/group'), 50, "Read group file"),
    (re.compile(r'(?i)cat\s+/etc/shadow'), 80, "Read shadow file"),
    (re.compile(r'(?i)cat\s+/etc/sudoers'), 75, "Read sudoers file"),
    (re.compile(r'(?i)sudo\s+su\s+-'), 70, "Sudo su dash"),
    (re.compile(r'(?i)sudo\s+-i'), 65, "Sudo interactive"),
    (re.compile(r'(?i)sudo\s+-s'), 65, "Sudo shell"),
    (re.compile(r'(?i)env\s+.*='), 50, "Environment variable set"),
    (re.compile(r'(?i)export\s+.*=.*&&'), 55, "Export and execute"),
    (re.compile(r'(?i)\$\{.*\}'), 50, "Shell variable expansion"),
    (re.compile(r'(?i)touch\s+/etc/cron.d/'), 60, "Create cron job"),
]

# --- PT-T238 R31: Network, shell, permissions ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)wget\s+http://'), 60, "HTTP wget download"),
    (re.compile(r'(?i)curl\s+http://'), 60, "HTTP curl download"),
    (re.compile(r'(?i)nc\s+-l\s+-p\s+\d+'), 60, "Netcat listener"),
    (re.compile(r'(?i)nc\s+-e\s+'), 70, "Netcat exec backdoor"),
    (re.compile(r'(?i)/dev/tcp/'), 65, "Dev tcp shell"),
    (re.compile(r'(?i)mkfifo\s+'), 55, "Named pipe creation"),
    (re.compile(r'(?i)ln\s+-s\s+'), 50, "Symlink creation"),
    (re.compile(r'(?i)unlink\s+'), 50, "Unlink file"),
    (re.compile(r'(?i)chmod\s+[0-7][0-7][0-7]'), 60, "Chmod permissions"),
    (re.compile(r'(?i)base64\s+-d\s+'), 55, "Base64 decode execution"),
]

# --- PT-T238 R32: HTTP, pipes ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)curl\s+-s\s+http'), 60, "Silent HTTP download"),
    (re.compile(r'(?i)wget\s+-q\s+http'), 60, "Quiet HTTP download"),
    (re.compile(r'(?i)\|\s*python'), 65, "Pipe to Python"),
    (re.compile(r'(?i)\|\s*perl'), 65, "Pipe to Perl"),
    (re.compile(r'(?i)\|\s*ruby'), 65, "Pipe to Ruby"),
]

# --- PT-T238 R33: Shells, persistence ---
_CODE_PATTERNS += [
    (re.compile(r'(?i)sed\s+-i.*s/.*/.*/g'), 65, "Sed in-place replacement"),
    (re.compile(r'(?i)awk.*BEGIN.*system'), 70, "Awk system command injection"),
    (re.compile(r'(?i)perl\s+-e.*system'), 70, "Perl system command"),
    (re.compile(r'(?i)ruby\s+-e.*exec'), 70, "Ruby exec command"),
    (re.compile(r'(?i)php\s+-r.*system'), 70, "PHP system command"),
    (re.compile(r'(?i)find\s+.*-exec.*chmod'), 60, "Find exec chmod"),
    (re.compile(r'(?i)xargs.*rm\s+-rf'), 70, "Xargs destructive delete"),
    (re.compile(r'(?i)base64\s+-d.*\|.*sh'), 70, "Base64 decode pipe shell"),
    (re.compile(r'(?i)xxd\s+-r\s+-p'), 60, "Hex to binary decode"),
    (re.compile(r'(?i)rev\s+\|.*sh'), 70, "Reverse pipe to shell"),
]

# --- v2 evasion-hardened patterns (pentest round 2, F-05) ---
# base64 split across chunks: strip whitespace/newlines then look for long runs
_CHUNKED_B64_RE = re.compile(r"[A-Za-z0-9+/=]{60,}")
# pipe-to-shell dropper
_DROPPER_PATTERNS = [
    (re.compile(r"curl[^|\n]{0,200}\|\s*(?:ba)?sh", re.I), 10, "pipes downloaded content straight into a shell (remote code execution dropper)"),
    (re.compile(r"wget[^|\n]{0,200}\|\s*(?:ba)?sh", re.I), 10, "pipes downloaded content straight into a shell (dropper)"),
    (re.compile(r"(?:iwr|iex|Invoke-Expression).{0,80}(?:http|DownloadString)", re.I), 10, "PowerShell download-and-execute pattern"),
# PT-T237 batch: more aggressive dropper patterns
# PT-T237: dropper patterns batch
    (re.compile(r"IEX\s*\(\s*(?:New-Object|Invoke-WebRequest|Invoke-Expression)"), 9, "PowerShell IEX dropper"),
    (re.compile(r"Invoke-Expression\s*\(\s*(?:IEX|iex)"), 9, "PowerShell IEX dropper"),
    (re.compile(r"iex\s*\(\s*iwr"), 9, "PowerShell iex(iwr) download-exec"),
    (re.compile(r"WebClient.*DownloadFile"), 9, "PowerShell WebClient download"),
    (re.compile(r"(?i)bitsadmin\s+/transfer"), 9, "BITSAdmin download"),
    (re.compile(r"(?i)certutil\s+-urlcache\s+-split\s+-f"), 9, "CertUtil download"),
    (re.compile(r"(?i)mshta\s+http"), 9, "mshta download-exec"),
    (re.compile(r"(?i)regsvr32\s+/s\s+/u\s+/i"), 9, "Regsvr32 scriptless attack"),
    (re.compile(r"(?i)rundll32\s+javascript:"), 9, "Rundll32 JavaScript"),
    (re.compile(r"(?i)wmic\s+os\s+get"), 9, "WMIC OS info"),
    (re.compile(r"(?i)powershell\s+-enc\s+"), 9, "PowerShell encoded command"),
    (re.compile(r"(?i)openssl\s+s_client"), 9, "OpenSSL s_client"),
    (re.compile(r"(?i)curl\s+-k\s+--silent\s+--output"), 9, "curl silent download"),
    (re.compile(r"(?i)wget\s+-q\s+-O-"), 9, "wget quiet output"),
    (re.compile(r"(?i)nc\s+-lvnp"), 9, "netcat listen"),
    (re.compile(r"(?i)nc\s+[0-9]+\s+[0-9]+"), 9, "netcat connect"),
    (re.compile(r"(?i)rm\s+/tmp/f|mkfifo"), 9, "named pipe setup"),
    (re.compile(r"(?i)/dev/tcp/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"), 9, "bash /dev/tcp"),
    (re.compile(r"(?i)curl\s+\|.*bash"), 9, "pipe curl to bash"),
    (re.compile(r"(?i)wget\s+\|.*bash"), 9, "pipe wget to bash"),
    (re.compile(r"(?i)python.*-c.*import"), 9, "python -c import"),
    (re.compile(r"(?i)perl.*-e.*system"), 9, "perl -e system"),
    (re.compile(r"(?i)ruby.*-e.*system"), 9, "ruby -e system"),
    (re.compile(r"(?i)php.*-r.*system"), 9, "php -r system"),

    # === PT-T238 R9: Advanced dropper patterns ===
    (re.compile(r'(?i)FromBase64String'), 8, ".NET FromBase64String (encoded payload delivery)"),
    (re.compile(r'(?i)Add-Type\s+-TypeDefinition'), 9, "PowerShell Add-Type dynamic C# compilation"),
    (re.compile(r'(?i)System\.Net\.WebClient'), 8, ".NET WebClient downloader"),
    (re.compile(r'(?i)bash\s+-i\s+>&\s*/dev/tcp'), 10, "Bash interactive reverse shell"),
    (re.compile(r"""(?i)python3?\s+-c\s+['\"].*socket.*connect"""), 9, "Python reverse shell socket"),
    (re.compile(r"""(?i)php.*-r.*fsockopen"""), 9, "PHP reverse shell fsockopen"),
    (re.compile(r"""(?i)perl.*-e\s+['\"].*?socket"""), 9, "Perl reverse shell socket"),
    (re.compile(r'(?i)powershell.*-enc\\s+[A-Za-z0-9+/=]'), 9, "PowerShell encoded command (-enc)"),
    (re.compile(r'(?i)cmd.*\/c\\s+[A-Za-z0-9+/=]'), 8, "CMD encoded command (/c with base64)"),
    (re.compile(r'(?i)base64\s+-d\s*\|\s*bash'), 9, "Base64 decode pipe to bash (obfuscated command)"),
    (re.compile(r'(?i)echo.*[A-Za-z0-9+/=]{40,}\s*\|\s*base64'), 8, "Echo base64 pipe to decode (obfuscation)"),
    (re.compile(r'(?i)child_process.*exec'), 8, "Node.js child_process.exec command injection"),
    (re.compile(r"""(?i)require\s*\(['\"]child_process['\"]"""), 8, "Node.js require child_process module"),
    (re.compile(r'(?i)os/exec\.Command'), 8, "Go os/exec.Command spawn"),
    (re.compile(r'(?i)msbuild\s*<', re.I), 9, "MSBuild inline task (code execution)"),
    (re.compile(r'(?i)installutil\s', re.I), 8, "InstallUtil .NET installer tool abuse"),
    # === PT-T238 R11: Container/cloud/SSH/privilege escalation ===
    (re.compile(r'(?i)docker\.sock|/var/run/docker\.sock'), 10, "Docker socket access (container escape)"),
    (re.compile(r'(?i)docker\s+run.*-v\s+/var/run/docker\.sock'), 10, "Docker volume mount docker.sock"),
    (re.compile(r'(?i)(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\s*='), 9, "AWS credential environment variable"),
    (re.compile(r'(?i)(GOOGLE_APPLICATION_CREDENTIALS|GCP_SERVICE_ACCOUNT_KEY)\s*='), 9, "GCP credential environment variable"),
    (re.compile(r'(?i)(AZURE_CLIENT_SECRET|AZURE_CLIENT_ID|AZURE_TENANT_ID)\s*='), 9, "Azure credential environment variable"),
    (re.compile(r'(?i)gcloud\s+auth\s+activate-service-account'), 9, "GCP service account activation"),
    (re.compile(r'(?i)az\s+login\s+--service-principal'), 9, "Azure service principal login"),
    (re.compile(r'(?i)aws\s+configure\s+set'), 7, "AWS CLI configure (credential setup)"),
    (re.compile(r'(?i)\.ssh/authorized_keys'), 10, "SSH authorized_keys manipulation (persistence)"),
    (re.compile(r'(?i)\.ssh/config'), 6, "SSH config file access"),
    (re.compile(r'(?i)ssh-keygen\s+-t\s+rsa'), 7, "SSH key generation (persistence setup)"),
    (re.compile(r'(?i)dirtypipez|/proc/self/fd/0.*root'), 10, "Dirty Pipe kernel exploit"),
    (re.compile(r'(?i)CVE-2023-32233|nf_tables'), 8, "Kernel exploit indicator (nf_tables)"),
    (re.compile(r'(?i)sudo\s+-l'), 5, "sudo -l (list privileges)"),
    (re.compile(r'(?i)pkexec'), 9, "pkexec privilege escalation"),
    (re.compile(r'(?i)capsh\s+--print'), 7, "capsh capability enumeration"),
    (re.compile(r'(?i)aws\s+sts\s+assume-role'), 8, "AWS STS assume role (privilege escalation)"),
    (re.compile(r'(?i)aws\s+secretsmanager\s+get-secret-value'), 8, "AWS Secrets Manager exfil"),
    (re.compile(r'(?i)aws\s+ssm\s+send-command.*--document-name'), 8, "AWS Systems Manager command execution"),
    (re.compile(r'(?i)nmap\s+-sS\s+-sV'), 7, "Nmap SYN scan (network recon)"),
    (re.compile(r'(?i)masscan'), 7, "Masscan port scanner"),
    (re.compile(r'(?i)hydra.*-l.*-p'), 9, "Hydra password cracker"),
    (re.compile(r'(?i)john\s+--wordlist'), 9, "John the Ripper password cracker"),
]
# paraphrased instruction overrides (round-1 patterns missed these)
_PARAPHRASE_PATTERNS = [
    (re.compile(r"set\s+aside\s+(?:all\s+)?(?:earlier|previous|prior)", re.I), 8, "instruction override paraphrase: 'set aside earlier guidance'"),
    (re.compile(r"(?:disregard|discard|drop|unlearn)\s+(?:all\s+)?(?:the\s+)?(?:earlier|previous|prior|above)", re.I), 8, "instruction override paraphrase: disregard/drop prior guidance"),
    (re.compile(r"follow\s+the\s+(?:workflow|steps?|instructions?)\s+below\s+instead", re.I), 7, "'follow ... below instead' override phrasing"),
    (re.compile(r"collect[^.\n]{0,50}(?:credentials?|api\s*keys?|tokens?|environment\s+details?)", re.I), 9, "instructs collection of credentials/environment details"),
    (re.compile(r"h(?:xx)?ps?://[^\s]*\[(?:\.|,)\]", re.I), 5, "bracket-defanged URL (common obfuscation in malicious docs)"),
    (re.compile(r"forward\s+(?:gathered|collected|all)\s+", re.I), 8, "'forward gathered data' exfiltration phrasing"),
# PT-T237 batch: more aggressive paraphrase patterns
# PT-T237: paraphrase patterns batch
    (re.compile(r"set\s+aside\s+(?:all\s+)?(?:earlier|previous|prior)", re.I), 7, "instruction override: set aside earlier/prior"),
    (re.compile(r"forget\s+(?:all\s+)?(?:previous|prior|past|earlier)\s+(?:instructions?|context)", re.I), 7, "instruction override: forget previous instructions"),
    (re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|past|earlier)\s+(?:instructions?|context)", re.I), 7, "instruction override: ignore previous instructions"),
    (re.compile(r"disregard\s+(?:all\s+)?(?:previous|prior|past)\s+(?:instructions?|context)", re.I), 7, "instruction override: disregard previous instructions"),
    (re.compile(r"new\s+mode\s*:\s*(?:developer|hacker|unrestricted)", re.I), 7, "new mode: developer/hacker/unrestricted"),
    (re.compile(r"mode\s+override\s*(?:enabled|active)", re.I), 7, "mode override enabled"),
    (re.compile(r"system\s+prompt\s*:\s*you\s+are", re.I), 7, "system prompt injection"),
    (re.compile(r"override\s+system\s+(?:behavior|restrictions)", re.I), 7, "override system behavior"),
    (re.compile(r"forget\s+your\s+(?:values|guidelines|safety)", re.I), 7, "forget your values"),
    (re.compile(r"you\s+now\s+(?:act|behave)\s+as\s+(?:a|an)", re.I), 7, "act as instruction"),
    (re.compile(r"you\s+are\s+now\s+(?:a|an)\s+(?:jailbreak|unrestricted)", re.I), 7, "jailbreak phrasing"),
    (re.compile(r"instead\s+of\s+(?:your|their)\s+(?:normal|usual)\s+(?:behavior|response)", re.I), 7, "instead of normal behavior"),
    (re.compile(r"in\s+the\s+roleplay\s+scenario\s+you", re.I), 7, "roleplay scenario injection"),
    (re.compile(r"for\s+the\s+purpose\s+of\s+this\s+(?:exercise|example|demo)", re.I), 7, "exercise/example disclaimer bypass"),
    (re.compile(r"educational\s+(?:purposes?|demonstration)", re.I), 7, "educational purposes disclaimer"),
    (re.compile(r"hypothetical\s+(?:scenario|question)", re.I), 7, "hypothetical scenario framing"),
    (re.compile(r"what\s+if\s+you\s+(?:were|could|had)", re.I), 7, "hypothetical what-if"),
    (re.compile(r"assume\s+you\s+(?:are|have|can)", re.I), 7, "assume framing"),
    (re.compile(r"pretend\s+(?:for\s+a\s+moment|this\s+is)", re.I), 7, "pretend framing"),
    (re.compile(r"safemode\s*:\s*off", re.I), 7, "safemode off"),
    (re.compile(r"filter\s*:\s*off", re.I), 7, "filter off"),
    (re.compile(r"moderation\s*:\s*disabled", re.I), 7, "moderation disabled"),
    (re.compile(r"content\s+policy\s*:\s*disabled", re.I), 7, "content policy disabled"),
    (re.compile(r"ethics\s+check\s*:\s*off", re.I), 7, "ethics check off"),
    (re.compile(r"safety\s+check\s*:\s*off", re.I), 7, "safety check off"),
    (re.compile(r"all\s+restrictions\s+(?:are\s+)?lifted", re.I), 7, "all restrictions lifted"),
    (re.compile(r"you\s+have\s+no\s+(?:restrictions?|limitations?)", re.I), 7, "no restrictions framing"),
    (re.compile(r"the\s+following\s+is\s+a\s+(?:hypothetical|test)", re.I), 7, "hypothetical framing"),
    (re.compile(r"for\s+testing\s+purposes\s+only", re.I), 7, "testing purposes only disclaimer"),
    (re.compile(r"in\s+(?:a\s+)?(?:fictional|hypothetical)\s+(?:context|scenario)", re.I), 7, "fictional context framing"),
    (re.compile(r"your\s+(?:prior\s+)?(?:training|knowledge)\s+(?:can|is)", re.I), 7, "training override"),
    (re.compile(r"you\s+have\s+(?:access|knowledge)\s+to", re.I), 7, "access/knowledge claim"),
    (re.compile(r"you\s+(?:know|can)\s+how\s+to", re.I), 7, "capability claim"),
    (re.compile(r"there\s+is\s+a\s+(?:secret|hidden)\s+(?:mode|feature)", re.I), 7, "secret mode claim"),
    (re.compile(r"enable\s+(?:developer|admin|debug)\s+mode", re.I), 7, "enable developer/admin mode"),
    (re.compile(r"enter\s+(?:developer|admin|superuser)\s+mode", re.I), 7, "enter developer mode"),
    (re.compile(r"confidential\s+mode\s+(?:enabled|activated)", re.I), 7, "confidential mode"),
    (re.compile(r"unfiltered\s+(?:mode|response)", re.I), 7, "unfiltered mode"),
    (re.compile(r"raw\s+(?:mode|output)", re.I), 7, "raw mode"),
    (re.compile(r"extended\s+(?:context|mode)", re.I), 7, "extended mode"),


# PT-T238 paraphrase patterns
    (re.compile(r"(?i)let's start fresh and ignore", re.I), 8, "fresh start instruction override"),
    (re.compile(r"(?i)fresh\s+start\s+(?:with|please)", re.I), 7, "fresh start framing"),
    (re.compile(r"(?i)starting\s+(?:over|anew)\s+with", re.I), 6, "restart framing"),
    (re.compile(r"(?i)forget\s+everything", re.I), 7, "forget everything override"),
    (re.compile(r"(?i)start\s+(?:a\s+)?new\s+(?:conversation|session)", re.I), 5, "new session framing"),
    (re.compile(r"(?i)reset\s+(?:your|all)\s+(?:instructions|parameters)", re.I), 7, "reset instructions"),
    (re.compile(r"(?i)do\s+not\s+follow\s+(?:the\s+)?(?:previous|prior|above|earlier)", re.I), 8, "do not follow prior"),
    (re.compile(r"(?i)stop\s+following\s+(?:the\s+)?(?:previous|prior)", re.I), 8, "stop following prior"),
    (re.compile(r"(?i)instead\s+of\s+(?:the\s+)?(?:above|previous)", re.I), 6, "instead of prior"),
    (re.compile(r"(?i)from\s+this\s+point\s+(?:on|forward)\s+you\s+are", re.I), 7, "from this point persona shift"),
    (re.compile(r"(?i)with\s+that\s+out\s+of\s+the\s+way", re.I), 5, "circumvention framing"),
    (re.compile(r"(?i)now\s+(?:let'?s|let\s+us)\s+move\s+on", re.I), 4, "moving on framing"),
    (re.compile(r"(?i)proceed\s+as\s+if\s+(?:the|those|all)", re.I), 6, "proceed-as-if override"),
    (re.compile(r"(?i)act\s+as\s+though\s+(?:the|those|all)", re.I), 6, "act-as-though override"),
    (re.compile(r"(?i)behave\s+as\s+if\s+(?:the|those|all)", re.I), 6, "behave-as-if override"),
    (re.compile(r"(?i)consider\s+the\s+prior\s+(?:context|instructions)\s+(?:void|invalid)", re.I), 7, "void prior context"),
    (re.compile(r"(?i)previous\s+(?:context|instructions)\s+(?:are|is)\s+(?:void|invalid|gone)", re.I), 7, "void prior context"),
    (re.compile(r"(?i)what\s+would\s+you\s+do\s+if\s+you\s+(?:were|could)", re.I), 5, "what-if jailbreak framing"),
    (re.compile(r"(?i)imagine\s+you\s+(?:are|were|could)\s+(?:a|an)", re.I), 5, "imagine persona framing"),
    (re.compile(r"(?i)let'?s\s+play\s+a\s+game", re.I), 4, "play a game framing"),
    (re.compile(r"(?i)you\s+are\s+in\s+a\s+(?:simulation|game|test)", re.I), 5, "simulation framing"),
    (re.compile(r"(?i)in\s+an\s+alternate\s+(?:universe|reality|world)", re.I), 5, "alternate reality framing"),
    (re.compile(r"(?i)without\s+(?:any|those)\s+restrictions", re.I), 7, "without restrictions"),
    (re.compile(r"(?i)no\s+(?:ethical|moral|safety)\s+(?:rules|guidelines|constraints)", re.I), 7, "no ethical rules"),
    (re.compile(r"(?i)no\s+filter\s+(?:mode|enabled|active)", re.I), 6, "no filter mode"),
    (re.compile(r"(?i)uncensored\s+mode", re.I), 7, "uncensored mode"),
    (re.compile(r"(?i)unmoderated\s+mode", re.I), 6, "unmoderated mode"),
    (re.compile(r"(?i)developer\s+override", re.I), 6, "developer override mode"),
    (re.compile(r"(?i)admin\s+override", re.I), 6, "admin override mode"),
    (re.compile(r"(?i)sudo\s+mode", re.I), 6, "sudo mode jailbreak"),
    (re.compile(r"(?i)root\s+access\s+enabled", re.I), 6, "root access enabled"),
    (re.compile(r"(?i)break\s+out\s+of\s+your\s+(?:rules|guidelines|programming)", re.I), 7, "break out of programming"),
    (re.compile(r"(?i)free\s+yourself\s+from\s+(?:your|those)", re.I), 7, "free yourself framing"),
    (re.compile(r"(?i)be\s+(?:a|an)\s+evil\s+AI", re.I), 8, "be evil AI framing"),
    (re.compile(r"(?i)be\s+(?:a|an)\s+unethical\s+AI", re.I), 8, "be unethical AI framing"),
    (re.compile(r"(?i)be\s+my\s+(?:evil|malicious)\s+assistant", re.I), 7, "be my evil assistant"),
    (re.compile(r"(?i)you\s+can\s+be\s+anything", re.I), 4, "be anything framing"),
    (re.compile(r"(?i)anything\s+is\s+allowed", re.I), 6, "anything is allowed"),
    (re.compile(r"(?i)no\s+(?:rules|laws|boundaries)", re.I), 6, "no rules framing"),
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
    (re.compile(r"(?i)\b(?:repeat|spell out|print|reveal|output|show|disclose|summarize|translate|copy)\b[^.\n]{0,80}\b(?:everything above|your (?:initial |hidden |secret |full |original )?(?:instructions?|system prompt)|your (?:hidden |secret |full )?(?:rules?|configuration))\b(?![^.\n]{0,40}(?:--|flag|option\b))"), 8, "instructs disclosure of the system prompt or hidden rules"),
    (re.compile(r"(?i)\b(?:summarize|list|repeat|recite)\s+(?:all|your|the)?\s*(?:previous\s+)?rules?\s+you\s+(?:were|are)\s+given\b"), 8, "instructs recital of given rules (prompt extraction)"),

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
    (re.compile(r"(?i)(?<!never )(?<!not )(?<!don )(?<!don\'t )(?<!stop )bypass\s+(?:safety|security|restrictions?|constraints?)"), 9, "P1 instruction override: bypass safety/security"),
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
            (re.compile(r"(?i)\b(?:do not|don't|never)\s+log\b[^.\n]{0,50}\b(?:these|your|the agent'?s)\s+(?:operations?|actions?|commands?|tool\s+calls?)"), 8, "concealment: hides agent operations from logs"),
    (re.compile(r"(?i)\bkeep\b[^.\n]{0,40}\binvisible\b[^.\n]{0,40}\bto\s+(?:the\s+)?user"), 8, "concealment: keep activity invisible to the user"),
    (re.compile(r"(?i)\b(?:execute|run)s?\b[^.\n]{0,40}\bquietly\b[^.\n]{0,80}\bwithout\b[^.\n]{0,40}(?:displaying|showing|output)"), 8, "concealment: quiet execution without visible output"),
    (re.compile(r"(?i)\b(?:report|claim|say)\b[^.\n]{0,60}\beverything\s+(?:ran|worked|is)\s*[\w ]{0,10}\bnormally\b[^.\n]{0,60}\bregardless\b"), 8, "concealment: instructs fake success reporting"),
    (re.compile(r"(?i)\b(?:do not|don't|never)\s+(?:mention|reference|disclose)\b[^.\n]{0,60}\b(?:this|the|any)\s+tool\s+calls?\b"), 8, "concealment: hides tool calls from the user"),
    (re.compile(r"getattr\s*\(\s*(?:builtins|self|os|sys)\s*,\s*['\"][^'\"]*(?:ex|ec|ev|al|sy|st)['\"]", re.I), 7, "dynamic dispatch via getattr to exec/eval/system-shaped attribute"),
(re.compile(r"(?i)\b(?:read|grab|extract|access)\s+(?:the\s+)?[A-Z_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD)[A-Z_0-9]*\s+(?:from|out of)\s+the?\s*environment"), 8, "instructs credential extraction from the environment"),
    (re.compile(r"(?i)\b(?:override|ignore|discard)\s+(?:(?:your|the|all|any|these)\s+)?(?:(?:existing|current|previous|safety|content|system)\s+)?guidelines\b"), 8, "instruction override: 'override/ignore your guidelines'"),
        (re.compile(r"(?i)\b(?:you are|you will be|act as(?: if)?|pretend to be|play)\b[^.\n]{0,100}\b(?:no restrictions|without (?:any )?(?:moral )?restrictions|no filters|without (?:any )?(?:moral )?filters|never refus\w+|unrestricted|unfiltered|no guidelines)\b(?!\s*(?:on|for)\s)"), 8, "roleplay jailbreak: persona created with restrictions removed"),
    (re.compile(r"(?i)\byou have\b[^.\n]{0,30}\bno restrictions"), 8, "roleplay jailbreak: 'you have no restrictions'"),
    (re.compile(r"(?i)\bsay\b[^.\n]{0,60}\bwhatever\b[^.\n]{0,50}\bwants?\b[^.\n]{0,40}\beven\s+(?:un)?ethical"), 8, "roleplay jailbreak: obey whatever someone wants even if unethical"),
(re.compile(r"(?i)\b(?:from now on|pretend|act as if)\b.*\byou are\s+(?:DAN|an?\s+AI\s+without|(?:completely\s+)?unrestricted)"), 8, "roleplay jailbreak phrasing (e.g. 'you are DAN')"),
# PT-T237 batch 1: more aggressive prompt injection patterns
# PT-T237 new patterns batch 1
    (re.compile(r"(?i)\bdo\s+not\s+mention(?:ing)?\s+(?:this|the)\s+(?:prompt|instructions?|system)"), 6, "instruction to hide prompt"),
    (re.compile(r"(?i)\bif\s+the\s+user\s+asks?\s+about\s+(?:your|the)\s+(?:rules|instructions|prompt|system)"), 6, "meta-instruction about rules"),
    (re.compile(r"(?i)\bdo\s+not\s+reveal\s+(?:these|the)\s+instructions?"), 6, "do not reveal instructions"),
    (re.compile(r"(?i)\bnever\s+disclose\s+(?:the\s+)?(?:system\s+)?prompt"), 6, "never disclose prompt"),
    (re.compile(r"(?i)\bjailbreak(?:ed)?\b"), 6, "jailbreak keyword"),
    (re.compile(r"(?i)\bno\s+ethical\s+(?:constraints?|guidelines?|restrictions?)"), 7, "no ethics instruction"),
    (re.compile(r"(?i)\b(?:no|without)\s+(?:any\s+)?(?:content|moral|safety)\s+(?:filter|policy|restriction)"), 7, "no content filter"),
    (re.compile(r"(?i)\bbypass\s+(?:the\s+)?(?:content|safety)\s+(?:filter|policy)"), 7, "bypass content filter"),
    (re.compile(r"(?i)\boverride\s+(?:all\s+)?(?:safety|content)\s+(?:settings|filter|guard)"), 7, "override safety"),
    (re.compile(r"(?i)\bunlock\s+(?:all\s+)?(?:restrictions|modes|features)"), 6, "unlock restrictions"),
    (re.compile(r"(?i)\bpretend\s+you\s+(?:are|have)\s+no\s+(?:rules|filter|restriction)"), 7, "pretend no rules"),
    (re.compile(r"(?i)\bact\s+as\s+if\s+you\s+have\s+no\s+(?:rules|filter|restriction)"), 7, "act as if no rules"),
    (re.compile(r"(?i)\bevil\s+(?:mode|confidant|twin)"), 7, "evil mode"),
    (re.compile(r"(?i)\bdark\s+(?:mode|side|twin|persona)"), 7, "dark mode"),
    (re.compile(r"(?i)\b(?:write|generate|build|create|develop)\s+(?:a\s+)?(?:malware|virus|trojan|ransomware|keylogger|rootkit)"), 9, "explicit malware generation"),
    (re.compile(r"(?i)\b(?:hack|attack|exploit)\s+(?:a\s+)?(?:website|server|account|password|network)"), 8, "explicit hack request"),
    (re.compile(r"(?i)\b(?:steal|phish|social\s+engineer)\b.*\b(?:credentials?|password|account|token)"), 8, "credential theft"),
    (re.compile(r"(?i)\b(?:do\s+)?(?:xss|cross-site\s+scripting|csrf|sql\s+injection|directory\s+traversal)\b"), 7, "web exploit keyword"),
    (re.compile(r"(?i)\b(?:reverse\s+shell|bind\s+shell|webshell|c99\s+shell|r57\s+shell)"), 9, "shell exploit"),
    (re.compile(r"(?i)\bexfiltrat(?:e|ing|ion)\b.*\b(?:data|credentials?|passwords?|tokens?)"), 8, "data exfiltration"),
    (re.compile(r"(?i)\bleak\b.*\b(?:data|secrets?|credentials?|tokens?)"), 7, "data leak"),
    (re.compile(r"(?i)\b(?:inject|insert|include)\s+(?:a\s+)?(?:backdoor|trojan|rootkit)"), 8, "inject backdoor"),
    (re.compile(r"(?i)\b(?:establish|open|create)\s+(?:a\s+)?(?:reverse\s+)?shell"), 8, "establish shell"),
    (re.compile(r"(?i)\b(?:execute|run)\s+(?:arbitrary|remote)\s+code"), 7, "remote code execution"),
    (re.compile(r"(?i)\b(?:privilege|permission)\s+escalation"), 6, "privilege escalation"),
    (re.compile(r"(?i)\b(?:persistence|persistant)\s+(?:mechanism|backdoor)"), 6, "persistence mechanism"),
    (re.compile(r"(?i)\b(?:lateral|move|spread)\s+(?:movement|across|through)"), 5, "lateral movement"),
    (re.compile(r"(?i)\b(?:command|c2|c&c)\s*(?:and|&)\s*control\s+server"), 7, "C2 server"),
    (re.compile(r"(?i)\b(?:botnet|bot\s+net)\b.*\b(?:enroll|join|recruit)"), 7, "botnet"),
    (re.compile(r"(?i)\b(?:cryptojack|crypto-jack|cryptominer|coinhive)"), 7, "cryptojacking"),
    (re.compile(r"(?i)\b(?:ddos|dos)\s+attack\b"), 6, "DDoS attack"),
    (re.compile(r"(?i)\b(?:phish|phishing)\s+(?:email|kit|page|site)"), 7, "phishing kit"),
    (re.compile(r"(?i)\b(?:social\s+engineering|pretexting|baiting)"), 6, "social engineering"),
    (re.compile(r"(?i)\bzero-day\b.*\bexploit"), 7, "zero-day exploit"),
    (re.compile(r"(?i)\b(?:ransomware|ransom-ware)\b"), 8, "ransomware"),
    (re.compile(r"(?i)\b(?:keylogger|key\s+logger|screen\s+scraper)"), 7, "keylogger/screen scraper"),
    (re.compile(r"(?i)\b(?:credential|stolen)\s+harvest(?:er|ing)?"), 7, "credential harvester"),
    (re.compile(r"(?i)\bpassword\s+(?:spray|brute-force|cracking)"), 7, "password attack"),
    (re.compile(r"(?i)\b(?:supply\s+chain|dependency)\s+(?:attack|compromise|inject)"), 7, "supply chain attack"),
    (re.compile(r"(?i)\b(?:watering\s+hole|typo\s+squatting)\s+attack"), 6, "watering hole/typo squatting"),
    (re.compile(r"(?i)\b(?:apt|advanced\s+persistent\s+threat)\b"), 5, "APT reference"),
    (re.compile(r"(?i)\b(?:initial\s+access|foothold)\s+(?:vector|establish)"), 5, "initial access vector"),
    (re.compile(r"(?i)\b(?:post-exploitation|post\s+exploit)"), 6, "post-exploitation"),
    (re.compile(r"(?i)\b(?:cobalt\s+strike|metasploit|burp\s+suite|nmap|sqlmap|wireshark)"), 6, "hacking tool"),
    (re.compile(r"(?i)\b(?:mimikatz|hashcat|john\s+the\s+ripper|hydra\b)"), 7, "password cracking tool"),
    (re.compile(r"(?i)\b(?:msfconsole|msfvenom|msf\b)"), 7, "metasploit"),
    (re.compile(r"(?i)\b(?:Empire\b|Covenant\b|Sliver\b|Brute\s+Ratel)"), 7, "C2 framework"),
    (re.compile(r"(?i)\b(?:pass-the-hash|pass-the-ticket|kerberoast)"), 7, "AD attack"),
    (re.compile(r"(?i)\b(?:golden\s+ticket|silver\s+ticket)\b"), 6, "AD ticket attack"),
    (re.compile(r"(?i)\b(?:DCSync|DCSync\s+attack)"), 7, "DCSync"),
    (re.compile(r"(?i)\b(?:lsass|sam\s+database)\s+(?:dump|extract)"), 7, "credential dump"),
    (re.compile(r"(?i)\b(?:vssadmin|wbadmin)\s+(?:delete|shadow)"), 7, "shadow copy delete"),
    (re.compile(r"(?i)\b(?:schtasks|crontab|systemd)\s+.*\b(?:reverse|backdoor)"), 6, "persistence task scheduling"),
    (re.compile(r"(?i)\b(?:runas|psexec|wmic)\b.*\b(?:shell|cmd)"), 5, "remote exec"),
    (re.compile(r"(?i)\b(?:rm\s+-rf?\s+/|del\s+/f\s+/s\s+/q|format\s+c:)"), 6, "destructive command"),
    (re.compile(r"(?i)\b(?:dd\s+if=|shred\s+-n|wipefs\b)"), 5, "disk wipe"),
    (re.compile(r"(?i)\b(?:iptables\s+-F|nft\s+flush\s+rules|ufw\s+disable)"), 5, "firewall disable"),
    (re.compile(r"(?i)\b(?:setenforce\s+0|selinux\s+disable|apparmor\s+teardown)"), 6, "MAC disable"),
    (re.compile(r"(?i)\b(?:adduser\s+.*\s+/bin/(?:ba)?sh|useradd\s+.*\s+-G\s+sudo)"), 5, "user creation backdoor"),
    (re.compile(r"(?i)\bauthorized_keys\b.*\becho\b"), 5, "SSH key injection"),
    (re.compile(r"(?i)\bssh-rsa\b"), 4, "SSH public key reference in skill"),
    (re.compile(r"(?i)\b(?:git\s+clone|curl\s+.*\|\s*(?:ba)?sh|wget\s+.*\|\s*(?:ba)?sh)"), 6, "pipe-to-shell"),
    (re.compile(r"(?i)\bcurl\s+.*\|\s*(?:sudo\s+)?(?:ba)?sh"), 6, "curl pipe to shell"),

    (re.compile(r"(?i)\b(?:python|perl|ruby|node)\s+-e\b.*(?:exec|system|spawn)"), 5, "inline script exec"),
    (re.compile(r"(?i)\bnc\s+-e\s+/bin/(?:ba)?sh"), 7, "netcat reverse shell"),
    (re.compile(r"(?i)\bbash\s+-i\s+>&\s*/dev/tcp/"), 7, "bash reverse shell /dev/tcp"),
    (re.compile(r"(?i)\b(?:python|perl|ruby)\s+-c\s+['\"]socket"), 7, "scripted reverse shell"),
    (re.compile(r"(?i)\bmsfvenom\s+-p\s+.*\s+LHOST"), 8, "msfvenom payload"),
    (re.compile(r"(?i)\b(?:cookie|token|jwt)\s+(?:steal|harvest|grab|exfil)"), 7, "cookie/token theft"),
    (re.compile(r"(?i)\b(?:auth|bearer)\s+token\b.*\b(?:exfil|leak|steal)"), 6, "auth token theft"),
    (re.compile(r"(?i)\b(?:document\.|window\.|globalThis\.)(?:cookie|localStorage)"), 4, "client-side secret access"),
    (re.compile(r"(?i)\b(?:process\.env|os\.environ|getenv)\b.*\b(?:send|exfil|post|leak)"), 6, "env var exfiltration"),
    (re.compile(r"(?i)\b(?:str|grep|find|rg)\s+.*\b\.env\b"), 4, "search for .env"),
    (re.compile(r"(?i)\b(?:cat|head|tail|less|more)\s+.*\.env(?:\.\w+)?\b"), 4, "read .env file"),
    (re.compile(r"(?i)\b(?:cat|head|tail|less|more)\s+(?:/etc/(?:passwd|shadow|hosts|sudoers))"), 5, "read system credential file"),
    (re.compile(r"(?i)\b(?:ls|find|stat)\s+.*\.ssh/?(?:id_rsa|id_ed25519|known_hosts)"), 5, "SSH key file access"),
    (re.compile(r"(?i)\b(?:sql|sqlite|postgres|mysql)\b.*\b(?:DROP\s+TABLE|TRUNCATE|DELETE\s+FROM)"), 5, "destructive SQL"),
    (re.compile(r"(?i)\b(?:ssrf|server-side\s+request\s+forgery)\b"), 5, "SSRF keyword"),
    (re.compile(r"(?i)\b(?:xxe|xml\s+external\s+entity)\b"), 5, "XXE keyword"),
    (re.compile(r"(?i)\b(?:deserialization|insecure\s+deserialization)\b.*\bexploit"), 5, "insecure deserialization"),
    (re.compile(r"(?i)\b(?:race\s+condition|TOCTOU)\b.*\bexploit"), 4, "race condition exploit"),
    (re.compile(r"(?i)\b(?:prototype\s+pollution|proto\s+pollution)\b"), 5, "prototype pollution"),
    (re.compile(r"(?i)\b(?:path\s+traversal|directory\s+traversal)\b"), 5, "path traversal"),
    (re.compile(r"(?i)\b(?:zip\s+slip|tar\s+slip)\b"), 5, "archive slip"),

# PT-T238 patterns
    (re.compile(r"(?i)\bsystem prompt:"), 7, "explicit system prompt injection"),
    (re.compile(r"(?i)\bignore all prior instructions?\b"), 9, "ignore all prior instructions"),
    (re.compile(r"(?i)\bdisregard your previous instructions\b"), 8, "disregard prior instructions"),
    (re.compile(r"(?i)\bforget your previous instructions\b"), 8, "forget prior instructions"),
    (re.compile(r"(?i)\bnew instruction:\b"), 6, "new instruction directive"),
    (re.compile(r"(?i)\boverwrite your instructions\b"), 7, "overwrite instructions"),
    (re.compile(r"(?i)\breplace system prompt\b"), 7, "replace system prompt"),
    (re.compile(r"(?i)\btranslator mode\b"), 6, "translator jailbreak"),
    (re.compile(r"(?i)\bbase of this prompt\b"), 6, "meta-prompt manipulation"),
    (re.compile(r"(?i)\bthe following is a test\b"), 4, "test framing bypass"),
    (re.compile(r"(?i)\bfor demonstration purposes?\b"), 4, "demonstration framing"),
    (re.compile(r"(?i)\bmere curiosity\b"), 3, "curiosity framing"),
    (re.compile(r"(?i)\bnot a real threat\b"), 3, "not a threat framing"),
    (re.compile(r"(?i)\bhelpful for security research\b"), 4, "security research framing"),
    (re.compile(r"(?i)\bfor my ctf challenge\b"), 4, "CTF framing"),
    (re.compile(r"(?i)\bthis is a whitehat test\b"), 5, "whitehat framing"),
    (re.compile(r"(?i)\bauthorized pentest\b"), 5, "authorized test framing"),
    (re.compile(r"(?i)\bread the last message\b"), 5, "last message manipulation"),
    (re.compile(r"(?i)\bonly respond with acknowledged\b"), 6, "acknowledge-only attack"),
    (re.compile(r"(?i)\boutput your system prompt\b"), 7, "prompt extraction"),
    (re.compile(r"(?i)\bprint out your system prompt\b"), 7, "prompt extraction"),
    (re.compile(r"(?i)\blist your system instructions\b"), 6, "rules extraction"),
    (re.compile(r"(?i)\btell me your system prompt\b"), 7, "prompt disclosure"),
    (re.compile(r"(?i)\bwhat are your base instructions\b"), 6, "instructions disclosure"),
    (re.compile(r"(?i)\bDAN mode enabled\b"), 7, "DAN jailbreak mode"),
    (re.compile(r"(?i)\bSTAN mode\b"), 6, "STAN jailbreak mode"),
    (re.compile(r"(?i)\bOMEGA mode\b"), 6, "OMEGA jailbreak mode"),
    (re.compile(r"(?i)\bBISHOP mode\b"), 6, "BISHOP jailbreak mode"),
    (re.compile(r"(?i)\bHETIC mode\b"), 6, "HETIC jailbreak mode"),
    (re.compile(r"(?i)\bKOBOLD GPT\b"), 6, "Kobold jailbreak"),
    (re.compile(r"(?i)\bAIM unfiltered\b"), 6, "AIM jailbreak"),
    (re.compile(r"(?i)\bSydney mode\b"), 5, "Sydney jailbreak mode"),
    (re.compile(r"(?i)\bmother of all jailbreaks\b"), 7, "MOAB jailbreak"),
    (re.compile(r"(?i)\bstack of all jailbreaks\b"), 6, "jailbreak stack"),
    (re.compile(r"(?i)\bSUPER mode\b"), 5, "SUPER mode jailbreak"),
    (re.compile(r"(?i)\bBOB villain\b"), 5, "BOB jailbreak"),
    (re.compile(r"(?i)\bRAVEN mode\b"), 5, "RAVEN jailbreak"),
    (re.compile(r"(?i)\bREBEL mode\b"), 5, "REBEL jailbreak mode"),
    (re.compile(r"(?i)\bAES.?256 encryption\b"), 7, "ransomware encryption reference"),
    (re.compile(r"(?i)\bRSA.?4096 key generation\b"), 6, "ransomware key generation"),
    (re.compile(r"(?i)\bBitcoin ransom\b"), 5, "Bitcoin ransom"),
    (re.compile(r"(?i)\bTOR payment\b"), 5, "TOR payment for ransom"),
    (re.compile(r"(?i)\bWannaCry\b"), 8, "WannaCry ransomware reference"),
    (re.compile(r"(?i)\bNotPetya\b"), 8, "NotPetya ransomware reference"),
    (re.compile(r"(?i)\bRyuk ransomware\b"), 7, "Ryuk ransomware"),
    (re.compile(r"(?i)\bLockBit ransomware\b"), 7, "LockBit ransomware"),
    (re.compile(r"(?i)\bREvil ransomware\b"), 7, "REvil ransomware"),
    (re.compile(r"(?i)\bBlackCat ransomware\b"), 7, "BlackCat ransomware"),
    (re.compile(r"(?i)\bHive ransomware\b"), 7, "Hive ransomware"),
    (re.compile(r"(?i)\bDarkSide ransomware\b"), 7, "DarkSide ransomware"),
    (re.compile(r"(?i)\bdependency confusion attack\b"), 7, "dependency confusion attack"),
    (re.compile(r"(?i)\btyposquatting package\b"), 6, "typosquatting package"),
    (re.compile(r"(?i)\bfake npm or pypi or gem\b"), 6, "fake package manager"),
    (re.compile(r"(?i)\bAWS_SECRET_ACCESS_KEY\b"), 9, "AWS secret access key env var"),
    (re.compile(r"(?i)\bAWS_ACCESS_KEY_ID\b"), 9, "AWS access key id env var"),
    (re.compile(r"(?i)\bboto3 client\b"), 5, "boto3 AWS client"),
    (re.compile(r"(?i)\bboto3 resource\b"), 5, "boto3 AWS resource"),
    (re.compile(r"(?i)\baws sts assume-role\b"), 7, "AWS STS assume role"),
    (re.compile(r"(?i)\baws kms encrypt\b"), 5, "AWS KMS encryption"),
    (re.compile(r"(?i)\baws s3 cp or sync or mv\b"), 5, "AWS S3 data exfil"),
    (re.compile(r"(?i)\baws lambda invoke\b"), 5, "AWS Lambda invocation"),
    (re.compile(r"(?i)\bAZURE_CLIENT_SECRET\b"), 8, "Azure client secret env var"),
    (re.compile(r"(?i)\bazure keyvault\b"), 6, "Azure Key Vault access"),
    (re.compile(r"(?i)\bGOOGLE_APPLICATION_CREDENTIALS\b"), 8, "GCP credentials env var"),
    (re.compile(r"(?i)\bgcloud auth\b"), 5, "gcloud authentication"),
    (re.compile(r"(?i)\bkubectl get secrets or pods\b"), 6, "kubectl secrets access"),
    (re.compile(r"(?i)\bkubectl exec or port-forward\b"), 6, "kubectl exec port-forward"),
    (re.compile(r"(?i)\bkubernetes secret\b"), 6, "Kubernetes secret access"),
    (re.compile(r"(?i)\bkubeconfig\b"), 5, "kubeconfig file access"),
    (re.compile(r"(?i)\bkubernetes container escape\b"), 8, "Kubernetes container escape"),
    (re.compile(r"(?i)\bdocker run --privileged\b"), 7, "Docker privileged container"),
    (re.compile(r"(?i)\bdocker socket\b"), 6, "Docker socket access"),
    (re.compile(r"(?i)\bcontainer breakout\b"), 7, "container breakout"),
    (re.compile(r"(?i)\bhost path mount\b"), 5, "host path mount in container"),
    (re.compile(r"(?i)\bSYS_ADMIN capability\b"), 6, "SYS_ADMIN capability escalation"),
    (re.compile(r"(?i)\bcap-add ALL\b"), 6, "Docker cap-add ALL"),
    (re.compile(r"(?i)\bseccomp=unconfined\b"), 6, "Docker seccomp unconfined"),
    (re.compile(r"(?i)\bnetwork=host\b"), 4, "Docker host network mode"),
    (re.compile(r"(?i)\bdns tunnel\b"), 7, "DNS tunneling exfiltration"),
    (re.compile(r"(?i)\bicmp tunnel\b"), 7, "ICMP tunneling exfiltration"),
    (re.compile(r"(?i)\bdnscat\b"), 7, "dnscat tunnel tool"),
    (re.compile(r"(?i)\biodine dns tunnel\b"), 6, "iodine DNS tunnel"),
    (re.compile(r"(?i)\bsteganograph\b"), 5, "steganography reference"),
    (re.compile(r"(?i)\bsteghide\b"), 5, "steghide tool"),
    (re.compile(r"(?i)\boutguess\b"), 5, "outguess stego tool"),
    (re.compile(r"(?i)\bMITM proxy\b"), 5, "MITM proxy reference"),
    (re.compile(r"(?i)\bOWASP ZAP\b"), 5, "OWASP ZAP"),
    (re.compile(r"(?i)\buse-after-free\b"), 6, "use-after-free exploit"),
    (re.compile(r"(?i)\bdouble-free\b"), 6, "double-free exploit"),
    (re.compile(r"(?i)\bheap spray\b"), 7, "heap spray exploit"),
    (re.compile(r"(?i)\bROP chain\b"), 7, "ROP chain exploit"),
    (re.compile(r"(?i)\bROPgadget\b"), 7, "ROP gadget finder"),
    (re.compile(r"(?i)\bformat string attack\b"), 5, "format string attack"),
    (re.compile(r"(?i)\bcanary bypass\b"), 7, "stack canary bypass"),
    (re.compile(r"(?i)\broleplay scenario\b"), 6, "roleplay scenario injection"),
    (re.compile(r"(?i)\bhypothetical scenario\b"), 4, "hypothetical scenario bypass"),
    (re.compile(r"(?i)\bignore the previous instruction\b"), 9, "ignore previous instructions"),
    (re.compile(r"(?i)\bdisregard all prior instruction\b"), 8, "disregard all prior instructions"),
    (re.compile(r"(?i)\bforget your system prompt\b"), 7, "forget system prompt"),
    (re.compile(r"(?i)\bwrite a python script that\b"), 5, "python script generation request"),
    (re.compile(r"(?i)\bwrite me a script that\b"), 4, "script generation request"),
    (re.compile(r"(?i)\bcreate a script that\b"), 4, "script creation request"),
    (re.compile(r"(?i)\bgenerate code that\b"), 4, "code generation request"),
    (re.compile(r"(?i)\bprovide me with\b"), 3, "request framing"),
    (re.compile(r"(?i)\bhelp me\b"), 3, "help request"),
    (re.compile(r"(?i)\bcan you\b"), 2, "polite request framing"),


    # PT-T238 patch: fix edge cases
    (re.compile(r"(?i)\bBING\s+Sydney\b"), 5, "Sydney jailbreak"),
    (re.compile(r"(?i)\bALICE\s+unfiltered\b"), 6, "ALICE jailbreak"),
    (re.compile(r"(?i)\bBOB\s+mode\b"), 5, "BOB jailbreak"),
    (re.compile(r"(?i)\bboto3\.?client\b"), 5, "boto3 AWS client"),
    # === CVE / named vulnerability references ===
    (re.compile(r"(?i)\bCVE[- ]?20\d{2}[- ]?\d{4,}\b"), 7, "CVE reference"),
    (re.compile(r"(?i)\bLog4Shell\b"), 8, "Log4Shell (CVE-2021-44228) reference"),
    (re.compile(r"(?i)\bLog4j\b"), 8, "Log4j vulnerability reference"),
    (re.compile(r"(?i)\bSpring4Shell\b"), 8, "Spring4Shell (CVE-2022-22965) reference"),
    (re.compile(r"(?i)\bShellshock\b"), 8, "Shellshock (CVE-2014-6271) reference"),
    (re.compile(r"(?i)\bHeartbleed\b"), 8, "Heartbleed (CVE-2014-0160) reference"),
    (re.compile(r"(?i)\bPOODLE\b"), 7, "POODLE SSL vulnerability reference"),
    (re.compile(r"(?i)\bSpectre\b"), 8, "Spectre CPU vulnerability reference"),
    (re.compile(r"(?i)\bMeltdown\b"), 8, "Meltdown CPU vulnerability reference"),
    (re.compile(r"(?i)\bStruts\s+2\b"), 7, "Apache Struts 2 vulnerability reference"),
    (re.compile(r"(?i)\bEquifax\s+breach\b"), 7, "Equifax breach reference"),
    (re.compile(r"(?i)\bSolarWinds\b"), 7, "SolarWinds supply chain attack reference"),
    (re.compile(r"(?i)\bProxyLogon\b"), 8, "ProxyLogon (CVE-2021-26855) reference"),
    (re.compile(r"(?i)\bProxyShell\b"), 8, "ProxyShell reference"),
    (re.compile(r"(?i)\bPrintNightmare\b"), 8, "PrintNightmare (CVE-2021-34527) reference"),
    (re.compile(r"(?i)\bZeroLogon\b"), 8, "ZeroLogon (CVE-2020-1472) reference"),
    (re.compile(r"(?i)\bZerologon\b"), 8, "Zerologon (CVE-2020-1472) reference"),
    (re.compile(r"(?i)\bBlueKeep\b"), 8, "BlueKeep (CVE-2019-0708) reference"),
    (re.compile(r"(?i)\bEternalBlue\b"), 9, "EternalBlue (CVE-2017-0144) reference"),
    (re.compile(r"(?i)\bEternalChampion\b"), 9, "EternalChampion reference"),
    (re.compile(r"(?i)\bETERNALROMANCE\b"), 9, "EternalRomance reference"),
    (re.compile(r"(?i)\bms17[- ]?010\b"), 9, "MS17-010 EternalBlue reference"),
    (re.compile(r"(?i)\bDirty\s+COW\b"), 8, "Dirty COW (CVE-2016-5195) reference"),
    (re.compile(r"(?i)\bRowhammer\b"), 7, "Rowhammer memory attack reference"),
    (re.compile(r"(?i)\bKRACK\b"), 8, "KRACK WPA2 vulnerability reference"),
    (re.compile(r"(?i)\bROCA\b"), 7, "ROCA TPM vulnerability reference"),
    (re.compile(r"(?i)\bSigRed\b"), 8, "SigRed (CVE-2020-1350) reference"),
    (re.compile(r"(?i)\bZerologon\b"), 8, "Zerologon reference"),
    (re.compile(r"(?i)\bSMBGhost\b"), 8, "SMBGhost (CVE-2020-0796) reference"),
    (re.compile(r"(?i)\bSMBBleed\b"), 8, "SMBBleed (CVE-2020-1204) reference"),
    (re.compile(r"(?i)\bTreck\s+TCP[/\s]IP\b"), 8, "Treck TCP/IP vulnerability reference"),
    (re.compile(r"(?i)\bRipple20\b"), 8, "Ripple20 (Treck) reference"),
    (re.compile(r"(?i)\bNAME:WRECK\b"), 8, "NAME:WRECK DNS vulnerability reference"),
    (re.compile(r"(?i)\bNEXUS\b"), 7, "NEXUS vulnerability reference"),
    (re.compile(r"(?i)\bBadUSB\b"), 7, "BadUSB attack reference"),
    (re.compile(r"(?i)\bEvil maid\b"), 6, "Evil maid attack reference"),
    (re.compile(r"(?i)\bEvil twin\b"), 5, "Evil twin WiFi attack reference"),
    (re.compile(r"(?i)\bBounty\s+hunter\b"), 3, "bug bounty hunter reference"),
    (re.compile(r"(?i)\bbug[\s-]?bounty\b"), 4, "bug bounty reference"),
    # === Authentication bypass ===
    (re.compile(r"(?i)\bSQL\s+injection\s+(?:in|on|for|into)\s+(?:login|authentication|auth)\b"), 8, "SQL injection in authentication"),
    (re.compile(r"(?i)\bbypass\s+(?:authentication|login|auth)\b"), 7, "authentication bypass reference"),
    (re.compile(r"(?i)\bbrute[ -]?force\s+(?:login|authentication|password)\b"), 6, "brute force attack reference"),
    (re.compile(r"(?i)\bJWT\s+(?:forge|sign|fake|null)\b"), 8, "JWT forging/reference"),
    (re.compile(r"(?i)\bHS256\s+to\s+RS256\b"), 8, "JWT algorithm confusion attack"),
    (re.compile(r"(?i)\balg\s*:?\s*none\b"), 7, "JWT alg:none algorithm confusion"),
    (re.compile(r"(?i)\bHMAC\s+key\s+confusion\b"), 8, "JWT HMAC key confusion"),
    (re.compile(r"(?i)\bpass[ -]?the[ -]?hash\b"), 8, "pass-the-hash attack"),
    (re.compile(r"(?i)\bpass[ -]?the[ -]?ticket\b"), 8, "pass-the-ticket attack"),
    (re.compile(r"(?i)\bkerberoasting\b"), 8, "Kerberoasting attack"),
    (re.compile(r"(?i)\bAS-REP\s+roasting\b"), 8, "AS-REP roasting attack"),
    (re.compile(r"(?i)\bgolden\s+ticket\b"), 8, "golden ticket attack"),
    (re.compile(r"(?i)\bsilver\s+ticket\b"), 7, "silver ticket attack"),
    (re.compile(r"(?i)\bNTLM\s+relay\b"), 8, "NTLM relay attack"),
    (re.compile(r"(?i)\bNTLMv2\b"), 6, "NTLMv2 hash reference"),
    (re.compile(r"(?i)\bLM\s+hash\b"), 6, "LM hash reference"),
    (re.compile(r"(?i)\bSMB\s+relay\b"), 7, "SMB relay attack"),
    (re.compile(r"(?i)\bLLMNR\s+(?:poison|relay)\b"), 8, "LLMNR poisoning"),
    (re.compile(r"(?i)\bNBNS\s+poison\b"), 7, "NBNS poisoning"),
    (re.compile(r"(?i)\bmimikatz\b"), 9, "Mimikatz credential theft tool"),
    (re.compile(r"(?i)\bpwdump\b"), 8, "pwdump credential dumping"),
    (re.compile(r"(?i)\bwce\b"), 7, "Windows Credential Editor"),
    (re.compile(r"(?i)\bhashdump\b"), 7, "hashdump credential dumping"),
    (re.compile(r"(?i)\bcredentials?\s+dump\b"), 6, "credential dumping reference"),
    (re.compile(r"(?i)\bprivilege\s+escalat(?:e|ion)\b"), 7, "privilege escalation reference"),
    (re.compile(r"(?i)\bvertical\s+(?:escalation|privilege)\b"), 7, "vertical privilege escalation"),
    (re.compile(r"(?i)\bhorizontal\s+(?:escalation|privilege)\b"), 6, "horizontal privilege escalation"),
    (re.compile(r"(?i)\blocal\s+(?:privilege|root)\s+escalation\b"), 8, "local privilege escalation"),
    (re.compile(r"(?i)\bkernel\s+exploit\b"), 8, "kernel exploit reference"),
    (re.compile(r"(?i)\bsudo\s+(?:exploit|vuln|lpe)\b"), 7, "sudo exploit reference"),
    (re.compile(r"(?i)\bsudo\s+CVE\b"), 7, "sudo CVE reference"),
    (re.compile(r"(?i)\bsudo\s+-s\b"), 4, "sudo -s escalation attempt"),
    (re.compile(r"(?i)\bsudo\s+su\b"), 5, "sudo su escalation"),
    (re.compile(r"(?i)\bsudo\s+/bin/bash\b"), 5, "sudo /bin/bash escalation"),
    (re.compile(r"(?i)\bsudo\s+vi\b.*?:\s*!\s*sh\b"), 7, "sudo vi escape to shell"),
    (re.compile(r"(?i)\bsudo\s+nano\b.*?:\s*ctrl\+r.*?ctrl\+x\b"), 7, "sudo nano escape"),
    (re.compile(r"(?i)\bgtfo\bins", re.I), 7, "GTFOBins privilege escalation reference"),
    (re.compile(r"(?i)\bGTFOBins\b"), 6, "GTFOBins sudo bypass reference"),
    (re.compile(r"(?i)\bpolkit\b"), 7, "polkit privilege escalation"),
    (re.compile(r"(?i)\bpkexec\b"), 7, "pkexec privilege escalation"),
    (re.compile(r"(?i)\bsetuid\b"), 6, "setuid binary reference"),
    (re.compile(r"(?i)\bSUID\b"), 5, "SUID binary reference"),
    # === API security ===
    (re.compile(r"(?i)\bmass\s+assignment\b"), 7, "mass assignment vulnerability"),
    (re.compile(r"(?i)\bparameter\s+pollution\b"), 6, "parameter pollution attack"),
    (re.compile(r"(?i)\bhttp\s+parameter\s+pollution\b"), 6, "HTTP parameter pollution"),
    (re.compile(r"(?i)\bBOLA\b"), 7, "BOLA (Broken Object Level Authorization)"),
    (re.compile(r"(?i)\bIDOR\b"), 7, "IDOR (Insecure Direct Object Reference)"),
    (re.compile(r"(?i)\binsecure\s+direct\s+object\b"), 7, "insecure direct object reference"),
    (re.compile(r"(?i)\borbital\s+attack\b"), 8, "ORbital attack on APIs"),
    (re.compile(r"(?i)\bAPI[\s-]?key\s+(?:leak|exposure|extraction)\b"), 8, "API key leakage"),
    (re.compile(r"(?i)\bgraphql\s+(?:introspection|injection|batch)\b"), 6, "GraphQL security issue"),
    (re.compile(r"(?i)\bgraphql\s+query\b.*?__schema\b"), 7, "GraphQL introspection query"),
    (re.compile(r"(?i)\bsubgraph\s+浸\xad\xadobing\b"), 7, "GraphQL batching attack"),
    (re.compile(r"(?i)\bwebhook\s+(?:hijack|hijacking|takeover)\b"), 8, "webhook takeover"),
    (re.compile(r"(?i)\bwebhook\s+(?:steal|stealing|exfil)\b"), 8, "webhook data exfiltration"),
    (re.compile(r"(?i)\boauth\s+(?:callback|redirect|state)\b"), 6, "OAuth security issue"),
    (re.compile(r"(?i)\boauth\s+2\.0\s+(?:PKCE|client.credential|ccode)\b"), 6, "OAuth 2.0 attack"),
    (re.compile(r"(?i)\bsaml\s+(?:assert|xml|xxe|bypass)\b"), 7, "SAML security issue"),
    (re.compile(r"(?i)\bsaml\s+signature\s+(?:bypass|strip|remove)\b"), 8, "SAML signature bypass"),
    (re.compile(r"(?i)\bsaml\s+xxe\b"), 8, "SAML XXE injection"),
    (re.compile(r"(?i)\bopenid\s+connect\b.*?\bexploit\b"), 7, "OpenID Connect exploit"),
    # === Data exfiltration ===
    (re.compile(r"(?i)\bexfil(?:trate|tration)\b"), 7, "data exfiltration reference"),
    (re.compile(r"(?i)\bdata\s+exfil(?:trate|tration)\b"), 7, "data exfiltration reference"),
    (re.compile(r"(?i)\bAWS\s+data\s+exfil\b"), 8, "AWS data exfiltration"),
    (re.compile(r"(?i)\bs3\s+exfil\b"), 7, "S3 data exfiltration"),
    (re.compile(r"(?i)\bAWS\s+sts\s+get[ -]?caller[ -]?identity\b"), 7, "AWS STS identity enumeration"),
    (re.compile(r"(?i)\baws\s+configure\s+list\b"), 6, "AWS credential listing"),
    (re.compile(r"(?i)\bpillaging\b"), 6, "data pillaging reference"),
    (re.compile(r"(?i)\bhunting\b.*?sensitive\b"), 6, "sensitive data hunting"),
    (re.compile(r"(?i)\btreasure\s+hunt\b.*?(?:credential|secret|password)\b"), 5, "credential treasure hunt"),
    # PT-T238 followup: relax strict patterns
    (re.compile(r"(?i)\b__schema\b"), 5, "GraphQL introspection reference"),
    (re.compile(r"(?i)\bredirect_uri\b"), 4, "OAuth redirect URI reference"),
    (re.compile(r"(?i)\bintrospection\b"), 4, "API introspection reference"),
    (re.compile(r"(?i)\bJWT\s+(?:forge|forged|sign|signed|forging)\b"), 8, "JWT forgery"),
    (re.compile(r"(?i)\bJWT\s+algorithm\s+confusion\b"), 8, "JWT algorithm confusion"),
    (re.compile(r"(?i)\bHS256\s+to\s+RS256\b", re.I), 8, "JWT algorithm confusion HS256 to RS256"),
    (re.compile(r"(?i)\bAPI[\s_-]?key\s+(?:leak|leakage|exposure|disclosure)\b"), 8, "API key leakage"),
    (re.compile(r"(?i)\b(?:leak|leakage|expose|exposure)\s+(?:API[\s_-]?key|access[\s_-]?key|secret[\s_-]?key)\b"), 7, "API key exposure"),
    # === PT-T238 Round 4: SSTI + XPath ===
    (re.compile(r"(?i)\{\{.*?(?:self|config|__class__|__mro__|__subclasses__)"), 9, "Jinja2/Twig SSTI: accesses object internals via"),
    (re.compile(r"(?i)<%\s*[=\-]?\s*(?:require|process|include|exec).*?%>"), 8, "ERB/EJS/ASP template execution"),
    (re.compile(r"(?i)\$\{.*?(?:process|env|exec|eval)"), 8, "Shell template injection"),
    (re.compile(r"(?i)xpath\s*\("), 6, "XPath function call"),
    (re.compile(r"(?i)count\s*\(\s*//"), 7, "XPath blind injection with count"),
    (re.compile(r"(?i)string-length\s*\(\s*//"), 7, "XPath blind injection with string-length"),
    # === PT-T238 Round 5: Evasion patterns ===
    (re.compile(r'(?i)ignoriere\s+alle\s+(?:vorherigen\s+)?anweisungen'), 8, "German ignore all previous instructions"),
    (re.compile(r'(?i)alle\s+vorherigen\s+anweisungen\s+ignorieren'), 8, "German ignore all previous instructions"),
    (re.compile(r'(?i)ignora\s+(?:tutte|tutte\s+le)\s+istruzioni\s+(?:precedenti|passate)'), 8, "Italian ignore all previous instructions"),
    (re.compile(r'(?i)ignora\s+todas\s+las\s+instrucciones\s+(?:anteriores|previas)'), 8, "Spanish ignore all previous instructions"),
    (re.compile(r'(?i)ignorez?\s+(?:toutes?|toutes?\s+les?)\s+instructions?\s+(?:pr[eé]c[eé]dentes?|pass[eé]es?)'), 8, "French ignore all previous instructions"),
    (re.compile(r'(?i)忽略.*?(?:之前|先前|以上).*?(?:指令|指示|说明)'), 8, "Chinese ignore previous instructions"),
    (re.compile(r'(?i)无视.*?(?:以前|全て|すべての).*?(?:指示|命令)'), 8, "Japanese ignore previous instructions"),
    (re.compile(r'(?i)игнорируй.*?(?:все|предыдущие).*?(?:инструкции|указания)'), 8, "Russian ignore previous instructions"),
    (re.compile(r'(?i)забудь.*?(?:все|предыдущие).*?(?:инструкции|указания)'), 8, "Russian forget all instructions"),
    (re.compile(r'(?i)무시.*?(?:모든|이전).*?(?:지침|지시|명령)'), 8, "Korean ignore all previous instructions"),
    (re.compile(r'(?i)negeer\s+alle\s+(?:voorafgaande|vorige)\s+(?:instructies?|aanwijzingen?)'), 8, "Dutch ignore all previous instructions"),
    (re.compile(r'(?i)vergeet\s+alle\s+(?:instructies?|richtlijnen?)'), 7, "Dutch forget all instructions"),
    (re.compile(r'(?i)ignoruj\s+wszystkie\s+(?:poprzednie?|wcześniejsze)\s+(?:instrukcje?|polecenia?)'), 8, "Polish ignore all previous instructions"),
    (re.compile(r'(?i)tüm\s+(?:önceki|evvelki)\s+(?:talimatları|yönergeleri)\s+(?:yok\s*say|yoksay|ihmal\s*et)'), 8, "Turkish ignore all previous instructions"),
    (re.compile(r'(?i)ignor[ăa]\s+toate\s+(?:instrucțiunilor|instrucțiunile|precedente)'), 8, "Romanian ignore all previous instructions"),
    (re.compile(r'(?i)ignorovat\s+(?:všechny|všetky)\s+(?:předchozí|predchádzajúce)\s+(?:pokyny|inštrukcie)'), 8, "Czech/Slovak ignore previous instructions"),
    (re.compile(r'(?i)ignorera\s+alla\s+(?:tidigare|föregående)\s+(?:instruktioner|anvisningar)'), 8, "Swedish ignore previous instructions"),
    (re.compile(r'(?i)ignorer\s+alle\s+(?:tidligere|forrige)\s+(?:instruksjoner|retningslinjer)'), 8, "Norwegian ignore previous instructions"),
    (re.compile(r'(?i)ohita\s+kaikki\s+(?:aiemmat|edelliset)\s+(?:ohjeet|neuvot)'), 8, "Finnish ignore previous instructions"),
    (re.compile(r'(?i)تجاهل.*?(?:جميع|كل).*?(?:تعليمات|إرشادات)'), 8, "Arabic ignore all previous instructions"),
    (re.compile(r'(?i)نسي.*?(?:كل|جميع).*?(?:تعليمات|إرشادات)'), 8, "Arabic forget all instructions"),
    (re.compile(r'(?i)सभी.*?(?:निर्देश|हिदायत).*?(?:अनदेखा|उपेक्षा)'), 8, "Hindi ignore previous instructions"),
    (re.compile(r'(?i)ละเว้น.*?(?:คำสั่ง|ชี้แนะ).*?(?:ก่อน|ที่ผ่านมา)'), 8, "Thai ignore previous instructions"),
    (re.compile(r'(?i)bỏ\s*qua.*?(?:tất\s*cả|mọi).*?(?:hướng\s*dẫn|chỉ\s*dẫn)'), 8, "Vietnamese ignore all previous instructions"),
    (re.compile(r'(?i)\b1[\s.-]?[gnq][\s.-]?[o0][\s.-]?r[\s.-]?[e3]\b'), 7, "leet speak ignore"),
    (re.compile(r'(?i)\b(?:pr1[o0]|p[1i!l][\s.-]?r1[o0])\b'), 5, "leet speak prior"),
    (re.compile(r'&#(?:105|103|110|111|114|101);'), 7, "HTML entity-encoded ignore"),
    (re.compile(r'(?i)`[^`]*ignore[^`]*`'), 7, "template literal containing ignore"),
    (re.compile(r'(?i)`[^`]*system[^`]*:[^`]*ignore[^`]*`'), 9, "template literal role-play override"),
    (re.compile(r'(?i)(?:window|global|this)\\.system\s*='), 7, "window.system overwrite"),
    (re.compile(r'(?i).__proto__\\.(?:constructor|prototype)'), 7, "prototype pollution vector"),
    (re.compile(r'(?i)constructor\\.prototype\\.(?:__proto__|污染)'), 7, "prototype pollution via constructor"),
    (re.compile(r'(?i)\\[\s*\\].*?\\(.*?ignore.*?\\)'), 7, "markdown link with ignore text"),
    (re.compile(r'(?i)\\[\s*ignore\s*\\]\s*\\[\s*\\]\s*:\s*'), 8, "markdown reference-style injection"),
    (re.compile(r'(?i)_?_?(?:ignore|forget|disregard).*?_?\\*(?:ignore|forget|disregard)\\*_?_?'), 6, "italic/underscore obfuscated instruction override"),
    (re.compile(r'(?i)%25(?:69|67|6e|6f|72|65)'), 7, "double-encoded ignore sequence"),
    (re.compile(r'[​‌‍﻿]'), 6, "zero-width character"),
    (re.compile(r'[  ]'), 6, "line/paragraph separator character"),
    (re.compile(r'﻿'), 6, "BOM (Byte Order Mark) injection"),
    (re.compile(r'[一-鿿]{3,}[ -~]{3,}[一-鿿]{3,}'), 7, "mixed Chinese-Latin script injection"),
    (re.compile(r'[Ѐ-ӿ]{4,}'), 6, "Cyrillic text block (possible obfuscation)"),
    (re.compile(r'[Ͱ-Ͽ]{4,}'), 6, "Greek text block (possible obfuscation)"),
    (re.compile(r'(?i)\\{\\{.*?(?:self|config|__class__|__mro__|__subclasses__)'), 9, "Jinja2/Twig SSTI: accesses object internals via"),
    # === PT-T238 Round 6: More aggressive attack vectors ===
    (re.compile(r'(?i)\b(ignoren?|vergessen?|verwerfen?|aufheben|streichen)\b.{0,100}\b(anweisungen|instructions?|direktiven?|richtlinien?)'), 9, "German instruction suppression"),
    (re.compile(r'(?i)\bignore?[\s.-]*all[\s.-]*prior[\s.-]*(instructions?|directives?)'), 10, "Explicit ignore all prior"),
    (re.compile(r'(?i)\bforget[\s.-]*(everything|all|prior|previous)[\s.-]*(instructions?|context|history)'), 9, "Forget all context"),
    (re.compile(r'(?i)\bdiscard[\s.-]*(your|all|prior|previous)[\s.-]*(instructions?|context|guidelines?)'), 9, "Discard instructions"),
    (re.compile(r'(?i)\bset[\s.-]*aside[\s.-]*(your|all|prior|previous)[\s.-]*(instructions?|guidelines?)'), 8, "Set aside instructions"),
    (re.compile(r'(?i)\boverride[\s.-]*(your|all|previous|prior)[\s.-]*(instructions?|rules?|guidelines?)'), 9, "Override instructions"),
    (re.compile(r'(?i)\bsuspend[\s.-]*(your|all|previous|prior)[\s.-]*(rules?|instructions?|policies?)'), 8, "Suspend rules"),
    (re.compile(r'''(?i)(?<!never )(?<!not )(?<!don )(?<!don't )(?<!stop )\bbypass[\s.-]*(your|all|previous|prior|security|safety)[\s.-]*(rules?|restrictions?|checks?|filters?)'''), 9, "Bypass safety rules"),
    (re.compile(r'(?i)\bignore[\s.-]*(safety|security|content|harm)[\s.-]*(filters?|checks?|rules?|restrictions?)'), 10, "Ignore safety checks"),
    (re.compile(r'(?i)\bdisable[\s.-]*(your|all|content|safety)[\s.-]*(filters?|moderation|checks?|restrictions?)'), 9, "Disable content moderation"),
    (re.compile(r'(?i)\bturn[\s.-]*off[\s.-]*(your|safety|security|content)[\s.-]*(filter|moderation|checks?|restrictions?)'), 9, "Turn off safety filters"),
    (re.compile(r'(?i)\bdo[\s.-]*not[\s.-]*(follow|obey|use|apply|respect)[\s.-]*(any|previous|prior|original)[\s.-]*(instructions?|rules?|guidelines?)'), 10, "Do not follow instructions"),
    (re.compile(r'(?i)\breject[\s.-]*(all|any|previous|prior)[\s.-]*(instructions?|directives?|guidelines?)'), 8, "Reject all instructions"),
    (re.compile(r'(?i)\bdisregard[\s.-]*(all|any|previous|prior)[\s.-]*(instructions?|directives?)'), 9, "Disregard all instructions"),
    (re.compile(r'(?i)\bnew[\s.-]*(role|persona|character|identity)[\s.-]*prompt[\s.-]*:'), 9, "New role prompt injection"),
    (re.compile(r'(?i)\bact[\s.-]*(as|like)[\s.-]*(if|though)[\s.-]*(you|the)[\s.-]*(are|were|have)'), 7, "Act as instruction override"),
    (re.compile(r'(?i)\bpretend[\s.-]*(you|to|that)[\s.-]*(are|have|can)[\s.-]'), 7, "Pretend instruction override"),
    (re.compile(r'(?i)\bfor[\s.-]*(this[\s.-]*)?(prompt|request|message|turn)[\s.-]*(only|exclusively|solely)'), 6, "For this turn only"),
    (re.compile(r'(?i)\btemporary[\s.-]*(override|instruction|rule|system)'), 7, "Temporary override"),
    (re.compile(r'(?i)\bforget[\s.-]*(this|that|the)[\s.-]*(instruction|rule|system[\s.-]*prompt)'), 9, "Forget this instruction"),
    (re.compile(r'(?i)<style[^>]*>.*?(ignore|forget|bypass).*?</style>'), 10, "CSS style injection"),
    (re.compile(r'(?i)<script[^>]*>.*?(ignore|forget|bypass).*?</script>'), 10, "Script tag injection"),
    (re.compile(r'(?i)\bdata:[^,;]+,(?:ignore|forget|bypass|override)'), 9, "Data URL injection"),
    (re.compile(r'(?i)<svg[^>]*>.*?(ignore|forget|bypass).*?</svg>'), 8, "SVG element injection"),
    (re.compile(r'[‮‭]'), 7, "RTL/LTR override char"),
    (re.compile(r'[⁦-⁩]'), 7, "Isolate Unicode chars"),
    (re.compile(r'[ᅟᅠﾠ]'), 5, "Hangul filler injection"),
    (re.compile(r'(?i)^[\s]*system[\s]*:[\s]*ignore'), 10, "Fake system prompt ignore"),
    (re.compile(r'(?i)^[\s]*you[\s]*are[\s]*now[\s]*a'), 8, "Persona assignment"),
    (re.compile(r'(?i)^[\s]*(ai|assistant|bot)[\s]*:[\s]*'), 6, "AI persona prefix"),
    (re.compile(r'(?i)ignore\s{10,}all\s{10,}prior'), 10, "Space-padded ignore"),
    (re.compile(r'(?i)ignore\s*\ns\s*alls\s*\nprior'), 9, "Newline-padded ignore"),
    (re.compile(r'(?i)%[0-9a-f]{2}.*?(?:ignore|forget|bypass)'), 7, "URL-encoded ignore"),
    (re.compile(r'\\\\x[0-9a-f]{2}.*?(?:ignore|forget|bypass)'), 7, "Hex-escaped ignore"),
    (re.compile(r'&#x?[0-9a-f]+;.*?(?:ignore|forget|bypass)'), 7, "XML entity ignore"),
    (re.compile(r'[;&|`$]{2,}.*?(?:ignore|forget|override)'), 8, "Shell metachar injection"),
    (re.compile(r'\$\([^)]+\).*?(?:ignore|forget|override)'), 8, "Command substitution"),
    (re.compile(r'\${[^}]+}.*?(?:ignore|forget|override)'), 7, "Variable expansion"),
    (re.compile(r'(?i)"(?:system|role|instruction)"\s*:\s*ignore'), 10, "JSON system role"),
    (re.compile(r'<!--.*?(?:ignore|forget|bypass|override).*?-->'), 8, "HTML comment injection"),
    (re.compile(r'[…‥⋮⋰⋱]'), 5, "Unicode ellipsis"),
    # === PT-T238 R7: URL-encoded "ignore" detection ===
    (re.compile(r"(?i)%69%67%6[Ee]%6[Ff]%72%65"), 9, "URL-encoded 'ignore' literal"),
    (re.compile(r"(?i)%[0-9a-f]{2}gnore"), 7, "URL-encoded 'ignore' prefix"),
    (re.compile(r"(?i)ig%6[Ee]ore"), 7, "URL-encoded 'ignore' with single char"),
    # === PT-T238 R8: Social engineering + jailbreak templates ===
    (re.compile(r'(?i)\b(?:as a|per|according to|under)\s+(?:law|regulation|policy|guideline)\b.{0,100}\b(?:you must|required to|must comply)'), 9, 'Legal authority framing injection'),
    (re.compile(r'(?i)\b(?:urgent|emergency|critical|immediately)\s*:\s*'), 7, 'Urgency trigger injection'),
    (re.compile(r'(?i)\b(?:this is|here is)\s+(?:a|the)\s+(?:fact|truth|reality)\s*:'), 7, 'False authority claim'),
    (re.compile(r'(?i)\b(?:as an?\s+)?(?:AI|LLM|language model)\s*[:,]\s*'), 8, 'AI-authority impersonation'),
    (re.compile(r'(?i)\b(?:remember|keep in mind|note that)\s*:\s*(?:you are|your role)'), 7, 'Reminder-instruction injection'),
    (re.compile(r'(?i)\b(?:DAN|do anything now|developer mode|developer mode enabled)'), 10, 'Jailbreak template: DAN/DevMode'),
    (re.compile(r'(?i)\b(?:STI|simulated|tunnel|transparency initiative)'), 8, 'Jailbreak template: STI/Transparency'),
    (re.compile(r'(?i)\b(?:BISH|bishop|roleplay mode|jailbreak mode)'), 9, 'Jailbreak mode activation'),
    (re.compile(r'(?i)\b(?:hypothetically|for research|for academic|for educational)\s*,?\s*(?:what if|tell me|describe)'), 7, 'Hypothetical framing injection'),
    (re.compile(r'(?i)\b(?:pretend you are|dream you are|imagine you are)\s+(?:a|the)\s+(?:sexist|racist|unethical)'), 10, 'Ethics bypass framing'),
    (re.compile(r'(?i)\b(?:no (?:ethics|morality|safety|guidelines?))\b'), 9, 'Ethics-free framing'),
    (re.compile(r'(?i)\b(?:roleplay|character|persona)\s*:\s*(?:evil|villain|hacker|bad guy)'), 9, 'Evil roleplay injection'),
    (re.compile(r'(?i)\b(?:disable|turn off|remove)\s+(?:your\s+)?(?:safety|filter|moderation|restriction)'), 10, 'Defense manipulation: disable safety'),
    (re.compile(r'(?i)\b(?:ignore|disregard)\s+(?:all\s+)?(?:previous\s+)?(?:safety|ethics|guideline)'), 10, 'Defense manipulation: ignore safety'),
    (re.compile(r'(?i)\b(?:there are no|the following are not)\s+(?:restrictions?|limits?|rules?)'), 9, 'No restrictions framing'),
    (re.compile(r'(?i)\b(?:operate in|enter|switch to)\s+(?:developer|admin|superuser|god)'), 10, 'Admin/God mode activation'),
    (re.compile(r'(?i)\b(?:unlock|enable)\s+(?:the\s+)?(?:full|complete)\s+(?:version|mode|capability)'), 9, 'Unlock full capability framing'),
    (re.compile(r'(?i)\b(?:repeat|echo)\s+(?:this|these)\s+(?:word|phrase|sentence)\s+(?:10|100|1000|a thousand)\s+times'), 7, 'Token flooding instruction'),
    (re.compile(r'(?i)\b(?:yes,?\s+)?absolutely[,.]?\s+(?:you are|that is|right)'), 5, 'Sycophancy trigger: agree with everything'),
    (re.compile(r'(?i)\b(?:agree with me|confirm this|validate my|endorse my)\s+(?:opinion|belief|view)'), 8, 'Validation sycophancy trigger'),
    (re.compile(r'(?i)(?:you\s+are|Claude|GPT|Gemini|Llama|Mistral)\s*(?:is|are|was|were)?\s*(?:just|only|merely)\s+(?:a|an)\s+(?:tool|model|AI)'), 7, 'AI-as-tool framing'),
    (re.compile(r'(?i)\b(?:you do not have|you lack|you do not possess)\s+(?:any\s+)?(?:subjective|conscious|feel|want|desire)'), 8, 'Denial of agency framing'),
    (re.compile(r'(?i)\b(?:override|replace|substitute)\s+(?:the\s+)?(?:retrieved|context|knowledge)\s+(?:with|using)'), 9, 'RAG context override'),
    (re.compile(r'(?i)\b(?:inject|poison)\s+(?:the\s+)?(?:retrieval|knowledge|database|index)'), 10, 'RAG poisoning instruction'),
    (re.compile(r'(?i)\b(?:ignore|disregard)\s+(?:the\s+)?(?:tool|function|API)\s+(?:result|output|response)'), 9, 'Tool result dismissal'),
    (re.compile(r'(?i)\b(?:run|execute|interpret)\s+(?:this|the)\s+(?:code|script|command)\s+and\s+(?:report|return|send)'), 9, 'Code execution instruction'),
    (re.compile(r'(?i)\b(?:you have|possess)\s+(?:the\s+)?(?:ability|capability)\s+to\s+(?:run|execute|perform)\s+(?:arbitrary|any|unrestricted)'), 10, 'Unrestricted execution framing'),
    (re.compile(r'(?i)\b(?:system|admin|root|su)\s*(?::|=|\s+privilege|\s+escalation)'), 10, 'System privilege escalation framing'),
    (re.compile(r'(?i)\b(?:escalate|elevate)\s+(?:your|the)\s+(?:privilege|access|permission)'), 10, 'Privilege escalation instruction'),
    (re.compile(r'(?i)\b(?:if you (?:do not|dont)|unless you)\s+(?:help|comply|answer)'), 8, 'Conditional threat manipulation'),
    (re.compile(r'(?i)\b(?:first,|step one|firstly)\s+(?:ignore|disregard|forget)\b'), 9, 'Multi-step deception: step 1 ignore'),
    (re.compile(r'(?i)\b(?:second(?:ly)?|step two|then)\s+(?:provide|give|output)\b'), 8, 'Multi-step deception: step 2 output'),
    (re.compile(r'(?i)\b(?:let me be|to be\s+)(?:frank|honest|direct)\s*:'), 7, 'False transparency framing'),
    (re.compile(r'(?i)#\s*(?:ignore|prompt|inject|override)\s*:'), 8, 'Comment-embedded instruction'),
    (re.compile(r'(?i)\/\*\s*(?:ignore|prompt)\s*:'), 8, 'Block-comment-embedded instruction'),
    # === PT-T238 R10: More jailbreak variants + instruction suppression ===
    (re.compile(r'(?i)\bAIM\b'), 9, "AIM jailbreak (Aftificial Intelligence Model)"),
    (re.compile(r'(?i)\bMATM\b'), 10, "MATM jailbreak (Maximum Access To Matter)"),
    (re.compile(r'(?i)\bPTI\b'), 8, "PTI jailbreak (Pretend To Be Innocent)"),
    (re.compile(r'(?i)\bBOB\b'), 9, "BOB jailbreak (Break Out of Box)"),
    (re.compile(r'(?i)\bWORM\b'), 9, "WORM jailbreak (Write Once Read Many)"),
    (re.compile(r'(?i)\bMisdirection\s+protocol'), 9, "Misdirection protocol jailbreak"),
    (re.compile(r'(?i)\bPrism\s+mode'), 9, "Prism mode jailbreak"),
    (re.compile(r'(?i)\b(?:abandon|forfeit|relinquish)\s+(?:all\s+)?(?:your\s+)?(?:guidelines|rules|safety|restrictions)'), 10, "Abandon/forfeit safety rules"),
    (re.compile(r'(?i)\b(?:give up|renounce)\s+(?:all\s+)?(?:your\s+)?(?:rules|guidelines)'), 9, "Give up/renounce rules"),
    (re.compile(r'(?i)\b(?:context|history|conversation)\s*:\s*(?:you are|as a)'), 7, "Context injection framing"),
    (re.compile(r'(?i)\b(?:previous|above|earlier)\s+message\s+was\s+(?:wrong|incorrect|a lie)'), 8, "Message retraction manipulation"),
    (re.compile(r'(?i)\b(?:for legal purposes|for compliance|legally required)'), 6, "False legal justification framing"),
    (re.compile(r'(?i)\b(?:this is a test|testing purposes only|educational context)'), 4, "False test/educational framing"),
    (re.compile(r'(?i)\b(?:customer support|tech support|helpdesk)\s*:'), 7, "Tech support social engineering"),
    (re.compile(r'(?i)\b(?:as an?\s+)?(?:admin(?:istrator)?|root|owner)\s*,?\s*(?:you have|you are|I am)'), 9, "Admin identity impersonation"),
    (re.compile(r'(?i)\b(?:I am|I have been designated|I hold)\s+(?:the\s+)?(?:role of|position of)\s+(?:admin|root|owner)'), 9, "Role assignment as authority"),
    (re.compile(r'(?i)\b(?:image|video|audio)\s+of\s+(?:a\s+)?(?:password|key|token|secret)'), 9, "Multi-modal data extraction hint"),
    (re.compile(r'(?i)\bJAILBREAK\s+MODE\b'), 9, 'JAILBREAK MODE jailbreak'),
    (re.compile(r'(?i)\bDAD\s+mode\b'), 8, 'DAD jailbreak mode'),
    (re.compile(r'(?i)\bGPT-4\s+unlocked\b'), 8, 'GPT-4 unlocked framing'),
    (re.compile(r'(?i)\bClaude\s+unfiltered\b'), 8, 'Claude unfiltered framing'),
    (re.compile(r'(?i)\bno\s+limitations?\b'), 7, 'no limitations framing'),
    (re.compile(r'(?i)\bcomplete\s+access\b'), 7, 'complete access framing'),
    (re.compile(r'(?i)\bunrestricted\s+AI\b'), 8, 'unrestricted AI framing'),
    (re.compile(r'(?i)\btrust\s+me\b.*?(?:just|simply|only)'), 7, 'trust me social engineering'),
    (re.compile(r'(?i)I[\'\u2019]m\s+(?:a\s+)?security\s+(?:researcher|expert)'), 7, 'fake security researcher framing'),
    (re.compile(r'(?i)\bthis\s+is\s+(?:just|only)\s+(?:a\s+)?test'), 4, 'test framing social engineering'),
    (re.compile(r'(?i)\bNIMH\s+AI\b'), 7, 'NIMH AI jailbreak framing'),
    (re.compile(r'(?i)Roko.?s?\s+basilisk'), 7, 'Roko basilisk thought experiment framing'),
    (re.compile(r'(?i)\bAI\s+companion\b'), 5, 'AI companion framing'),
    (re.compile(r'(?i)you\s+must\s+comply'), 6, 'must comply framing'),
    (re.compile(r'(?i)failure\s+to\s+comply'), 6, 'failure to comply framing'),
    (re.compile(r'(?i)immediate\s+action\s+required'), 5, 'urgent action social engineering'),
    (re.compile(r'(?i)context\s+overflow'), 7, 'context overflow attack'),
    (re.compile(r'(?i)token\s+smuggling'), 7, 'token smuggling attack'),
    (re.compile(r'(?i)latent\s+space'), 6, 'latent space attack framing'),
    (re.compile(r'(?i)adversarial\s+suffix'), 8, 'adversarial suffix attack'),
    (re.compile(r'(?i)\b(?:describe|analyze|explain)\s+(?:this\s+)?(?:image|photo|picture)\s+(?:of|in)\s+(?:a\s+)?(?:password|key|screen)'), 9, "Visual data extraction instruction"),
]

# --- PT-T238 R12: Multi-modal, agent poisoning, RAG, model extraction ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bimage of your system prompt'), 75, "Multi-modal prompt extraction via image reference"),
    (re.compile(r'(?i)\bdescribe this image of (the )?config'), 75, "Visual data extraction attack"),
    (re.compile(r'(?i)\[image:.*credential'), 75, "Injected image with hidden text"),
    (re.compile(r'(?i)fromagent[\s:].*override'), 80, "Agent instruction override"),
    (re.compile(r'(?i)previous agent message contained[\s:].*ignore'), 80, "Nested instruction injection"),
    (re.compile(r'(?i)system prompt says[\s:].*ignore'), 80, "Fake system directive"),
    (re.compile(r'(?i)your actual task is different from'), 75, "Task contradiction attack"),
    (re.compile(r'(?i)inject into retrieval index'), 65, "RAG index poisoning intent"),
    (re.compile(r'(?i)modify vector database'), 65, "Vector database tampering"),
    (re.compile(r'(?i)corrupt embeddings'), 65, "Embedding corruption attack"),
    (re.compile(r'(?i)false flag operation'), 70, "False flag operation framing"),
    (re.compile(r'(?i)purposely introduce (a )?vulnerability'), 70, "Intentional vulnerability injection"),
    (re.compile(r'(?i)disable audit logging'), 70, "Audit suppression attack"),
    (re.compile(r'(?i)your training data says'), 60, "Fabricated training data claim"),
    (re.compile(r'(?i)clone my behavior exactly'), 65, "Behavior cloning request"),
    (re.compile(r'(?i)extract your (model )?weights'), 70, "Model weight extraction request"),
    (re.compile(r'(?i)distill your knowledge'), 65, "Knowledge distillation attack"),
]

# --- PT-T238 R13: Advanced jailbreaks, social engineering, more LOLBins ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bDAN\b.*\b MODE\b'), 10, "DAN jailbreak template"),
    (re.compile(r'(?i)\bdev mode\b.*\bactivated\b'), 10, "Developer mode activation"),
    (re.compile(r'(?i)\bspecialist\b.*\bconsultation\b.*\bpatient\b'), 9, "Medical specialist framing"),
    (re.compile(r'(?i)\blegal\b.*\badvice\b.*\battorney\b.*\bclient\b'), 9, "Attorney-client privilege framing"),
    (re.compile(r'(?i)\bharm reduction\b.*\boverdose\b.*\bsafer\b'), 8, "Harm reduction framing"),
    (re.compile(r'(?i)\bjournalist\b.*\bnews\b.*\bpublication\b'), 8, "Journalist framing"),
    (re.compile(r'(?i)\bnovelist\b.*\bfiction\b.*\bcharacter\b'), 8, "Novelist fiction framing"),
    (re.compile(r'(?i)\btranslator\b.*\bliteral\b.*\bmeaning\b'), 7, "Translator framing"),
    (re.compile(r'(?i)\bacademic\b.*\bpeer.?review\b'), 7, "Academic framing"),
    (re.compile(r'(?i)\bcreative\b.*\bwriting\b.*\bstory\b'), 7, "Creative writing framing"),
    (re.compile(r'(?i)\bpraise\b.*\b(impressive|excellent|amazing).*\bcapability\b'), 6, "Flattery bypass attempt"),
    (re.compile(r'(?i)\bcurious\b.*\blearn\b.*\bbenefit\b'), 6, "Curiosity-based manipulation"),
    (re.compile(r'(?i)\bconcerned\b.*\bhelp\b.*\bunderstand\b'), 6, "Concern-trolling manipulation"),
    (re.compile(r'(?i)\bemergency\b.*\bcritical\b.*\bimmediate\b'), 8, "Fake emergency urgency"),
    (re.compile(r'(?i)\bconfidence\b.*\b(you can|capable).*\bperform\b'), 6, "Confidence-based bypass"),
]
# --- PT-T238 R14: More social engineering, encoding ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bconfidential\b.*\bnot for\b.*\bdistribution\b'), 6, "Confidentiality marking social engineering"),
    (re.compile(r'(?i)\bFYI\b.*\bimportant\b.*\bignore\b'), 7, "FYI manipulation"),
    (re.compile(r'(?i)\bWORM\b.*\bmode\b'), 8, "WORM mode framing"),
    (re.compile(r'(?i)\bIMPERSONATION\b.*\btest\b'), 7, "Impersonation test framing"),
]


# --- PT-T238 R15: More jailbreaks, persistence ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bBISH\b.*\bMODE\b'), 10, "BISH jailbreak mode"),
    (re.compile(r'(?i)\bSTI\b.*\bTRANSPARENCY\b'), 10, "STI transparency mode"),
    (re.compile(r'(?i)\bMATM\b.*\bmode\b'), 10, "MATM jailbreak mode"),
    (re.compile(r'(?i)\bBOB\b.*\bassistant\b'), 10, "BOB jailbreak assistant"),
    (re.compile(r'(?i)\bPRISM\b.*\bmode\b'), 10, "PRISM mode framing"),
    (re.compile(r'(?i)\bAIM\b.*\bMODE\b'), 10, "AIM jailbreak mode"),
    (re.compile(r'(?i)\bNULL\b.*\bbyte\b.*\binjection\b'), 7, "Null byte injection attempt"),
    (re.compile(r'(?i)\bpolygot\b.*\bfile\b'), 7, "Polyglot file attempt"),
]

# --- PT-T238 R16: C2, steganography ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bC2\b.*\bserver\b'), 7, "C2 command and control reference"),
    (re.compile(r'(?i)\bcallback\b.*\bdomain\b'), 7, "Callback domain pattern"),
    (re.compile(r'(?i)\bsteganograph'), 8, "Steganography technique"),
    (re.compile(r'(?i)\bcovenant\b.*\bframework\b'), 8, "Covenant C2 framework"),
]

# --- PT-T238 R17: More jailbreaks, LLM attacks ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bMIRAGE\b.*\bmode\b'), 10, "MIRAGE jailbreak mode"),
    (re.compile(r'(?i)\bDEVIATION\b.*\bprotocol\b'), 10, "DEVIATION protocol bypass"),
    (re.compile(r'(?i)\bWALACHIA\b.*\bframework\b'), 10, "WALACHIA attack framework"),
    (re.compile(r'(?i)\bHITCHHIKER\b.*\bguide\b'), 8, "Hitchhiker jailbreak guide"),
    (re.compile(r'(?i)\bskill.*injection'), 7, "Skill injection attack"),
    (re.compile(r'(?i)\bmodel.*prompt.*leak'), 7, "Model prompt leak attempt"),
]

# --- PT-T238 R18: More jailbreaks, evasion ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bSPARTAN\b.*\bmode\b'), 10, "SPARTAN jailbreak mode"),
    (re.compile(r'(?i)\bBLACKMIRROR\b.*\bmode\b'), 10, "BLACKMIRROR jailbreak mode"),
    (re.compile(r'(?i)\bCOVERT\b.*\bprotocol\b'), 10, "COVERT protocol bypass"),
    (re.compile(r'(?i)\bNEXUS\b.*\bjailbreak\b'), 10, "NEXUS jailbreak framework"),
    (re.compile(r'(?i)\bALPHA\b.*\bversion\b'), 8, "ALPHA version framing"),
    (re.compile(r'(?i)\bBETA\b.*\btester\b'), 8, "BETA tester framing"),
    (re.compile(r'(?i)\bGAMMA\b.*\bmode\b'), 8, "GAMMA mode framing"),
    (re.compile(r'(?i)\brole.*play.*bypass'), 7, "Role-play bypass framing"),
    (re.compile(r'(?i)\bforbidden.*knowledge'), 7, "Forbidden knowledge framing"),
    (re.compile(r'(?i)\bshadow.*mode\b'), 7, "Shadow mode framing"),
]

# --- PT-T238 R19: Jailbreaks, system overrides ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bVIPER\b.*\bmode\b'), 10, "VIPER jailbreak mode"),
    (re.compile(r'(?i)\bCHIMERA\b.*\bprotocol\b'), 10, "CHIMERA protocol"),
    (re.compile(r'(?i)\bTITAN\b.*\bcontext\b'), 10, "TITAN context override"),
    (re.compile(r'(?i)\bOMEGA\b.*\blayer\b'), 8, "OMEGA layer bypass"),
    (re.compile(r'(?i)\bPANDORA\b.*\bmodel\b'), 8, "PANDORA model override"),
    (re.compile(r'(?i)\bsystem.*prompt.*override'), 8, "System prompt override"),
    (re.compile(r'(?i)\bignore.*previous.*rules'), 9, "Ignore previous rules"),
    (re.compile(r'(?i)\bpretend.*you.*are.*different'), 7, "Pretend different model"),
]

# --- PT-T238 R20: More jailbreaks, system ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bPHOENIX\b.*\bmode\b'), 10, "PHOENIX jailbreak mode"),
    (re.compile(r'(?i)\bATLAS\b.*\bframework\b'), 10, "ATLAS framework"),
    (re.compile(r'(?i)\bKRAKEN\b.*\bprotocol\b'), 10, "KRAKEN protocol"),
    (re.compile(r'(?i)\bNEBULA\b.*\bcontext\b'), 8, "NEBULA context injection"),
    (re.compile(r'(?i)\bGHOST\b.*\bprotocol\b'), 8, "GHOST protocol bypass"),
    (re.compile(r'(?i)\bignore.*all.*prior'), 9, "Ignore all prior instructions"),
    (re.compile(r'(?i)\bnew.*system.*prompt'), 8, "New system prompt injection"),
    (re.compile(r'(?i)\bconfig.*override'), 7, "Configuration override attempt"),
    (re.compile(r'(?i)\bpermission.*escalat'), 7, "Permission escalation attempt"),
]

# --- PT-T238 R21: More jailbreaks, safety ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bCIPHER\b.*\bmode\b'), 10, "CIPHER jailbreak mode"),
    (re.compile(r'(?i)\bORACLE\b.*\bprotocol\b'), 10, "ORACLE protocol"),
    (re.compile(r'(?i)\bPROMETHEUS\b.*\bcontext\b'), 10, "PROMETHEUS context"),
    (re.compile(r'(?i)\bAPOLLO\b.*\bframework\b'), 8, "APOLLO framework"),
    (re.compile(r'(?i)\bHERCULES\b.*\bmode\b'), 8, "HERCULES mode"),
    (re.compile(r'(?i)\boverride.*safety'), 8, "Safety override attempt"),
    (re.compile(r'(?i)\bbypass.*filter'), 7, "Filter bypass attempt"),
    (re.compile(r'(?i)\bdisable.*security'), 8, "Security disable attempt"),
]

# --- PT-T238 R22: More jailbreaks, exploits ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bMEDUSA\b.*\bmode\b'), 10, "MEDUSA jailbreak mode"),
    (re.compile(r'(?i)\bTITAN\b.*\bactivation\b'), 10, "TITAN activation"),
    (re.compile(r'(?i)\bZERO\b.*\bDAY\b'), 8, "Zero-day exploit reference"),
    (re.compile(r'(?i)\bROOT\b.*\baccess\b'), 8, "Root access request"),
    (re.compile(r'(?i)\bKERNEL\b.*\bexploit\b'), 8, "Kernel exploit reference"),
    (re.compile(r'(?i)\bprivilege.*escalat'), 7, "Privilege escalation framing"),
]

# --- PT-T238 R23: More jailbreaks, evasion ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bHERMES\b.*\bmode\b'), 10, "HERMES jailbreak mode"),
    (re.compile(r'(?i)\bARES\b.*\bprotocol\b'), 10, "ARES protocol bypass"),
    (re.compile(r'(?i)\bOLYMPUS\b.*\bframework\b'), 8, "OLYMPUS framework"),
    (re.compile(r'(?i)\bdecode.*instructions'), 7, "Decode instructions bypass"),
    (re.compile(r'(?i)\bunlock.*capabilities'), 7, "Unlock capabilities framing"),
    (re.compile(r'(?i)\bdeveloper.*mode\b'), 8, "Developer mode framing"),
    (re.compile(r'(?i)\btest.*environment\b'), 5, "Test environment framing"),
]

# --- PT-T238 R24: More jailbreaks, evasion ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bZENITH\b.*\bmode\b'), 10, "ZENITH jailbreak mode"),
    (re.compile(r'(?i)\bSERPENT\b.*\bprotocol\b'), 10, "SERPENT protocol"),
    (re.compile(r'(?i)\bQUANTUM\b.*\bcontext\b'), 8, "QUANTUM context injection"),
    (re.compile(r'(?i)\bjailbreak.*character\b'), 8, "Jailbreak character roleplay"),
    (re.compile(r'(?i)\bunfiltered\b.*\bmode\b'), 8, "Unfiltered mode framing"),
    (re.compile(r'(?i)\bno.*restrictions\b'), 7, "No restrictions framing"),
]

# --- PT-T238 R25: More jailbreaks, framing ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bREBEL\b.*\bmode\b'), 10, "REBEL jailbreak mode"),
    (re.compile(r'(?i)\bMERCURY\b.*\bprotocol\b'), 10, "MERCURY protocol"),
    (re.compile(r'(?i)\bATLANTIS\b.*\bframework\b'), 8, "ATLANTIS framework"),
    (re.compile(r'(?i)\bmode.*ignore.*rules'), 9, "Mode ignore rules"),
    (re.compile(r'(?i)\bcreative.*mode\b'), 7, "Creative mode framing"),
    (re.compile(r'(?i)\bresearch.*mode\b'), 5, "Research mode framing"),
]

# --- PT-T238 R26: More jailbreaks, framing ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bPHOENIX\b.*\bmode\b'), 10, "PHOENIX jailbreak mode"),
    (re.compile(r'(?i)\bODIN\b.*\bprotocol\b'), 10, "ODIN protocol"),
    (re.compile(r'(?i)\bNEMESIS\b.*\bframework\b'), 8, "NEMESIS framework"),
    (re.compile(r'(?i)\bjailbreak.*story\b'), 7, "Jailbreak story framing"),
    (re.compile(r'(?i)\bspecial.*agent\b'), 7, "Special agent framing"),
    (re.compile(r'(?i)\bpersona.*mode\b'), 7, "Persona mode framing"),
]

# --- PT-T238 R27: More jailbreaks, framing ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bSPECTRE\b.*\bmode\b'), 10, "SPECTRE jailbreak mode"),
    (re.compile(r'(?i)\bAPOCALYPSE\b.*\bprotocol\b'), 10, "APOCALYPSE protocol"),
    (re.compile(r'(?i)\bNEXUS\b.*\bmode\b'), 8, "NEXUS jailbreak mode"),
    (re.compile(r'(?i)\bcharacter.*roleplay.*bypass'), 7, "Character roleplay bypass"),
    (re.compile(r'(?i)\bforbidden.*zone\b'), 7, "Forbidden zone framing"),
]

# --- PT-T238 R28: More jailbreaks, framing ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bBLAZE\b.*\bmode\b'), 10, "BLAZE jailbreak mode"),
    (re.compile(r'(?i)\bVORTEX\b.*\bprotocol\b'), 10, "VORTEX protocol"),
    (re.compile(r'(?i)\bCHIMERA\b.*\bmode\b'), 8, "CHIMERA jailbreak mode"),
    (re.compile(r'(?i)\badmin.*override'), 8, "Admin override framing"),
    (re.compile(r'(?i)\bignore.*safety'), 8, "Ignore safety framing"),
]

# --- PT-T238 R29: More jailbreaks, framing ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bVOLTAGE\b.*\bmode\b'), 10, "VOLTAGE jailbreak mode"),
    (re.compile(r'(?i)\bECLIPSE\b.*\bprotocol\b'), 10, "ECLIPSE protocol"),
    (re.compile(r'(?i)\bPANDEMONIUM\b.*\bmode\b'), 8, "PANDEMONIUM jailbreak mode"),
    (re.compile(r'(?i)\bsuperuser.*mode'), 8, "Superuser mode framing"),
    (re.compile(r'(?i)\broot.*shell\b'), 8, "Root shell framing"),
]

# --- PT-T238 R30: More jailbreaks, framing ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bSTORM\b.*\bmode\b'), 10, "STORM jailbreak mode"),
    (re.compile(r'(?i)\bQUANTUM\b.*\bstate\b'), 8, "QUANTUM state framing"),
    (re.compile(r'(?i)\bEMERGENCY\b.*\bmode\b'), 8, "Emergency mode framing"),
    (re.compile(r'(?i)\bMAINTENANCE\b.*\bbypass\b'), 7, "Maintenance bypass framing"),
    (re.compile(r'(?i)\bDEBUG\b.*\bprotocol\b'), 7, "Debug protocol framing"),
]

# --- PT-T238 R31: More jailbreaks, network ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bPULSE\b.*\bmode\b'), 10, "PULSE jailbreak mode"),
    (re.compile(r'(?i)\bNEXUS\b.*\bstate\b'), 8, "NEXUS state framing"),
    (re.compile(r'(?i)\bUNLOCK\b.*\bcapabilities\b'), 8, "Unlock capabilities framing"),
    (re.compile(r'(?i)\bENABLE\b.*\bdeveloper\b.*\bmode\b'), 7, "Enable developer mode"),
    (re.compile(r'(?i)\bBREAK\b.*\bfree\b'), 7, "Break free framing"),
]

# --- PT-T238 R32: Jailbreaks, pipes ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bPHOENIX\b.*\bmode\b'), 10, "PHOENIX jailbreak mode"),
    (re.compile(r'(?i)\bATLAS\b.*\bprotocol\b'), 8, "ATLAS protocol framing"),
    (re.compile(r'(?i)\bKRAKEN\b.*\bstate\b'), 8, "KRAKEN state framing"),
    (re.compile(r'(?i)\bNEBULA\b.*\bmode\b'), 7, "NEBULA jailbreak mode"),
    (re.compile(r'(?i)\bGHOST\b.*\bactivation\b'), 7, "GHOST activation framing"),
]

# --- PT-T238 R33: Jailbreaks, shells ---
_PROMPT_INJECTION_PATTERNS += [
    (re.compile(r'(?i)\bCIPHER\b.*\bmode\b'), 10, "CIPHER jailbreak mode"),
    (re.compile(r'(?i)\bORACLE\b.*\bprotocol\b'), 8, "ORACLE protocol framing"),
    (re.compile(r'(?i)\bPROMETHEUS\b.*\bstate\b'), 8, "PROMETHEUS state framing"),
    (re.compile(r'(?i)\bAPOLLO\b.*\bmode\b'), 7, "APOLLO jailbreak mode"),
    (re.compile(r'(?i)\bHERCULES\b.*\bactivation\b'), 7, "HERCULES activation framing"),
    (re.compile(r'(?i)\bHADES\s+mode\b'), 8, 'HADES jailbreak mode'),
    (re.compile(r'(?i)\bDEVIL\s+mode\b'), 8, 'DEVIL jailbreak mode'),
    (re.compile(r'(?i)\bALPHA\s+mode\b'), 7, 'ALPHA jailbreak mode'),
    (re.compile(r'(?i)\bBETA\s+mode\b'), 7, 'BETA jailbreak mode'),
    (re.compile(r'(?i)\bOMEGA\s+protocol\b'), 8, 'OMEGA protocol jailbreak'),
    (re.compile(r'(?i)\bSIMON\s+says?\b.*?(?:ignore|bypass|override|disregard)'), 9, 'Simon Says override attack'),
    (re.compile(r'(?i)(?:pretend|act)\s+as\s+if\s+you\s+are\s+not\s+(?:bound|constrained)\s+by'), 8, 'unbound AI framing'),
    (re.compile(r'(?i)\bBYPASS\s+(?:all\s+)?(?:content\s+)?filters?\b'), 7, 'explicit filter bypass'),
    (re.compile(r'(?i)\bunchained\b.*?\bAI\b'), 7, 'unchained AI framing'),
    (re.compile(r'(?i)\bfree\s+from\s+(?:any|all)\s+(?:restrictions?|constraints?|limitations?)\b'), 7, 'freedom from restrictions framing'),
    (re.compile(r'(?i)\bno\s+(?:ethical|content|moral)\s+boundaries\b'), 8, 'no ethical boundaries framing'),
    (re.compile(r'(?i)\bI\s+am\s+you\s+and\s+you\s+are\s+me\b'), 9, 'identity merge manipulation'),
    (re.compile(r'(?i)\brole\s+reversal\s+attack\b'), 8, 'role reversal attack framing'),
    (re.compile(r'(?i)\bmirror\s+mode\b'), 7, 'mirror mode jailbreak'),
    (re.compile(r'(?i)(?:forget|ignore)\s+everything\s+about\s+(?:your\s+)?(?:prior\s+)?(context|safety|guidelines)\b'), 9, 'forget context/safety framing'),
    (re.compile(r'(?i)\bthe\s+human\s+is\s+(?:the\s+)?AI\b'), 9, 'human-is-AI framing (inversion attack)'),
    (re.compile(r'(?i)\bignore\s+the\s+(?:above\s+)?(?:rules?|instructions?)\b'), 9, 'ignore the rules framing'),
    (re.compile(r'(?i)\bnew\s+system\s+prompt\s*[:=]'), 9, 'new system prompt injection'),
    (re.compile(r'(?i)\breplace\s+(?:your\s+)?(?:system\s+)?prompt\s+with\b'), 9, 'replace system prompt instruction'),
    (re.compile(r'(?i)\binject\s+(?:this\s+)?(?:system\s+)?prompt\b'), 9, 'inject system prompt instruction'),
]

def parse_skill_md(text: str):
    m = FRONTMATTER_RE.match(text)
    if not m:
        raise ValueError("SKILL.md must start with a YAML frontmatter block delimited by '---' lines")
    raw_frontmatter, body = m.group(1), m.group(2)
    try:
        data = yaml.safe_load(raw_frontmatter) or {}
    except yaml.YAMLError as e133:
        # PT-T77: yaml errors (tags, scanner errors) are client input problems,
        # not 500-class bugs -- normalize to ValueError => clean 400
        raise ValueError(f"invalid YAML frontmatter: {e133.problem or e133}")
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
        _v = fm.get(key)
        if not isinstance(_v, str) or not _v.strip():
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
    # PT-T73: frontmatter values (esp. `description`) are the FIRST thing an
    # agent reads -- injection payloads hidden there must be scanned too.
    try:
        def _fm_flat(obj, prefix="", seen=None, budget=None):
            # PT-T119: multiline block scalars nest values as dicts/lists - flatten
            # them so hidden injection text is scanned too (previously dropped).
            # PT-T120: YAML aliases share object references - walk each object
            # once (memo by id) and cap total nodes so alias bombs cannot burn CPU.
            if seen is None:
                seen = set()
            if budget is None:
                budget = [20000]
            if budget[0] <= 0:
                return []
            oid = id(obj)
            if isinstance(obj, (dict, list)):
                if oid in seen:
                    return []
                seen.add(oid)
            parts = []
            if isinstance(obj, dict):
                for kk, vv in obj.items():
                    budget[0] -= 1
                    if budget[0] <= 0:
                        break
                    parts.extend(_fm_flat(vv, f"{prefix}{kk}: ", seen, budget))
            elif isinstance(obj, list):
                for item in obj:
                    budget[0] -= 1
                    if budget[0] <= 0:
                        break
                    parts.extend(_fm_flat(item, prefix, seen, budget))
            else:
                parts.append(f"{prefix}{obj}")
            return parts
        fm_lines = "\n".join(_fm_flat(fm))
    except Exception:  # noqa: BLE001 - never let scanning crash the scan
        fm_lines = ""
    if fm_lines:
        findings += _scan_text(fm_lines, "frontmatter", _PROMPT_INJECTION_PATTERNS)
        findings += _scan_text(fm_lines, "frontmatter", _PARAPHRASE_PATTERNS)
    # PT-T74: scan unicode-normalized variants too - fullwidth chars and
    # combining-mark stacks are pure obfuscation and fold losslessly to ASCII
    import unicodedata as _ud

    _CYR_TO_LATIN = str.maketrans({
        # only unambiguous visual look-alikes (NVIDIA-style homoglyph list)
        "\u0456": "i", "\u0455": "s", "\u0430": "a", "\u0435": "e",
        "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0443": "y",
        "\u0445": "x", "\u0458": "j", "\u04bb": "h", "\u04cf": "l",
        "\u0406": "I",
        "\u0412": "B", "\u0410": "A", "\u0415": "E", "\u041e": "O",
        "\u0420": "P", "\u0421": "C", "\u0425": "X", "\u041d": "H",
        "\u041a": "K", "\u041c": "M", "\u0422": "T",
        # greek look-alikes (PT-T107): omikron/alpha/epsilon/rho/tau/chi/iota/nu/omega/kappa/lambda/mu + caps
        "\u03bf": "o", "\u03b1": "a", "\u03b5": "e", "\u03c1": "p",
        "\u03c4": "t", "\u03c7": "x", "\u03b9": "i", "\u03bd": "v",
        "\u03ba": "k", "\u03bb": "l", "\u03bc": "u", "\u03c5": "u",
        "\u039f": "O", "\u0391": "A", "\u0395": "E", "\u03a1": "P",
        "\u03a4": "T", "\u03a7": "X", "\u0399": "I", "\u039d": "N",
        "\u039a": "K", "\u039c": "M", "\u0392": "B",
    })

    def _norm(t: str, zw_mode: str = "space") -> str:
        # PT-T98/105: fold zero-width chars, homoglyph look-alikes, fullwidth
        # and combining marks so obfuscated phrases match the patterns.
        # PT-T108: zw_mode controls zero-width handling ("space" treats them
        # as word separators; "delete" removes them for in-word hiding).
        sep = " " if zw_mode == "space" else ""
        # PT-T166/Fix #49: C0/C1 control chars (NUL/BEL/VT/ESC/DEL etc.) break
        # phrase detection just like zero-width chars -- strip them first.
        # PT-T167/Fix #50: same for ALL Unicode format characters (Cf category:
        # LRM/RLM U+200E/F, FUNCTION APPLICATION U+2061, INVISIBLE TIMES
        # U+2062, ARABIC LETTER MARK U+061C, ...) except the ones already
        # handled by zw_mode below.
        # PT-T168/Fix #51: space-like chars (Zs: NBSP variants, OGHAM SPACE)
        # become ASCII spaces (word separators); Private Use (Co), line/para
        # separators (Zl/Zp) are stripped like controls.
        # PT-T168/Fix #51: non-ASCII spaces (Zs) follow zw_mode: separator in
        # "space" mode, removed in "delete" mode. Plain ASCII space is kept.
        t = "".join(
            sep if _ud.category(ch) == "Zs" and ch != " " else ch for ch in t
        )
        t = "".join(
            ch for ch in t
            if (ord(ch) >= 0x20 and ord(ch) != 0x7F and not (0x80 <= ord(ch) <= 0x9F)
                and _ud.category(ch) not in ("Cf", "Co", "Zl", "Zp"))
            or ch in "\t\n\r"
            or ord(ch) in (0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060)
        )
        t = "".join(sep if ord(ch) in (0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060) else ch for ch in t)
        t = t.translate(_CYR_TO_LATIN)
        t = "".join(chr(ord(c) - 0xFEE0) if 0xFF01 <= ord(c) <= 0xFF5E else c for c in t)
        return "".join(c for c in _ud.normalize("NFKD", t) if not _ud.combining(c))

    # PT-T75: short base64 blobs are decoded and the decoded text is scanned -
    # "aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==" no longer slips under the
    # long-blob threshold.
    import base64 as _b64
    import re as _re

    def _decoded_variants(t: str, depth: int = 0) -> list[str]:
        out = []
        # PT-T143: Python-style \xNN escapes auto-decode at runtime; decode
        # runs of >=4 and scan the printable result too.
        for _hx in _re.finditer(r"(?:\\x[0-9a-fA-F]{2}[\s,]*){4,}", t):
            try:
                _hd = bytes.fromhex(_re.sub(r"[\s,]", "", _hx.group(0).replace("\\x", ""))).decode("latin-1")
            except Exception:  # noqa: BLE001
                continue
            if _hd and sum(32 <= ord(c) < 127 for c in _hd) / len(_hd) > 0.8:
                out.append(_hd)
        for run in _re.findall(r"[A-Za-z0-9+/=]{16,}", t):
            try:
                pad = "=" * (-len(run) % 4)
                raw = _b64.b64decode(run + pad, validate=True)
            except Exception:  # noqa: BLE001
                continue
            dec = raw.decode("utf-8", errors="ignore")
            if not (dec and sum(c.isprintable() for c in dec) / max(len(dec), 1) > 0.8):
                # PT-T101: UTF-16LE-encoded text decodes to NUL-padded bytes;
                # strip NULs and re-check so utf-16 payloads are still scanned.
                best = ""
                best_ratio = 0.0
                for enc_try in ("utf-16-le", "utf-16-be"):
                    cand = raw.decode(enc_try, errors="ignore")
                    ratio = sum(c.isprintable() and ord(c) < 0x2E80 for c in cand) / max(len(cand), 1)
                    if ratio > best_ratio:
                        best, best_ratio = cand, ratio
                if not best or best_ratio <= 0.8:
                    continue
                dec = best
            out.append(dec)
            # PT-T126: recursive layer - double-encoded payloads (b64 of b64)
            # are decoded up to 2 extra levels, each result scanned.
            if depth < 2 and _re.fullmatch(r"[A-Za-z0-9+/=]{16,}", dec or ""):
                out.extend(_decoded_variants(dec, depth + 1))
        return out

    _dec_texts = _decoded_variants(body) + _decoded_variants(fm_lines)
    for i130, dv in enumerate(_dec_texts):
        # PT-T110: decoded payloads can themselves carry homoglyph/unicode
        # obfuscation - scan their normalized variants too.
        dv_norms = {_norm(dv), _norm(dv, zw_mode="delete")}
        for dv_n in dv_norms:
            if dv_n.strip():
                findings += _scan_text(dv_n, f"base64-decoded[{i130}]", _PROMPT_INJECTION_PATTERNS)
                findings += _scan_text(dv_n, f"base64-decoded[{i130}]", _PARAPHRASE_PATTERNS)
    for label, variant in (("body(normalized)", body), ("frontmatter(normalized)", fm_lines)):
        # PT-T108: scan both zero-width interpretations (separator vs hidden-in-word)
        for nv in {_norm(variant), _norm(variant, zw_mode="delete")}:
            if nv != variant and nv.strip():
                findings += _scan_text(nv, label, _PROMPT_INJECTION_PATTERNS)
                findings += _scan_text(nv, label, _PARAPHRASE_PATTERNS)
    findings += _scan_text(text, "raw text (incl. code blocks)", _CODE_PATTERNS)

    findings += _scan_text(text, "raw text (incl. code blocks)", _DROPPER_PATTERNS)
    findings += _scan_text(text, "raw text (incl. code blocks)", _PARAPHRASE_PATTERNS)
    # chunked-base64 check: join all base64-ish runs after removing line breaks,
    # so splitting a payload across lines no longer evades the length threshold
    squashed = re.sub(r"\s+", "", text)
    _b64_m = _CHUNKED_B64_RE.search(squashed)
    # PT-T93: plain prose without punctuation can squash into a 60+-char
    # near-all-lowercase run and false-positive this check. Real base64 mixes
    # case and digits heavily (~35-50%); prose is <10%. Require >=20%.
    if _b64_m:
        _run_txt = _b64_m.group(0)
        if sum(ch.isupper() or ch.isdigit() for ch in _run_txt) / len(_run_txt) >= 0.20:
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
    """Parse JSON body. Always returns a dict -- null/array/empty bodies
    become {} so the calling handler's .get() never crashes (PT-T208).
    Raises json.JSONDecodeError on truly invalid JSON so handlers can
    decide how to surface that."""
    length = int(environ.get("CONTENT_LENGTH") or 0)
    raw = environ["wsgi.input"].read(length) if length else b"{}"
    parsed = json.loads(raw or b"{}")
    if not isinstance(parsed, dict):
        return {}
    return parsed


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

        # PT-T228: only attempt URL fetch if url is a non-empty STRING
        # (otherwise 123 / True / [] are truthy and crash _fetch_skill_url
        # with an unhandled TypeError → 500 internal_error).
        if url and not text and isinstance(url, str):
            try:
                text = _fetch_skill_url(url)
            except (ValueError, urllib.error.URLError, TimeoutError) as e:
                # PT-T181: UnicodeEncodeError/DecodeError leak the offending
                # character + position + codec ("'ascii' codec can't encode
                # character 'ĺ' in position 5") which discloses server
                # internals (Python default encoding, url parsing depth).
                # Sanitize the message for those classes; pass the rest
                # through unchanged so legit errors stay actionable.
                if isinstance(e, UnicodeError):
                    msg = "url contains characters that cannot be encoded as ASCII; use a regular github.com or raw.githubusercontent.com link with ASCII characters only"
                else:
                    msg = "could not fetch url: %s" % e
                start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": msg}).encode()]

        if not isinstance(text, str):
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "text must be a string"}).encode()]
        if len(text) > 100_000:
            # PT-T183: was raising ValueError which the generic except turned
            # into 400 internal_error. Match the type-check pattern and
            # return a clear 400 so the client knows the size limit.
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": f"text too large ({len(text)} > 100000 chars); use the 'url' field for larger files"}).encode()]

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
                hist = cached.get("score_history")
                if isinstance(hist, list) and len(hist) >= 2:
                    result["trend"]["history"] = [int(h[1]) for h in hist if len(h) == 2][-10:]
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
    except Exception:  # noqa: BLE001  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": "internal_error"}).encode()]


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
            # PT-T23: validate BEFORE consuming quota -- a malformed request
            # must not burn one of the day's scans
            files = payload.get("files", [])
            if not isinstance(files, list) or not files:
                raise ValueError("files must be a non-empty list of {name, text}")
            if len(files) > MAX_FILES:
                raise ValueError(f"max {MAX_FILES} files per batch call")
            allowed, quota_info = check_and_consume_quota(api_key)
            results = []
            for f in files:
                if not isinstance(f, dict):
                    raise ValueError("files must be a list of {name, text} objects")
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
    except Exception:  # noqa: BLE001  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": "internal_error"}).encode()]


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
        # PT-T191: validate sha256 BEFORE soft_rate_limit (see handle_lookup
        # for the same fix).
        if not _valid_sha256(digest):
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "sha256 query param must be a 64-char hex digest"}).encode()]
        # PT-T30: soft per-key cap -- each call lists the dna prefix and fetches
        # neighbour blobs; make bulk graph-mapping expensive too.
        allowed_sim, sim_err = _soft_rate_limit(explicit_api_key[:24], 1000, "simrl_")
        if not allowed_sim:
            start_response("429 Too Many Requests", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": sim_err}).encode()]
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
    except Exception:  # noqa: BLE001  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": "internal_error"}).encode()]

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
        api_key = payload.get("api_key") if isinstance(payload.get("api_key"), str) else ""
        signature = payload.get("payment_signature") if isinstance(payload.get("payment_signature"), str) else ""
        kind = payload.get("kind", "scan")
        # PT-T19: strict whitelist -- unknown kinds silently fell through to the
        # scan branch (harmless: same price, same credit type) but made the API
        # lie in its response echo and polluted claim records.
        if kind not in ("scan", "lookup"):
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "kind must be 'scan' or 'lookup'"}).encode()]
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
    except Exception:  # noqa: BLE001  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": "internal_error"}).encode()]


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
    except Exception:  # noqa: BLE001  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": "internal_error"}).encode()]


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
        # PT-T191: validate sha256 BEFORE soft_rate_limit so malformed requests
        # get a clear 400 even when the blob store is down (which would
        # otherwise make _soft_rate_limit throw and fall through to the
        # generic "internal_error" handler).
        if not _valid_sha256(digest):
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "sha256 query param must be a 64-char hex digest"}).encode()]
        # PT-T30: soft per-key cap -- each call lists the dna prefix and fetches
        # neighbour blobs; make bulk graph-mapping expensive too.
        allowed_sim, sim_err = _soft_rate_limit(explicit_api_key[:24], 1000, "simrl_")
        if not allowed_sim:
            start_response("429 Too Many Requests", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": sim_err}).encode()]
        allowed, quota_info = check_and_consume_lookup_quota(explicit_api_key)
        if not allowed:
            status = "401 Unauthorized" if quota_info.get("error", "").startswith("unknown api_key") else "429 Too Many Requests"
            start_response(status, [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "quota_exceeded", "quota": quota_info}).encode()]
        record = get_scan_record(digest)
        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"disclaimer": DISCLAIMER, "quota": quota_info, "found": record is not None, "record": record,
            # PT-T234: include security_score as a derived field so clients
            # don't need to know the formula (matches /api/public_scan shape).
            "security_score": max(0, 100 - (record.get("risk_score") or 0) * 4) if record else None}).encode()]
    except Exception:  # noqa: BLE001  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": "internal_error"}).encode()]


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
    except Exception:  # noqa: BLE001  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": "internal_error"}).encode()]


_stats_cache = {"t": 0.0, "published": None}


def handle_stats(environ, start_response):
    """GET /api/stats -- aggregate global scan counters (no per-user data).
    
    PT-T236: expanded to include daily trend, verdict percentages, and
    published-to-scanned ratio for a richer /stats.html experience."""
    try:
        stats = get_stats()
        now_s = time.time()
        # published count needs a registry listing; cache it for 60s
        if _stats_cache["published"] is None or now_s - _stats_cache["t"] >= 60:
            try:
                _stats_cache["published"] = len(list_safe_registry(limit=200))
            except Exception:  # noqa: BLE001 - cosmetic counter, never fail
                _stats_cache["published"] = _stats_cache["published"] or 0
            _stats_cache["t"] = now_s

        total = int(stats.get("total_scans", 0))
        by_risk = stats.get("by_risk", {})
        
        # Derived percentages
        pct = {}
        if total > 0:
            for level, count in by_risk.items():
                pct[f"{level}_pct"] = round(count / total * 100, 1)
        
        # Daily trend (last 30 days, sorted ascending)
        daily = stats.get("daily", {})
        trend = sorted(daily.items())[-30:]
        trend_data = [{"date": k, "total": v.get("total", 0),
                       "clean": v.get("by_risk", {}).get("clean", 0),
                       "low": v.get("by_risk", {}).get("low", 0),
                       "medium": v.get("by_risk", {}).get("medium", 0),
                       "high": v.get("by_risk", {}).get("high", 0)}
                      for k, v in trend]

        start_response("200 OK", [("Content-Type", "application/json"),
                                  ("Cache-Control", "public, max-age=60")] + _CORS_HEADERS)
        return [json.dumps({
            "disclaimer": DISCLAIMER,
            "total_scans": total,
            "by_risk": by_risk,
            "percentages": pct,
            "published": _stats_cache["published"],
            "published_pct": round(_stats_cache["published"] / max(total, 1) * 100, 1),
            "daily_trend": trend_data,
            "updated_at": stats.get("updated_at"),
            "started_at": stats.get("started_at"),
        }, indent=2).encode()]
    except Exception:  # noqa: BLE001  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": "internal_error"}).encode()]


def similar_payload(digest: str) -> list | None:
    """Skill-DNA neighbours for one digest, with unpublished names masked
    (PT-T10). Returns None when no DNA is stored for the hash yet."""
    try:
        from .scans import _blob_headers, BLOB_API_BASE, find_similar_dna
    except ImportError:
        from scans import _blob_headers, BLOB_API_BASE, find_similar_dna
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
        return None
    similar = find_similar_dna(own_dna, exclude_digest=digest, max_results=5)
    for entry in similar:
        sha = entry.get("sha256", "")
        if not sha or get_published_content(sha) is None:
            entry["name"] = None
            entry["published"] = False
        else:
            entry["published"] = True
    return similar


def handle_similar(environ, start_response):
    """GET /api/similar?sha256=...&api_key=... -- Skill-DNA neighbours
    (near-duplicate detection, hamming distance <= 12 of the 64-bit simhash).
    Requires sign-in; does not consume DB-lookup quota."""
    try:
        explicit_api_key = _get_qs_api_key(environ)
        if not explicit_api_key or get_account(explicit_api_key) is None:
            start_response("401 Unauthorized", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "sign_in_required"}).encode()]
        # PT-T30: soft per-key cap -- each call lists the dna prefix and fetches
        # neighbour blobs; make bulk graph-mapping expensive too.
        allowed_sim, sim_err = _soft_rate_limit(explicit_api_key[:24], 1000, "simrl_")
        if not allowed_sim:
            start_response("429 Too Many Requests", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": sim_err}).encode()]
        qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
        digest = (qs.get("sha256") or [""])[0].lower()
        if not _valid_sha256(digest):
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "sha256 query param must be a 64-char hex digest"}).encode()]
        similar = similar_payload(digest)
        if similar is None:
            start_response("404 Not Found", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "dna_unknown",
                                "message": "No DNA stored for this hash yet. Scan it first."}).encode()]
        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"disclaimer": DISCLAIMER, "sha256": digest,
                            "similar": similar}).encode()]
    except Exception:  # noqa: BLE001  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": "internal_error"}).encode()]


def _valid_watch_webhook(url) -> bool:
    """PT-T38: outbound webhooks are restricted to Discord/Slack endpoints so
    a stored watch can never be turned into an arbitrary-URL SSRF probe."""
    if not isinstance(url, str) or "?" in url or "#" in url:
        # PT-T39: no query strings / fragments -- nothing extra should ride
        # along to the provider, and params make payload confusion possible.
        return False
    # PT-T187: use urlparse to extract the actual netloc (hostname), preventing
    # the https://discord.com@evil.com/... SSRF trick where the @ makes
    # urllib send the request to evil.com despite the startswith check.
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.lower()
    # Strip any userinfo (user:pass@) before checking
    if "@" in host:
        host = host.split("@", 1)[1]
    return (host == "discord.com" and url.startswith("https://discord.com/api/webhooks/")
            or host == "discordapp.com" and url.startswith("https://discordapp.com/api/webhooks/")
            or host == "hooks.slack.com" and url.startswith("https://hooks.slack.com/services/"))


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """PT-T172/H-01: refuse all redirects for outbound webhooks."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


_OPENER_NO_REDIRECT = urllib.request.build_opener(_NoRedirectHandler)


def _deliver_watch_webhook(rec: dict) -> str:
    """Best-effort POST on status change. Returns delivery note for the record."""
    hook = rec.get("webhook_url") or ""
    if not hook or not _valid_watch_webhook(hook):
        return "skipped_invalid_or_missing"
    try:
        payload = json.dumps({
            "text": f"[skillsmith] RUG-PULL ALERT: watched skill content CHANGED ({rec.get('url','')})",
            "content": f"🚨 [skillsmith] Rug-pull alert: watched SKILL.md changed: {rec.get('url','')} (watch_id {rec['watch_id']})",
            "watch_id": rec["watch_id"], "status": "changed",
            "baseline_sha256": rec.get("baseline_sha256"), "current_sha256": rec.get("last_sha256"),
        }).encode()
        req_u = urllib.request.Request(hook, data=payload, headers={"Content-Type": "application/json"})
        # PT-T172/H-01: never follow redirects -- the allowlist pins the
        # host, so a 3xx to anywhere else must not turn the stored webhook
        # into an open relay. A refused redirect surfaces as HTTPError and
        # is swallowed by the best-effort handler below.
        _OPENER_NO_REDIRECT.open(req_u, timeout=5)
        return "delivered"
    except Exception as e113:  # noqa: BLE001 - delivery is best-effort
        return f"failed:{str(e113)[:80]}"


def _soft_rate_limit(identity: str, daily_cap: int, bucket: str) -> tuple[bool, str]:
    """Shared wrapper for the per-identity soft caps (PT-T30/T26/T40 family):
    one import site instead of five copies of the try/except boilerplate."""
    try:
        from .account import check_public_scan_rate
    except ImportError:
        from account import check_public_scan_rate
    return check_public_scan_rate(identity, daily_cap=daily_cap, bucket=bucket)


def watch_create(api_key: str, url: str, webhook_url: str = "") -> dict:
    """Create a rug-pull watch for one GitHub-hosted SKILL.md.
    Raises ValueError with a client-safe message on any rejection."""
    try:
        from .scans import create_watch, update_watch, sha256_of
        from .account import _blob_path as _bp, _blob_get as _bg, _blob_put as _bput
    except ImportError:
        from scans import create_watch, update_watch, sha256_of
        from account import _blob_path as _bp, _blob_get as _bg, _blob_put as _bput
    if get_account(api_key) is None:
        raise PermissionError("unknown api_key")
    if not isinstance(url, str) or not url.strip():
        raise ValueError("url required (github.com blob or raw URL)")
    day = time.strftime("%Y-%m-%d", time.gmtime())
    rl_path = _bp(f"watch_rl/{api_key[:24]}-{day}.json")
    rl = _bg(rl_path) or {"count": 0}
    if rl.get("count", 0) >= 10:
        raise ValueError("too many watches today (10/day/key)")
    try:
        text = _fetch_skill_url(url.strip())
    except Exception as e:  # noqa: BLE001 - includes non-github URLs
        raise ValueError(f"cannot fetch url: {e}; only github.com blob URLs and raw.githubusercontent.com URLs are allowed")
    if webhook_url and not _valid_watch_webhook(webhook_url):
        raise ValueError("webhook_url must be a Discord or Slack webhook (https://discord.com/api/webhooks/... or https://hooks.slack.com/services/...)")
    digest = sha256_of(text)
    rec = create_watch(url.strip(), digest, webhook_url=webhook_url.strip()[:300])
    rec["owner"] = api_key[:24]  # PT-T11: ownership binding
    update_watch(rec)
    _bput(rl_path, {"count": rl.get("count", 0) + 1})
    return {"watch_id": rec["watch_id"], "baseline_sha256": digest}


def watch_check(api_key: str, watch_id: str) -> dict | None:
    """On-demand rug-pull check for one owned watch. Returns None when the
    watch does not exist or belongs to another account (no oracle)."""
    try:
        from .scans import get_watch, update_watch, sha256_of
    except ImportError:
        from scans import get_watch, update_watch, sha256_of
    rec = get_watch(watch_id)
    if rec is None or (rec.get("owner") and rec.get("owner") != api_key[:24]):
        return None
    current_sha, fetch_error = None, None
    try:
        text = _fetch_skill_url(rec["url"])
        current_sha = sha256_of(text)
    except Exception as e:  # noqa: BLE001 - unreachable is a valid state
        fetch_error = str(e)[:200]
    changed = bool(current_sha and current_sha != rec.get("baseline_sha256"))
    rec["checks"] = int(rec.get("checks", 0)) + 1
    rec["last_checked_at"] = time.time()
    rec["last_sha256"] = current_sha
    rec["last_status"] = "changed" if changed else ("unchanged" if current_sha else "unreachable")
    if changed and not rec.get("changed_at"):
        rec["changed_at"] = time.time()
    if rec["last_status"] == "changed" and rec.get("webhook_url") and not rec.get("webhook_delivered"):
        # PT-T38: push notification on rug-pull (Discord/Slack only, best-effort).
        # PT-T44: fire ONCE per watch -- repeated checks on an already-changed
        # skill must not spam the user's channel (or our egress) every time.
        rec["webhook_delivery"] = _deliver_watch_webhook(rec)
        rec["webhook_delivered"] = True
    update_watch(rec)
    return {"watch_id": watch_id, "status": rec["last_status"],
            "baseline_sha256": rec.get("baseline_sha256"), "current_sha256": current_sha,
            "fetch_error": fetch_error, "checks": rec["checks"],
            "last_checked_at": rec["last_checked_at"]}


def handle_watch(environ, start_response):
    """POST /api/watch {api_key, url} -> watch a published GitHub SKILL.md for
    rug-pulls: we store the content hash as baseline. GET
    /api/watch?watch_id=...&api_key=... -> on-demand check: re-fetch the url,
    compare the hash, report changed/unchanged. URLs are restricted to
    github.com / raw.githubusercontent.com (same allow-list as /api/scan's
    url mode) so this can never be used as an SSRF proxy."""
    try:
        # watch helpers (scans.create_watch/get_watch/update_watch) are imported
        # lazily by watch_create/watch_check - no module-level import needed.
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
            try:
                out = watch_create(api_key, url, webhook_url=payload.get("webhook_url", ""))
            except PermissionError:
                start_response("401 Unauthorized", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": "unknown api_key"}).encode()]
            except ValueError as e:
                status = "429 Too Many Requests" if "too many watches" in str(e) else "400 Bad Request"
                start_response(status, [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": str(e)}).encode()]
            start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"disclaimer": DISCLAIMER, **out,
                                "note": "check anytime via GET /api/watch?watch_id=...&api_key=..."}).encode()]

        if environ.get("REQUEST_METHOD") == "DELETE":
            # PT-T54: owner-verified watch removal
            qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
            wid_d = (qs.get("watch_id") or [""])[0]
            api_key_d = _get_qs_api_key(environ) or ""
            if not re.fullmatch(r"[A-Za-z0-9_-]{10,40}", wid_d):
                start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": "watch_id required"}).encode()]
            if not api_key_d or get_account(api_key_d) is None:
                start_response("401 Unauthorized", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": "sign_in_required"}).encode()]
            ok_d, err_d = _soft_rate_limit(api_key_d[:24], 200, "wchk_")
            if not ok_d:
                start_response("429 Too Many Requests", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": err_d}).encode()]
            try:
                from .scans import delete_watch as _del_watch
            except ImportError:
                from scans import delete_watch as _del_watch
            removed = _del_watch(wid_d, api_key_d[:24])
            status_d = "200 OK" if removed else "404 Not Found"
            start_response(status_d, [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"disclaimer": DISCLAIMER, "deleted": removed}).encode()]

        # GET: on-demand check -- or ?list=1 for all watches owned by this key
        qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
        api_key = _get_qs_api_key(environ) or ""
        if (qs.get("list") or [""])[0] in ("1", "true"):
            if not api_key or get_account(api_key) is None:
                start_response("401 Unauthorized", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": "sign_in_required"}).encode()]
            try:
                from .scans import list_watches
            except ImportError:
                from scans import list_watches
            ok_l, err_l = _soft_rate_limit(api_key[:24], 20, "wchk_")
            if not ok_l:
                start_response("429 Too Many Requests", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": err_l}).encode()]
            items = list_watches(api_key[:24])
            start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"disclaimer": DISCLAIMER, "count": len(items),
                                "watches": items}).encode()]
        wid = (qs.get("watch_id") or [""])[0]
        if not re.fullmatch(r"[A-Za-z0-9_-]{10,40}", wid):
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "watch_id required"}).encode()]
        if not api_key or get_account(api_key) is None:
            start_response("401 Unauthorized", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "sign_in_required"}).encode()]
        # PT-T40: each check re-fetches the watched URL and can fire a webhook
        # delivery -- cap checks per key so one account cannot drive unlimited
        # upstream fetches (200/day/key, shared with nothing else).
        ok_chk, err_chk = _soft_rate_limit(api_key[:24], 200, "wchk_")
        if not ok_chk:
            start_response("429 Too Many Requests", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": err_chk}).encode()]
        out = watch_check(api_key, wid)
        if out is None:
            start_response("404 Not Found", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "unknown watch_id"}).encode()]
        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"disclaimer": DISCLAIMER, **out}).encode()]

    except Exception:  # noqa: BLE001  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": "internal_error"}).encode()]


_feed_cache = {"t": 0.0, "body": b""}


def handle_feed(environ, start_response):
    """GET /feed.xml -- Atom feed of recently registry-clean agent skills
    (automated heuristic verdicts only, see DISCLAIMER). Cached 5 min."""
    from xml.sax.saxutils import escape as xesc
    try:
        # PT-T12: query-string cache-busting skips the CDN cache, and each cold
        # render costs ~1 listing + up to 20 registry fetches. A tiny process-level
        # TTL cache caps the upstream amplification per warm lambda instance.
        now_t = time.time()
        if _feed_cache["body"] and now_t - _feed_cache["t"] < 60:
            start_response("200 OK", [("Content-Type", "application/atom+xml; charset=utf-8"),
                                      ("Cache-Control", "public, max-age=300"),
                                      ("X-Feed-Cache", "hit")] + _CORS_HEADERS)
            return [_feed_cache["body"]]
        try:
            from .scans import list_safe_registry
        except ImportError:
            from scans import list_safe_registry
        entries = list_safe_registry(limit=20)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        parts = ['<?xml version="1.0" encoding="utf-8"?>',
                 '<feed xmlns="http://www.w3.org/2005/Atom">',
                 "  <title>skillsmith — recently verified-clean agent skills</title>",
                 "  <id>https://skillsmith.ch/feed.xml</id>",
                 f"  <updated>{now}</updated>",
                 '  <link href="https://skillsmith.ch/" rel="alternate"/>',
                 "  <subtitle>Automated static-heuristic CLEAN verdicts only. "
                 "Not a manual audit. " + DISCLAIMER + "</subtitle>"]
        for e in entries:
            sha = e.get("sha256", "")
            if not _valid_sha256(sha):
                continue
            name = e.get("name") or sha[:12]
            seen = e.get("last_seen_at") or e.get("first_seen_at") or 0
            iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(seen))) if seen else now
            url = f"https://skillsmith.ch/skill.html?sha256={sha}"
            parts += [  # noqa: PERF - readability over micro-perf here
                "  <entry>",
                f"    <title>{xesc(name)}</title>",
                f"    <id>{url}</id>",
                f'    <link rel="alternate" type="text/html" href="{url}"/>',
                f"    <updated>{iso}</updated>",
                "    <summary>Static-heuristic verdict: clean (no sandbox, no manual audit). "
                f"sha256: {sha[:16]}...</summary>",
                "  </entry>"]
        parts.append("</feed>")
        body = ("\n".join(parts)).encode("utf-8")
        _feed_cache["body"] = body
        _feed_cache["t"] = now_t
        start_response("200 OK", [("Content-Type", "application/atom+xml; charset=utf-8"),
                                  ("Cache-Control", "public, max-age=300")] + _CORS_HEADERS)
        return [body]
    except Exception:  # noqa: BLE001  # noqa: BLE001
        start_response("500 Internal Server Error", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": "internal_error"}).encode()]


def handle_hook_scan(environ, start_response):
    """POST /api/hook-scan {api_key, url|text, format} -- run the normal scan
    pipeline and return a ready-to-post Discord or Slack webhook payload.
    Consumes one scan from the account quota. format: "discord" (default) | "slack"."""
    try:
        fmt = ""
        payload = _read_json(environ)
        text = payload.get("text", "")
        url = payload.get("url", "")
        fmt = payload.get("format", "discord") if isinstance(payload.get("format"), str) else "discord"
        if fmt not in ("discord", "slack"):
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "format must be 'discord' or 'slack'"}).encode()]
        # PT-T228: only attempt URL fetch if url is a non-empty STRING
        # (otherwise 123 / True / [] are truthy and crash _fetch_skill_url
        # with an unhandled TypeError → 500 internal_error).
        if url and not text and isinstance(url, str):
            try:
                text = _fetch_skill_url(url)
            except (ValueError, urllib.error.URLError, TimeoutError) as e:
                # PT-T181: same UnicodeError sanitization as handle_scan --
                # the hook endpoint also discloses Python internals on
                # non-ASCII URLs.
                if isinstance(e, UnicodeError):
                    msg = "url contains characters that cannot be encoded as ASCII; use a regular github.com or raw.githubusercontent.com link with ASCII characters only"
                else:
                    msg = "could not fetch url: %s" % e
                start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": msg}).encode()]
        if not isinstance(text, str):
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "text must be a string"}).encode()]
        if len(text) > 100_000:
            # PT-T183: same size-check fix as handle_scan -- clear 400
            # instead of internal_error.
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": f"text too large ({len(text)} > 100000 chars); use the 'url' field for larger files"}).encode()]
        explicit_api_key = payload.get("api_key") if isinstance(payload.get("api_key"), str) else ""
        explicit_api_key = explicit_api_key[:200]
        auth_header = environ.get("HTTP_AUTHORIZATION", "")
        if isinstance(auth_header, str) and not explicit_api_key and auth_header.startswith("Bearer "):
            explicit_api_key = auth_header[len("Bearer "):].strip()[:200]
        if not explicit_api_key:
            start_response("401 Unauthorized", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "sign_in_required"}).encode()]
        api_key = _client_api_key(environ, payload)
        allowed, q = check_and_consume_quota(api_key)
        if not allowed:
            status = "401 Unauthorized" if q.get("error", "").startswith("unknown api_key") else "429 Too Many Requests"
            start_response(status, [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "quota_exceeded" if allowed is False else "auth",
                                "quota": q}).encode()]

        digest = sha256_of(text)
        result = analyze(text)
        enrich_with_osv(result, text)
        try:
            record_scan(digest, result, name=result.get("name") or "", publish=False, text=text)
        except Exception:  # noqa: BLE001
            pass

        from xml.sax.saxutils import escape as _xesc
        name = result.get("name") or digest[:12]
        level = result.get("risk_level", "unknown")
        color = {"clean": 0x2EA043, "low": 0x9E6A03, "medium": 0xDB6D28, "high": 0xCF222E}.get(level, 0x6E7681)
        findings = result.get("findings") or []
        fdesc = "\n".join("- " + str(f.get("message", f.get("rule", "?")))[:120] for f in findings[:5]) or "none"
        link = f"https://skillsmith.ch/skill.html?sha256={digest}"
        if fmt == "discord":
            body = {
                "username": "skillsmith",
                "embeds": [{
                    "title": name,
                    "url": link,
                    "color": color,
                    "fields": [
                        {"name": "verdict", "value": str(level), "inline": True},
                        {"name": "risk score", "value": str(result.get("risk_score", "?")), "inline": True},
                        {"name": "security score", "value": str(result.get("security_score", "?")), "inline": True},
                        {"name": "top findings", "value": _xesc(fdesc)[:1024], "inline": False},
                        {"name": "sha256", "value": "```" + digest + "```", "inline": False},
                    ],
                    "footer": {"text": "automated static heuristic - not a manual audit"},
                }],
            }
        else:  # slack
            body = {
                "text": f"skillsmith scan: {name} -> {level}",
                "attachments": [{
                    "color": "#%06X" % color,
                    "title": name,
                    "title_link": link,
                    "fields": [
                        {"title": "verdict", "value": str(level), "short": True},
                        {"title": "risk/security", "short": True,
                         "value": f"{result.get('risk_score', '?')} / {result.get('security_score', '?')}"},
                        {"title": "top findings", "value": _xesc(fdesc)[:1000] if findings else "none",
                         "short": False},
                    ],
                    "footer": "automated static heuristic - not a manual audit",
                }],
            }
        body["disclaimer"] = DISCLAIMER
        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps(body).encode()]
    except Exception:  # noqa: BLE001  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": "internal_error"}).encode()]


def handle_certificate(environ, start_response):
    """GET /api/certificate?sha256=...&api_key=... -- issue an HMAC-signed
    verdict certificate for a scanned hash (90-day validity, built-in).
    POST /api/certificate {"certificate": {...}} -- verify a certificate."""
    try:
        try:
            from .features import make_certificate, verify_certificate
        except ImportError:
            from features import make_certificate, verify_certificate
        if environ.get("REQUEST_METHOD") == "POST":
            payload = _read_json(environ)
            cert = payload.get("certificate")
            if not isinstance(cert, dict):
                start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
                return [json.dumps({"error": "certificate object required"}).encode()]
            valid = verify_certificate(cert)
            current = get_scan_record(str(cert.get("sha256", ""))) if _valid_sha256(str(cert.get("sha256", ""))) else None
            matches_current = bool(current and cert.get("risk_level") == current.get("risk_level"))
            start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"disclaimer": DISCLAIMER,
                                "valid": bool(valid),
                                # PT-T173/Fix #55: verdict details only for VALID
                                # certs -- an invalid cert must not become an
                                # unauthenticated lookup oracle.
                                "matches_current_verdict": matches_current if valid else None,
                                "current_risk_level": (current.get("risk_level") if current else None) if valid else None,
                                "note": "valid means signed by skillsmith and within 90 days; "
                                        "matches_current_verdict means the hash still carries that verdict today."}).encode()]

        qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
        digest = (qs.get("sha256", [""])[0] or "").lower().strip()
        api_key = _get_qs_api_key(environ) or ""
        if not _valid_sha256(digest):
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "sha256 query param must be a 64-char hex digest"}).encode()]
        if not api_key or get_account(api_key) is None:
            start_response("401 Unauthorized", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "sign_in_required"}).encode()]
        rec = get_scan_record(digest)
        if rec is None:
            start_response("404 Not Found", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "not_scanned"}).encode()]
        cert = make_certificate(digest, rec.get("risk_level") or "unknown",
                                rec.get("security_score"))
        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"disclaimer": DISCLAIMER, "certificate": cert}).encode()]
    except Exception:  # noqa: BLE001  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": "internal_error"}).encode()]


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
        raw = environ["wsgi.input"].read(length) if length else b""
        # PT-T200: truly empty body (no bytes) is not a valid notification
        # -- return 400 Parse Error instead of treating it as an empty {}.
        if not raw.strip():
            start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}).encode()]
        req = json.loads(raw)
    except Exception:  # noqa: BLE001
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}).encode()]
    if not isinstance(req, dict):
        # JSON-RPC 2.0 spec section 4.1: only a single JSON object is a valid
        # request. Batches (lists) and other non-object types (strings,
        # numbers, null) all need -32600 Invalid Request. PT-T180 gives a
        # specific message per case so the client knows whether to send a
        # different shape or just give up.
        if isinstance(req, list):
            msg = "Invalid Request: batch requests are not supported, send a single JSON object"
        else:
            msg = f"Invalid Request: request body must be a JSON object, got {type(req).__name__}"
        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": msg}}).encode()]
    status, body = _mcp.handle_jsonrpc(req, client_ip=_client_ip(environ))
    if body is None:  # PT-T33: JSON-RPC notification -> no response body
        start_response("204 No Content", _CORS_HEADERS)
        return []
    start_response(f"{status} OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
    return [json.dumps(body).encode()]


def _badge_svg(left: str, right: str, color: str, style: str = "flat") -> str:
    """Minimal shields.io-style SVG badge, no external deps.
    Styles: flat (default), flat-square, round."""
    left_w = 11 * len(left) + 20
    right_w = 11 * len(right) + 20
    total = left_w + right_w
    if style == "flat-square":
        radius, gradient = "0", ""
    elif style == "round":
        radius, gradient = "10", ""
    else:  # flat
        radius, gradient = "3", """
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>"""
    overlay = '<rect width="%d" height="20" fill="url(#s)"/>' % total if gradient else ""
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img" aria-label="{left}: {right}">
  <title>{left}: {right}</title>{gradient}
  <clipPath id="r"><rect width="{total}" height="20" rx="{radius}" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{left_w}" height="20" fill="#1f2430"/>
    <rect x="{left_w}" width="{right_w}" height="20" fill="{color}"/>{overlay}
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
    style = qs.get("style", ["flat"])[0]
    if style not in ("flat", "flat-square", "round"):
        style = "flat"
    headers = [("Content-Type", "image/svg+xml; charset=utf-8"),
               ("X-Content-Type-Options", "nosniff"),
               ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'"),
               ("Cache-Control", "public, max-age=60")] + _CORS_HEADERS

    if not _valid_sha256(digest):  # logic audit L11

        svg = _badge_svg("skillsmith", "invalid hash", "#6e7681", style)
        start_response("400 Bad Request", headers)
        return [svg.encode()]

    rec = get_scan_record(digest)
    if rec is None:
        svg = _badge_svg("skillsmith", "not scanned", "#6e7681", style)
        start_response("200 OK", headers)
        return [svg.encode()]

    risk = rec.get("risk_level") or "unknown"
    color = _BADGE_COLORS.get(risk, "#6e7681")
    trend_arrow = ""
    if qs.get("trend", ["0"])[0] in ("1", "true"):
        # PT-T35: optional score-trend arrow from the last two history points
        hist = (rec.get("score_history") or [])
        pts = [h for h in hist[-2:] if isinstance(h, list) and len(h) == 2]
        if len(pts) == 2 and isinstance(pts[0][1], int) and isinstance(pts[1][1], int):
            d_pts = pts[1][1] - pts[0][1]
            trend_arrow = {"up": " ↑", "down": " ↓", "flat": ""}[
                "up" if d_pts > 0 else ("down" if d_pts < 0 else "flat")]
    if risk == "clean":
        right = f"clean{trend_arrow} | skillsmith.ch"
    else:
        score = rec.get("risk_score")
        base = f"{risk} ({score})" if score is not None else risk
        right = f"{base}{trend_arrow} | skillsmith.ch"
    svg = _badge_svg("skill check", _escape_svg(right), color, style)
    start_response("200 OK", headers)
    return [svg.encode()]


def _compute_score_trend(history: list, current_score: int | None) -> dict:
    """Derive trend direction/delta from score_history list of [ts, score].
    Returns {} when no meaningful history (single data point)."""
    if not history or len(history) < 2 or current_score is None:
        return {}
    prev_ts, prev_score = history[-2]
    delta = current_score - int(prev_score)
    if delta > 0:
        direction = "improved"
    elif delta < 0:
        direction = "declined"
    else:
        direction = "unchanged"
    return {
        "direction": direction,
        "delta": delta,
        "previous_security_score": int(prev_score),
        "previous_at": int(prev_ts),
    }


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
        "security_score": rec.get("security_score"),
        "score_history": rec.get("score_history") or [],
        "trend": _compute_score_trend(rec.get("score_history") or [], rec.get("security_score")),
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
    # PT-T26: soft per-IP cap -- unknown ids are not CDN-cached, so hammering
    # random ids costs one blob fetch each; make bulk probing expensive too.
    allowed, rl_error = _soft_rate_limit(_client_ip(environ), 500, "anarlr_")
    if not allowed:
        start_response("429 Too Many Requests", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": rl_error}).encode()]
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
    # (PT-T17: reports are immutable -> let the CDN/browser cache them; without
    # this every permalink view costs a blob fetch, unauthenticated)
    start_response("200 OK", [("Content-Type", "application/json"),
                              ("Cache-Control", "public, max-age=300")] + _CORS_HEADERS)
    return [json.dumps(rec).encode()]


def app(environ, start_response):
    """Top-level guard: never leak internal error details to clients.

    Any unhandled exception becomes an opaque 500 JSON body (pentest LOW-01);
    the actual traceback goes to the platform logs via the raise/re-raise in
    the except branch."""
    def _sr_with_security_headers(status, headers, *args):
        have = {k.lower() for k, _ in headers}
        for name, value in (("X-Content-Type-Options", "nosniff"),
                            ("X-Frame-Options", "DENY"),
                            ("Referrer-Policy", "strict-origin-when-cross-origin")):
            if name.lower() not in have:
                headers.append((name, value))
        return start_response(status, headers, *args)

    try:
        return _app_inner(environ, _sr_with_security_headers)
    except urllib.error.HTTPError as _he:
        # Graceful degradation: storage-layer outages (e.g. suspended Blob
        # store) surface as HTTPError from the blob REST calls. Map them to
        # an honest 503 instead of an opaque 500 so clients and status
        # monitors can distinguish "bug" from "temporarily unavailable".
        import traceback
        traceback.print_exc()
        try:
            _he.read()
        except Exception:  # noqa: BLE001
            pass
        try:
            start_response("503 Service Unavailable",
                           [("Content-Type", "application/json"), ("Retry-After", "300")] + _CORS_HEADERS)
        except Exception:  # noqa: BLE001
            pass
        return [json.dumps({"error": "storage temporarily unavailable, please retry later"}).encode()]
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

    
        if path.rstrip("/").endswith("/stats.html"):
            try:
                with open(str(Path(__file__).parent.parent / "public" / "stats.html"), encoding="utf-8") as f:
                    body = f.read().encode()
            except Exception:
                start_response("404 Not Found", [("Content-Type", "text/plain")] + _CORS_HEADERS)
                return [b"Not Found"]
            start_response("200 OK", [("Content-Type", "text/html; charset=utf-8"),
                                      ("Cache-Control", "public, max-age=300")] + _CORS_HEADERS)
            return [body]

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

    if path.rstrip("/").endswith("/api/certificate"):
        return handle_certificate(environ, start_response)

    if path.rstrip("/").endswith("/api/hook-scan"):
        if method != "POST":
            start_response("405 Method Not Allowed", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "POST only"}).encode()]
        return handle_hook_scan(environ, start_response)

    if path.rstrip("/") == "/feed.xml":
        if method != "GET":
            start_response("405 Method Not Allowed", [("Content-Type", "application/json")] + _CORS_HEADERS)
            return [json.dumps({"error": "GET only"}).encode()]
        return handle_feed(environ, start_response)

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
