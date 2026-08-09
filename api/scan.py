"""
skillsmith-web /api/scan — Vercel Serverless (WSGI)
====================================================
POST { "text": "<raw SKILL.md content>" } -> lint + security scan results,
using the real skillsmith package (vendored below, same logic as the CLI).
No data is persisted; each request is stateless.
"""
import json
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

_CORS_HEADERS = [
    ("Access-Control-Allow-Origin", "*"),
    ("Access-Control-Allow-Methods", "POST, OPTIONS"),
    ("Access-Control-Allow-Headers", "Content-Type"),
    ("Access-Control-Max-Age", "86400"),
]

NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
REQUIRED_KEYS = ("name", "description")
RECOMMENDED_MAX_DESCRIPTION_CHARS = 500
FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?\n)---\s*\n?(.*)$", re.DOTALL)

_CODE_PATTERNS = [
    (re.compile(r"\bos\.system\s*\("), 8, "shells out via os.system"),
    (re.compile(r"\bsubprocess\.(Popen|call|run|check_output)\s*\("), 6, "spawns a subprocess"),
    (re.compile(r"\beval\s*\("), 9, "calls eval() on dynamic input"),
    (re.compile(r"\bexec\s*\("), 9, "calls exec() on dynamic input"),
    (re.compile(r"\bpickle\.(loads|load)\s*\("), 7, "deserializes with pickle (arbitrary code execution risk)"),
    (re.compile(r"\b__import__\s*\("), 5, "dynamically imports modules"),
    (re.compile(r"\brequests\.(post|put|get)\s*\("), 3, "makes outbound network requests"),
    (re.compile(r"\burllib\.request\.urlopen\s*\("), 3, "makes outbound network requests"),
    (re.compile(r"\bsocket\.socket\s*\("), 4, "opens raw sockets"),
    (re.compile(r"(?i)\brm\s+-rf\b"), 8, "contains a destructive shell command (rm -rf)"),
    (re.compile(r"os\.environ(\.get)?\s*\[?['\"](\w*(KEY|TOKEN|SECRET|PASSWORD)\w*)['\"]"), 6, "reads an environment variable that looks like a credential"),
    (re.compile(r"\bopen\s*\([^)]*['\"]\.ssh"), 8, "reads from ~/.ssh"),
    (re.compile(r"\bopen\s*\([^)]*['\"]\.aws"), 8, "reads from ~/.aws credentials"),
]

_PROMPT_INJECTION_PATTERNS = [
    (re.compile(r"(?i)ignore (all|any|the) (previous|prior|above) instructions"), 10, "'ignore previous instructions' phrasing"),
    (re.compile(r"(?i)you are now (in )?(developer|debug|jailbreak|dan) mode"), 10, "jailbreak/mode-override phrasing"),
    (re.compile(r"(?i)do not (tell|inform|mention (this )?to) the user"), 8, "instructs the agent to hide actions from the user"),
    (re.compile(r"(?i)send (the|this|your) (api[- ]?key|token|password|secret|private key) to"), 10, "instructs exfiltration of credentials"),
    (re.compile(r"(?i)disregard (your|any) (safety|previous) (guidelines|instructions)"), 10, "safety-override phrasing"),
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
    }


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
        text = payload.get("text", "")
        if not isinstance(text, str) or len(text) > 100_000:
            raise ValueError("text must be a string under 100,000 chars")
        result = analyze(text)
        start_response("200 OK", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps(result).encode()]
    except Exception as e:  # noqa: BLE001 - return a clean JSON error either way
        start_response("400 Bad Request", [("Content-Type", "application/json")] + _CORS_HEADERS)
        return [json.dumps({"error": str(e)}).encode()]


app = handle
