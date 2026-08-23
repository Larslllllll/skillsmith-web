"""
skillsmith MCP server -- lets AI agents scan/lookup/publish/use Claude Agent
Skills directly from their own MCP client (Claude Code, Codex, Cursor,
etc.), the same way https://skillsmith.ch works for humans in a browser.

Endpoint: POST https://skillsmith.ch/mcp
Protocol: JSON-RPC 2.0 over HTTP (MCP "Streamable HTTP" transport, no SSE
needed for our synchronous tool calls).
Auth: an api_key from POST /api/signup (or GitHub sign-in), passed as a
tool argument on every call -- MCP doesn't mandate OAuth, and requiring one
here would be needless friction for agents that already have a key.

Tools exposed: scan_skill, lookup_hash, get_skill_content, list_safe_skills,
whoami. All of them just call straight into the same analyze()/account
functions the REST API and the web UI use -- one detection engine, one
quota system, three front doors (web, REST, MCP).
"""
import json

try:
    from .account import get_account, check_and_consume_quota, check_and_consume_lookup_quota
    from .scans import sha256_of, get_scan_record, record_scan, list_safe_registry, get_published_content
except ImportError:  # local/script execution without package context
    from account import get_account, check_and_consume_quota, check_and_consume_lookup_quota
    from scans import sha256_of, get_scan_record, record_scan, list_safe_registry, get_published_content


def _index_module():
    """Lazy import of api/index.py (analyze(), _fetch_skill_url(), DISCLAIMER).

    Deliberately deferred, not a module-level import: index.py imports this
    module (mcp.py) to serve /mcp through its single WSGI entrypoint, so a
    top-level 'from .index import ...' here would be a circular import. By
    the time any MCP tool actually runs, index.py has already finished
    loading, so a lazy import inside the function body is safe.
    """
    try:
        from . import index as _idx
    except ImportError:
        import index as _idx
    return _idx

TOOLS = [
    {
        "name": "scan_skill",
        "description": "Lint + static security-scan a Claude Agent Skill (SKILL.md). Pass either 'text' (the raw SKILL.md content) or 'url' (a github.com blob link). Requires an api_key from skillsmith_signup. Returns lint issues, security findings, a 0-100 security_score, and a disclaimer that this is a heuristic scanner, not a guarantee.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string", "description": "Account key from skillsmith_signup"},
                "text": {"type": "string", "description": "Raw SKILL.md content to scan"},
                "url": {"type": "string", "description": "github.com blob URL or raw.githubusercontent.com URL to scan instead of text"},
                "publish": {"type": "boolean", "description": "If true and the scan comes back clean, publish the content to the public Safe Skills Database so other agents can fetch and use it"},
            },
        },
    },
    {
        "name": "lookup_hash",
        "description": "VirusTotal-style lookup: has this exact SKILL.md (by SHA-256) been scanned before, and what was the verdict? Requires api_key, consumes 1 unit of your daily DB-lookup quota.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string"},
                "sha256": {"type": "string", "description": "64-character hex SHA-256 digest"},
            },
            "required": ["api_key", "sha256"],
        },
    },
    {
        "name": "get_skill_content",
        "description": "Fetch the actual, usable SKILL.md text for a published skill by its SHA-256 hash -- use this to actually reuse a vetted skill, not just check its safety verdict. 404s if that hash was never published.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string"},
                "sha256": {"type": "string"},
            },
            "required": ["api_key", "sha256"],
        },
    },
    {
        "name": "list_safe_skills",
        "description": "Browse the public Safe Skills Database: skills that scanned clean and lint-valid, newest first. Each entry has a has_content flag -- true means get_skill_content will return real, usable text for it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string"},
                "limit": {"type": "integer", "description": "Max entries to return, default 20"},
            },
            "required": ["api_key"],
        },
    },
    {
        "name": "skillsmith_signup",
        "description": "Create a new anonymous skillsmith account (no email/password) and get an api_key to use with the other tools. Free tier: 5 scans/day, 5 DB lookups/day.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "whoami",
        "description": "Check an api_key's current tier and quota usage (free/pro/premium, scans used today, lookups used today).",
        "inputSchema": {
            "type": "object",
            "properties": {"api_key": {"type": "string"}},
            "required": ["api_key"],
        },
    },
]


def _tool_result(payload):
    return {"content": [{"type": "text", "text": json.dumps(payload)}]}


def _call_tool(name, args, client_ip: str = ""):
    api_key = args.get("api_key", "")
    if not isinstance(api_key, str):
        api_key = ""
    api_key = api_key[:200]
    idx = _index_module()

    if name == "skillsmith_signup":
        # Same per-IP daily cap as POST /api/signup -- without this the MCP
        # route was an unlimited-signup bypass (pentest v2, F-01).
        try:
            from .account import check_and_consume_signup_quota
        except ImportError:
            from account import check_and_consume_signup_quota
        allowed, rl_error = check_and_consume_signup_quota(client_ip)
        if not allowed:
            return _tool_result({"error": rl_error,
                                 "tip": "sign in with GitHub at https://skillsmith.ch instead, it's not rate limited"})
        try:
            from .account import create_account
        except ImportError:
            from account import create_account
        key, _record = create_account()
        return _tool_result({"api_key": key, "free_daily_limit": 5, "note": "Save this key; it's the only way to recover this account."})

    if name == "scan_skill":
        text = args.get("text", "")
        url = args.get("url", "")
        if url and not text:
            try:
                text = idx._fetch_skill_url(url)
            except Exception as e:  # noqa: BLE001
                return _tool_result({"error": f"could not fetch url: {e}"})
        if not text:
            return _tool_result({"error": "provide either 'text' or 'url'"})
        allowed, quota_info = check_and_consume_quota(api_key or None)
        if not allowed:
            return _tool_result({"error": "quota_exceeded", "quota": quota_info})
        digest = sha256_of(text)
        result = idx.analyze(text)
        publish = bool(args.get("publish"))
        try:
            history = record_scan(digest, result, name=result.get("name") or "", publish=publish, text=text)
        except Exception:  # noqa: BLE001
            history = None
        result["quota"] = quota_info
        result["sha256"] = digest
        result["scan_history"] = {
            "seen_before": get_scan_record(digest) is not None,
            "seen_count": (history or {}).get("seen_count", 1),
            "published": bool((history or {}).get("has_content")),
        }
        return _tool_result(result)

    if name == "lookup_hash":
        digest = args.get("sha256", "").lower()
        if len(digest) != 64:
            return _tool_result({"error": "sha256 must be a 64-char hex digest"})
        allowed, quota_info = check_and_consume_lookup_quota(api_key or None)
        if not allowed:
            return _tool_result({"error": "quota_exceeded", "quota": quota_info})
        record = get_scan_record(digest)
        return _tool_result({"disclaimer": idx.DISCLAIMER, "found": record is not None, "record": record, "quota": quota_info})

    if name == "get_skill_content":
        digest = args.get("sha256", "").lower()
        if len(digest) != 64:
            return _tool_result({"error": "sha256 must be a 64-char hex digest"})
        allowed, quota_info = check_and_consume_lookup_quota(api_key or None)
        if not allowed:
            return _tool_result({"error": "quota_exceeded", "quota": quota_info})
        text = get_published_content(digest)
        if text is None:
            return _tool_result({"error": "not_published", "message": "This hash has no published content."})
        return _tool_result({"sha256": digest, "text": text, "quota": quota_info})

    if name == "list_safe_skills":
        allowed, quota_info = check_and_consume_lookup_quota(api_key or None)
        if not allowed:
            return _tool_result({"error": "quota_exceeded", "quota": quota_info})
        try:
            limit = max(1, min(int(args.get("limit", 20)), 200))
        except (ValueError, TypeError):
            limit = 20
        entries = list_safe_registry(limit=limit)
        return _tool_result({"disclaimer": idx.DISCLAIMER, "count": len(entries), "skills": entries, "quota": quota_info})

    if name == "whoami":
        record = get_account(api_key)
        if record is None:
            return _tool_result({"error": "unknown api_key"})
        return _tool_result({
            "tier": "unlimited" if record.get("unlimited") else "premium" if record.get("premium_expires_at", 0) else "pro" if record.get("pro_expires_at", 0) else "free",
            "free_used_today": record.get("free_used_count", 0),
            "pro_used_today": record.get("pro_used_count", 0),
            "bonus_credits": record.get("bonus_credits", 0),
            "bonus_lookup_credits": record.get("bonus_lookup_credits", 0),
        })

    return {"content": [{"type": "text", "text": json.dumps({"error": f"unknown tool: {name}"})}], "isError": True}


def handle_jsonrpc(req: dict, client_ip: str = "") -> tuple[int, dict]:
    """Pure JSON-RPC 2.0 dispatch, no WSGI/HTTP plumbing -- this file is
    imported as a library from api/index.py (the project's single WSGI
    entrypoint; Vercel's Python builder only supports one per project),
    not deployed as its own serverless function. Returns (http_status,
    response_body_dict)."""
    req_id = req.get("id")
    rpc_method = req.get("method", "")
    params = req.get("params") or {}

    if rpc_method == "initialize":
        result = {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "skillsmith-mcp", "version": "1.0.0"},
            "capabilities": {"tools": {}},
            "instructions": "Call skillsmith_signup first to get an api_key (free), then scan_skill / lookup_hash / get_skill_content / list_safe_skills / whoami. All tools use the same quota as https://skillsmith.ch.",
        }
    elif rpc_method == "tools/list":
        result = {"tools": TOOLS}
    elif rpc_method == "tools/call":
        result = _call_tool(params.get("name", ""), params.get("arguments") or {}, client_ip=client_ip)
    elif rpc_method == "ping":
        result = {}
    else:
        return 200, {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {rpc_method}"}}

    return 200, {"jsonrpc": "2.0", "id": req_id, "result": result}
