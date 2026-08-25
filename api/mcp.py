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
file_report, find_similar, whoami. All of them just call straight into the same analyze()/account
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
        "description": "Lint + static security-scan a Claude Agent Skill (SKILL.md). Pass either 'text' (the raw SKILL.md content) or 'url' (a github.com blob link). Requires an api_key from skillsmith_signup. Returns lint issues, security findings (with human-readable sources: body, frontmatter, base64-decoded, unicode-normalized), a 0-100 security_score, and a disclaimer that this is a heuristic scanner, not a guarantee. Detects injection phrasing and paraphrased overrides (disregard prior guidance, forward gathered data, defanged URLs) incl. frontmatter payloads, dangerous code patterns (eval/exec/pickle/shell) in fenced blocks, exfil URLs, unicode obfuscation (zero-width as separator or hidden-in-word/RTL/bidi/fullwidth/combining marks/cyrillic+greek homoglyph look-alikes), and decodes base64 payloads (incl. UTF-16) which are then normalized and re-scanned.",
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
        "name": "watch_skill",
        "description": "Rug-pull watch for a GitHub-hosted SKILL.md. Modes: create (pass url, optional webhook_url for auto-alerts), check (pass watch_id -> changed/unchanged/unreachable), list (pass list=true), delete (pass delete=<watch_id>). Only github.com/raw.githubusercontent.com URLs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string"},
                "url": {"type": "string", "description": "github.com blob or raw URL (required when creating)"},
                "watch_id": {"type": "string", "description": "existing watch to check"},
                "webhook_url": {"type": "string", "description": "optional Discord/Slack webhook; fires automatically when content changes"},
                "list": {"type": "boolean", "description": "set true to list all your watches"},
                "delete": {"type": "string", "description": "watch_id to remove"}
            },
            "required": ["api_key"],
        },
    },
    {
        "name": "find_similar",
        "description": "Skill-DNA near-duplicate search: given a scanned skill's sha256, return up to 5 stored skills whose simhash fingerprint is within Hamming distance 12 (renamed/cosmetically altered variants of known skills). Names of unpublished (private) skills are masked. Requires the hash to have been scanned before.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string"},
                "sha256": {"type": "string", "description": "64-char hex digest"}
            },
            "required": ["api_key", "sha256"],
        },
    },
    {
        "name": "file_report",
        "description": "File a community verdict report for a scanned skill hash: verdict is 'malicious', 'false_positive' or 'note'; optional comment (max 500 chars). Crowd reports are shown publicly on skillsmith.ch and in scan results. 20 reports/day/key.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string"},
                "sha256": {"type": "string", "description": "64-char hex digest of the skill"},
                "verdict": {"type": "string", "enum": ["malicious", "false_positive", "note"]},
                "comment": {"type": "string", "description": "optional, max 500 chars"}
            },
            "required": ["api_key", "sha256", "verdict"],
        },
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
    {
        "name": "analyze_behavior",
        "description": "Behavioral sandbox ('any.run for agent skills'): an AI analyst in an isolated container reads the skill and simulates what an agent following it WOULD do -- capabilities, step-by-step action trace, IOCs, deception techniques and a 0-10 severity verdict. Nothing is executed against real systems. Slow (30-120s). Requires api_key; limited to a few analyses per account per day.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string", "description": "Account key from skillsmith_signup"},
                "text": {"type": "string", "description": "Raw SKILL.md content to analyze (max 100000 chars)"},
            },
            "required": ["api_key", "text"],
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

    # logic audit L2: REST requires an explicit api_key; MCP must too, or
    # empty keys made every quota call "anonymous" = unmetered.
    if name in ("scan_skill", "lookup_hash", "get_skill_content", "list_safe_skills", "whoami", "analyze_behavior"):
        if not api_key:
            return _tool_result({"error": "api_key required",
                                 "tip": "call skillsmith_signup first (free), then pass the key as api_key"})

    if name == "scan_skill":
        # PT-T171/Fix #54: JSON-RPC args can be any JSON type; non-string
        # text/url crashed sha256_of/_fetch_skill_url with an AttributeError.
        text = args.get("text", "")
        if not isinstance(text, str):
            return _tool_result({"error": "text must be a string"})
        url = args.get("url", "")
        if not isinstance(url, str):
            return _tool_result({"error": "url must be a string"})
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
        # logic audit L6: MCP must run the same OSV enrichment as REST,
        # otherwise the two front doors can produce different verdicts for
        # the same hash (and MCP could publish what REST would gate).
        try:
            idx.enrich_with_osv(result, text)
        except Exception:  # noqa: BLE001
            pass
        publish = bool(args.get("publish"))
        seen_before = get_scan_record(digest) is not None  # read BEFORE upsert
        try:
            history = record_scan(digest, result, name=result.get("name") or "", publish=publish, text=text)
        except Exception:  # noqa: BLE001
            history = None
        result["quota"] = quota_info
        result["sha256"] = digest
        result["scan_history"] = {
            "seen_before": seen_before,
            "seen_count": (history or {}).get("seen_count", 1),
            "published": bool((history or {}).get("has_content")),
        }
        return _tool_result(result)

    if name == "lookup_hash":
        import re as _re_mod
        digest = str(args.get("sha256", "")).lower()
        if not _re_mod.fullmatch(r"[0-9a-f]{64}", digest):  # audit L11
            return _tool_result({"error": "sha256 must be a 64-char hex digest"})
        allowed, quota_info = check_and_consume_lookup_quota(api_key or None)
        if not allowed:
            return _tool_result({"error": "quota_exceeded", "quota": quota_info})
        record = get_scan_record(digest)
        return _tool_result({"disclaimer": idx.DISCLAIMER, "found": record is not None, "record": record, "quota": quota_info})

    if name == "get_skill_content":
        import re as _re_mod
        digest = str(args.get("sha256", "")).lower()
        if not _re_mod.fullmatch(r"[0-9a-f]{64}", digest):  # audit L11
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
        import time as _time
        now = _time.time()
        if record.get("unlimited"):
            tier = "unlimited"
        elif record.get("premium_expires_at", 0) > now:  # truthiness lied about expired tiers (audit L7)
            tier = "premium"
        elif record.get("pro_expires_at", 0) > now:
            tier = "pro"
        else:
            tier = "free"
        return _tool_result({
            "tier": tier,
            "free_used_today": record.get("free_used_count", 0),
            "pro_used_today": record.get("pro_used_count", 0),
            "bonus_credits": record.get("bonus_credits", 0),
            "bonus_lookup_credits": record.get("bonus_lookup_credits", 0),
        })

    if name == "watch_skill":
        watch_id = args.get("watch_id")
        record = get_account(api_key)
        if record is None:
            return _tool_result({"error": "unknown api_key"})
        # PT-T57: list & delete parity with the REST endpoint
        if args.get("list"):
            try:
                from .scans import list_watches
            except ImportError:
                from scans import list_watches
            ok_l2, err_l2 = idx._soft_rate_limit(api_key[:24], 20, "wchk_")
            if not ok_l2:
                return _tool_result({"error": err_l2})
            items = list_watches(api_key[:24])
            return _tool_result({"disclaimer": idx.DISCLAIMER, "count": len(items), "watches": items})
        if args.get("delete"):
            try:
                from .scans import delete_watch
            except ImportError:
                from scans import delete_watch
            ok_d2, err_d2 = idx._soft_rate_limit(api_key[:24], 200, "wchk_")
            if not ok_d2:
                return _tool_result({"error": err_d2})
            removed = delete_watch(str(args["delete"]), api_key[:24])
            return _tool_result({"disclaimer": idx.DISCLAIMER, "deleted": removed,
                                 **({} if removed else {"note": "unknown watch_id or not yours"})})
        if watch_id:
            out = idx.watch_check(api_key, str(watch_id))
            if out is None:
                return _tool_result({"error": "unknown watch_id"})
            return _tool_result({"disclaimer": idx.DISCLAIMER, **out})
        url = args.get("url", "")
        try:
            out = idx.watch_create(api_key, url, webhook_url=args.get("webhook_url", ""))
        except PermissionError:
            return _tool_result({"error": "unknown api_key"})
        except ValueError as e:
            return _tool_result({"error": str(e)})
        return _tool_result({"disclaimer": idx.DISCLAIMER, **out,
                             "note": "check anytime with watch_skill and this watch_id"})

    if name == "find_similar":
        digest = str(args.get("sha256", "")).lower().strip()
        if not idx._valid_sha256(digest):
            return _tool_result({"error": "sha256 must be a 64-char hex digest"})
        record = get_account(api_key)
        if record is None:
            return _tool_result({"error": "unknown api_key"})
        similar = idx.similar_payload(digest)
        if similar is None:
            return _tool_result({"error": "dna_unknown",
                                 "message": "No DNA stored for this hash yet. Scan it first."})
        return _tool_result({"disclaimer": idx.DISCLAIMER, "sha256": digest, "similar": similar})

    if name == "file_report":
        import time as _time
        digest = str(args.get("sha256", "")).lower().strip()
        if not idx._valid_sha256(digest):
            return _tool_result({"error": "sha256 must be a 64-char hex digest"})
        verdict = args.get("verdict", "")
        if verdict not in ("malicious", "false_positive", "note"):
            return _tool_result({"error": "verdict must be malicious | false_positive | note"})
        comment = args.get("comment", "") if isinstance(args.get("comment"), str) else ""
        record = get_account(api_key)
        if record is None:
            return _tool_result({"error": "unknown api_key"})
        # same flood guard as POST /api/report: 20/day/key
        try:
            from .account import _blob_path as _abp, _blob_get as _abg, _blob_put as _abput
        except ImportError:
            from account import _blob_path as _abp, _blob_get as _abg, _blob_put as _abput
        day = _time.strftime("%Y-%m-%d", _time.gmtime())
        rl_path = _abp(f"report_rl/{api_key[:24]}-{day}.json")
        rl = _abg(rl_path) or {"count": 0}
        if int(rl.get("count", 0)) >= 20:
            return _tool_result({"error": "too many reports today (20/day/key)"})
        try:
            from .scans import add_report as _add_report
        except ImportError:
            from scans import add_report as _add_report
        tally = _add_report(digest, {"verdict": verdict, "comment": comment[:500], "via": "mcp"})
        _abput(rl_path, {"count": int(rl.get("count", 0)) + 1})
        return _tool_result({"ok": True, **tally})

    if name == "analyze_behavior":
        text = args.get("text", "")
        if not isinstance(text, str) or not text.strip():
            return _tool_result({"error": "text required (raw SKILL.md content)"})
        if len(text) > 100_000:
            return _tool_result({"error": f"text too large ({len(text)} > 100000)"})
        # per-account daily cap (the REST route caps per-IP; MCP callers are
        # authenticated, so cap per account): 5/day, unlimited for owners.
        import time as _t2
        from .account import get_account as _ga, _blob_path as _bp, _blob_get as _bg, _blob_put as _bput
        rec = _ga(api_key)
        if rec is None:
            return _tool_result({"error": "unknown api_key"})
        day = _t2.strftime("%Y-%m-%d", _t2.gmtime())
        if not rec.get("unlimited"):
            rl_path = _bp(f"analyses_rl_acct/{api_key[:24]}-{day}.json")
            rl = _bg(rl_path) or {"count": 0}
            if rl.get("count", 0) >= 5:
                return _tool_result({"error": "daily behavioral-analysis limit reached (5/day/account)",
                                     "tip": "counter resets at 00:00 UTC"})
            _bput(rl_path, {"count": rl.get("count", 0) + 1})
        # synchronous call into the Node sandbox function (30-120s typical)
        import urllib.request as _ureq, os as _os
        base = _os.environ.get("SITE_URL", "https://skillsmith.ch").rstrip("/")
        req = _ureq.Request(base + "/api/sandbox-run",
                            data=json.dumps({"text": text}).encode(),
                            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with _ureq.urlopen(req, timeout=280) as resp:
                report = json.loads(resp.read().decode())
        except Exception as e:  # noqa: BLE001 - never crash the MCP session
            return _tool_result({"error": f"behavioral analysis failed: {e}",
                                 "note": "the sandbox can take up to ~120s; retry once if this was a timeout"})
        sev = (report.get("ai_analysis") or {}).get("severity") or {}
        return _tool_result({
            "analysis_id": report.get("analysis_id"),
            "sha256": report.get("sha256"),
            "status": report.get("status"),
            "duration_s": report.get("duration_s"),
            "static_iocs": report.get("static_iocs"),
            "ai_analysis": report.get("ai_analysis"),
            "severity": sev,
            "permalink": f"/api/analysis?id={report.get('analysis_id')}" if report.get("analysis_id") else None,
            "disclaimer": "Behavioral SIMULATION by an LLM analyst in an isolated container. Heuristic, not a guarantee.",
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
    # PT-T33: JSON-RPC notifications (no id) must not produce a response.
    if "id" not in req:
        return 204, None
    params = req.get("params") or {}
    # pentest PT-T3: params must be an object for our methods; arrays or
    # strings used to crash with a 500 instead of a structured RPC error.
    if not isinstance(params, dict):
        return 200, {"jsonrpc": "2.0", "id": req_id,
                     "error": {"code": -32602, "message": "invalid params: expected object"}}

    if rpc_method == "initialize":
        result = {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "skillsmith-mcp", "version": "1.0.0"},
            "capabilities": {"tools": {}},
            "instructions": "Call skillsmith_signup first to get a free api_key. Core loop: scan_skill (verdict) -> analyze_behavior (sandbox) -> watch_skill {url, webhook_url} to monitor a skill for rug-pulls; watch_skill also supports list:true and delete:<watch_id> for full lifecycle management. Re-check any past scan with lookup_hash. Also: get_skill_content, list_safe_skills, file_report, find_similar, whoami. All tools share the https://skillsmith.ch quota; free tier 5 scans/day.",
        }
    elif rpc_method == "tools/list":
        result = {"tools": TOOLS}
    elif rpc_method == "tools/call":
        # PT-T33: unknown tool / missing tool name are invalid params, not a
        # silent null result (JSON-RPC correctness; clients rely on errors).
        tool_name = params.get("name")
        if not isinstance(tool_name, str) or not tool_name:
            return 200, {"jsonrpc": "2.0", "id": req_id,
                         "error": {"code": -32602, "message": "invalid params: missing tool name"}}
        if tool_name not in {t["name"] for t in TOOLS}:
            return 200, {"jsonrpc": "2.0", "id": req_id,
                         "error": {"code": -32602, "message": f"unknown tool: {tool_name}"}}
        # PT-T171/Fix #54: arguments must be an object; lists/strings crashed
        # _call_tool with an unhandled AttributeError.
        tool_args = params.get("arguments")
        if not isinstance(tool_args, dict):
            return 200, {"jsonrpc": "2.0", "id": req_id,
                         "error": {"code": -32602, "message": "invalid params: arguments must be an object"}}
        try:
            result = _call_tool(tool_name, tool_args, client_ip=client_ip)
        except Exception as e:  # noqa: BLE001 - never crash the MCP session
            result = {"content": [{"type": "text", "text": '{"error": "internal_error"}'}], "isError": True}
    elif rpc_method == "ping":
        result = {}
    else:
        return 200, {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {rpc_method}"}}

    return 200, {"jsonrpc": "2.0", "id": req_id, "result": result}
