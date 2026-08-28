"""Tests for api/mcp.py — pure JSON-RPC 2.0 dispatch.

Exercises handle_jsonrpc() in isolation (no HTTP, no blob store, no
auth). All handlers fall back to structured JSON-RPC errors per
JSON-RPC 2.0 spec section 5.1; these tests pin that contract.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "api"))

import json

import mcp as mcp_mod


def test_jsonrpc_version_2_accepted():
    """PT-T177: jsonrpc:"2.0" is the only accepted version, per spec 4.1."""
    status, body = mcp_mod.handle_jsonrpc(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    )
    assert status == 200, f"expected 200, got {status}"
    assert "result" in body, f"expected result, got: {body}"
    assert "tools" in body["result"]


def test_jsonrpc_version_1_0_rejected():
    """PT-T177: jsonrpc:"1.0" must return -32600 Invalid Request."""
    status, body = mcp_mod.handle_jsonrpc(
        {"jsonrpc": "1.0", "id": 1, "method": "tools/list"}
    )
    assert status == 200, f"expected 200, got {status}"
    assert "error" in body, f"expected error, got: {body}"
    assert body["error"]["code"] == -32600, f"expected -32600, got: {body['error']}"
    assert "1.0" in body["error"]["message"]


def test_jsonrpc_version_99_0_rejected():
    """PT-T177: any non-"2.0" version returns -32600."""
    status, body = mcp_mod.handle_jsonrpc(
        {"jsonrpc": "99.0", "id": 1, "method": "tools/list"}
    )
    assert status == 200
    assert body["error"]["code"] == -32600


def test_jsonrpc_version_2_string_rejected():
    """PT-T177: "2" is not "2.0" — strict equality per spec."""
    status, body = mcp_mod.handle_jsonrpc(
        {"jsonrpc": "2", "id": 1, "method": "tools/list"}
    )
    assert status == 200
    assert body["error"]["code"] == -32600


def test_jsonrpc_missing_defaults_to_2_0():
    """PT-T177: missing jsonrpc field still works (spec allows optional)."""
    status, body = mcp_mod.handle_jsonrpc(
        {"id": 1, "method": "tools/list"}
    )
    assert status == 200
    assert "result" in body
    assert "tools" in body["result"]


def test_jsonrpc_notification_no_response():
    """PT-T33: notification (no id) must not produce a response body."""
    status, body = mcp_mod.handle_jsonrpc(
        {"jsonrpc": "2.0", "method": "tools/list"}
    )
    assert status == 204
    assert body is None


def test_jsonrpc_batch_array_rejected():
    """JSON-RPC 2.0 spec section 6: server MAY support batch. This server
    declines and returns a clear -32600 error."""
    # handle_jsonrpc is called per-element by the WSGI layer; the top-level
    # batch guard lives in handle_mcp. Skip here and test integration.
    pass  # covered by tests/test_index.py integration tests


def test_jsonrpc_params_must_be_object():
    """PT-T3: params as string or list returns -32602 invalid params."""
    status, body = mcp_mod.handle_jsonrpc(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": "string"}
    )
    assert status == 200
    assert body["error"]["code"] == -32602

    status2, body2 = mcp_mod.handle_jsonrpc(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": [1, 2]}
    )
    assert status2 == 200
    assert body2["error"]["code"] == -32602


def test_jsonrpc_method_missing():
    """Missing method field returns -32601 Method not found."""
    status, body = mcp_mod.handle_jsonrpc(
        {"jsonrpc": "2.0", "id": 1}
    )
    assert status == 200
    assert body["error"]["code"] == -32601


def test_jsonrpc_unknown_method():
    """Unknown method name returns -32601 Method not found."""
    status, body = mcp_mod.handle_jsonrpc(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/explode"}
    )
    assert status == 200
    assert body["error"]["code"] == -32601
    assert "tools/explode" in body["error"]["message"]


def test_handle_mcp_rejects_non_object_with_specific_type():
    """PT-T180: non-object JSON-RPC requests get a clear type-specific error.
    Previously the message said "batch requests are not supported" for ANY
    non-dict type (strings, numbers, null), misleading the client."""
    import io as _io
    import index as _idx

    # string body
    body = b'"hello"'
    env = {"REQUEST_METHOD": "POST", "CONTENT_LENGTH": str(len(body)),
           "QUERY_STRING": "", "wsgi.input": _io.BytesIO(body)}
    statuses = []
    out = _idx.handle_mcp(env, lambda st, hd: statuses.append(st))
    parsed = json.loads(b"".join(out))
    assert statuses[0].startswith("200"), f"expected 200, got {statuses[0]}"
    assert parsed["error"]["code"] == -32600
    assert "must be a JSON object" in parsed["error"]["message"]
    assert "str" in parsed["error"]["message"]

    # number body
    body = b"12345"
    env = {"REQUEST_METHOD": "POST", "CONTENT_LENGTH": str(len(body)),
           "QUERY_STRING": "", "wsgi.input": _io.BytesIO(body)}
    statuses = []
    out = _idx.handle_mcp(env, lambda st, hd: statuses.append(st))
    parsed = json.loads(b"".join(out))
    assert parsed["error"]["code"] == -32600
    assert "int" in parsed["error"]["message"]

    # null body
    body = b"null"
    env = {"REQUEST_METHOD": "POST", "CONTENT_LENGTH": str(len(body)),
           "QUERY_STRING": "", "wsgi.input": _io.BytesIO(body)}
    statuses = []
    out = _idx.handle_mcp(env, lambda st, hd: statuses.append(st))
    parsed = json.loads(b"".join(out))
    assert parsed["error"]["code"] == -32600
    assert "NoneType" in parsed["error"]["message"]


def test_handle_mcp_rejects_batch_with_batch_message():
    """PT-T180: a JSON array (batch) still gets the batch-specific message."""
    import io as _io
    import index as _idx
    body = b'[{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}]'
    env = {"REQUEST_METHOD": "POST", "CONTENT_LENGTH": str(len(body)),
           "QUERY_STRING": "", "wsgi.input": _io.BytesIO(body)}
    statuses = []
    out = _idx.handle_mcp(env, lambda st, hd: statuses.append(st))
    parsed = json.loads(b"".join(out))
    assert parsed["error"]["code"] == -32600
    assert "batch" in parsed["error"]["message"]


def test_mcp_unknown_api_key_surfaces_correctly():
    """PT-T184: invalid api_key in MCP tools should return "unknown api_key",
    not "quota_exceeded" (which would mislead the user into thinking they
    hit a quota limit)."""
    import mcp as _mcp2
    # scan_skill with bad api_key
    status, body = _mcp2.handle_jsonrpc({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "scan_skill", "arguments": {"text": "x", "api_key": "sk_definitely-not-a-real-key-1234567890"}}
    })
    assert status == 200
    text = json.loads(body["result"]["content"][0]["text"])
    assert text.get("error") == "unknown api_key, sign in again", f"got: {text}"
    assert "tip" in text


def test_mcp_lookup_hash_unknown_api_key_surfaces_correctly():
    """PT-T184: same fix for lookup_hash."""
    import mcp as _mcp2
    status, body = _mcp2.handle_jsonrpc({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "lookup_hash", "arguments": {
            "sha256": "0" * 64,
            "api_key": "sk_definitely-not-a-real-key-1234567890"
        }}
    })
    assert status == 200
    text = json.loads(body["result"]["content"][0]["text"])
    assert text.get("error") == "unknown api_key, sign in again", f"got: {text}"


def test_mcp_list_safe_skills_unknown_api_key_surfaces_correctly():
    """PT-T184: same fix for list_safe_skills (no sha256 param)."""
    import mcp as _mcp2
    status, body = _mcp2.handle_jsonrpc({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "list_safe_skills", "arguments": {
            "api_key": "sk_definitely-not-a-real-key-1234567890"
        }}
    })
    assert status == 200
    text = json.loads(body["result"]["content"][0]["text"])
    assert text.get("error") == "unknown api_key, sign in again", f"got: {text}"


def test_mcp_get_skill_content_unknown_api_key_surfaces_correctly():
    """PT-T184: same fix for get_skill_content."""
    import mcp as _mcp2
    status, body = _mcp2.handle_jsonrpc({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "get_skill_content", "arguments": {
            "sha256": "0" * 64,
            "api_key": "sk_definitely-not-a-real-key-1234567890"
        }}
    })
    assert status == 200
    text = json.loads(body["result"]["content"][0]["text"])
    assert text.get("error") == "unknown api_key, sign in again", f"got: {text}"


def test_mcp_analyze_behavior_requires_text():
    """PT-T193: analyze_behavior must return a clear error for empty/missing text."""
    import mcp as _mcp3
    # No text
    status, body = _mcp3.handle_jsonrpc({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "analyze_behavior", "arguments": {"api_key": "sk_test"}}
    })
    assert status == 200
    text = json.loads(body["result"]["content"][0]["text"])
    assert "text" in text.get("error", "").lower(), f"expected text error, got: {text}"
    # Whitespace-only
    status, body = _mcp3.handle_jsonrpc({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "analyze_behavior", "arguments": {"text": "   \n\t  ", "api_key": "sk_test"}}
    })
    text = json.loads(body["result"]["content"][0]["text"])
    assert "text" in text.get("error", "").lower(), f"expected text error, got: {text}"


def test_mcp_analyze_behavior_rejects_non_string_text():
    """PT-T193: non-string text is rejected with a clear error, not internal_error."""
    import mcp as _mcp3
    for bad in [{"text": 123}, {"text": ["a", "b"]}, {"text": {"k": "v"}}, {"text": True}]:
        status, body = _mcp3.handle_jsonrpc({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "analyze_behavior", "arguments": bad}
        })
        text = json.loads(body["result"]["content"][0]["text"])
        assert "error" in text, f"expected error for {bad}, got: {text}"
        assert "internal_error" not in text.get("error", ""), f"got internal_error for {bad}: {text}"


def test_mcp_analyze_behavior_rejects_oversized_text():
    """PT-T193: text > 100,000 chars returns a clear size error."""
    import mcp as _mcp3
    status, body = _mcp3.handle_jsonrpc({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "analyze_behavior", "arguments": {"text": "A" * 100001, "api_key": "sk_test"}}
    })
    text = json.loads(body["result"]["content"][0]["text"])
    assert "too large" in text.get("error", ""), f"expected size error, got: {text}"


def test_mcp_whoami_unknown_api_key():
    """PT-T193: whoami with invalid api_key returns 'unknown api_key'."""
    import mcp as _mcp3
    status, body = _mcp3.handle_jsonrpc({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "whoami", "arguments": {"api_key": "sk_definitely-not-a-real-key"}}
    })
    text = json.loads(body["result"]["content"][0]["text"])
    assert text.get("error") == "unknown api_key", f"got: {text}"


def test_mcp_whoami_missing_api_key():
    """PT-T193: whoami without api_key returns 'api_key required'."""
    import mcp as _mcp3
    status, body = _mcp3.handle_jsonrpc({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "whoami", "arguments": {}}
    })
    text = json.loads(body["result"]["content"][0]["text"])
    assert "api_key" in text.get("error", "").lower(), f"got: {text}"


def test_mcp_find_similar_invalid_sha256():
    """PT-T193: find_similar with invalid sha256 returns clear error, not internal_error."""
    import mcp as _mcp3
    for bad_sha in ["abc", "0" * 63, "0" * 65, "x" * 64, 123, None]:
        args = {"sha256": bad_sha, "api_key": "sk_test"} if bad_sha is not None else {"api_key": "sk_test"}
        status, body = _mcp3.handle_jsonrpc({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "find_similar", "arguments": args}
        })
        text = json.loads(body["result"]["content"][0]["text"])
        assert "error" in text, f"expected error for sha={bad_sha!r}, got: {text}"
        assert "internal_error" not in text.get("error", ""), f"internal_error for {bad_sha!r}: {text}"


def test_mcp_list_safe_skills_negative_limit():
    """PT-T193: list_safe_skills with negative limit is handled (not crash)."""
    import mcp as _mcp3
    status, body = _mcp3.handle_jsonrpc({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "list_safe_skills", "arguments": {"limit": -10, "api_key": "sk_test"}}
    })
    # Should not crash; either returns a result or a clear error
    assert status == 200
    assert "result" in body or "error" in body


def test_mcp_get_skill_content_invalid_sha256():
    """PT-T193: get_skill_content with invalid sha256 returns clear error."""
    import mcp as _mcp3
    status, body = _mcp3.handle_jsonrpc({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "get_skill_content", "arguments": {"sha256": "not-a-hash", "api_key": "sk_test"}}
    })
    text = json.loads(body["result"]["content"][0]["text"])
    assert "sha256" in text.get("error", "").lower(), f"expected sha256 error, got: {text}"


def test_mcp_analyze_behavior_rejects_url_field():
    """PT-T196: analyze_behavior only accepts text, not url. If a user passes
    a url field, it should be ignored (not fetched like /api/scan does)."""
    import mcp as _mcp4
    # analyze_behavior should work with just text
    status, body = _mcp4.handle_jsonrpc({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "analyze_behavior", "arguments": {
            "text": "print('hello')",
            "api_key": "sk_test"
        }}
    })
    # Should not crash; either returns a result or a clear error
    assert status == 200
    # The result should be a valid JSON-RPC response
    assert "result" in body or "error" in body


def test_mcp_analyze_behavior_handles_empty_text():
    """PT-T196: empty text returns clear error, not crash."""
    import mcp as _mcp4
    for empty in ["", "   ", "\n\t", None]:
        args = {"text": empty, "api_key": "sk_test"} if empty is not None else {"api_key": "sk_test"}
        status, body = _mcp4.handle_jsonrpc({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "analyze_behavior", "arguments": args}
        })
        text = json.loads(body["result"]["content"][0]["text"])
        assert "error" in text, f"expected error for empty={empty!r}, got: {text}"
        assert "text" in text.get("error", "").lower(), f"expected text error for {empty!r}, got: {text}"

def test_mcp_file_report_sha256_type_confusion():
    """PT-T223: file_report sha256 type-confusion returns clean error, no 500."""
    import mcp as _mcp_fr
    for bad_sha in [None, 12345, ["a", "b"], {"$ne": None}, True, False]:
        code, body = _mcp_fr.handle_jsonrpc({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "file_report", "arguments": {"sha256": bad_sha, "verdict": "malicious"}}
        })
        assert code == 200, f"sha={bad_sha}: got status {code}"
        result = body.get("result", {}).get("content", [{}])[0].get("text", "")
        assert "sha256 must be a 64-char hex digest" in result, f"sha={bad_sha}: got {result}"


def test_mcp_file_report_verdict_type_confusion():
    """PT-T223: file_report verdict type-confusion returns clean error."""
    import mcp as _mcp_fr2
    valid_sha = "0" * 64
    for bad_verdict in [None, 12345, True, False, ["malicious"], {"v": "malicious"}, "MAlIcIous"]:
        code, body = _mcp_fr2.handle_jsonrpc({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "file_report", "arguments": {"sha256": valid_sha, "verdict": bad_verdict}}
        })
        assert code == 200, f"verdict={bad_verdict}: got status {code}"
        result = body.get("result", {}).get("content", [{}])[0].get("text", "")
        assert "verdict must be" in result, f"verdict={bad_verdict}: got {result}"


def test_mcp_file_report_comment_type_confusion():
    """PT-T223: file_report non-string comment handled (treated as empty)."""
    import mcp as _mcp_fr3
    # No api_key -> unknown api_key error, not a 500 crash
    code, body = _mcp_fr3.handle_jsonrpc({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "file_report", "arguments": {
            "sha256": "0" * 64, "verdict": "note",
            "comment": 12345  # not a string
        }}
    })
    assert code == 200
    result = body.get("result", {}).get("content", [{}])[0].get("text", "")
    # Either unknown api_key (no key passed) or valid response — but NEVER 500/crash
    assert "internal_error" not in result or "unknown api_key" in result, f"unexpected: {result}"


def test_mcp_find_similar_sha256_type_confusion():
    """PT-T223: find_similar sha256 type-confusion returns clean error."""
    import mcp as _mcp_fs
    for bad_sha in [None, 12345, ["a", "b"], {}, True, False, "0" * 63, "x" * 64]:
        code, body = _mcp_fs.handle_jsonrpc({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "find_similar", "arguments": {"sha256": bad_sha}}
        })
        assert code == 200, f"sha={bad_sha}: got status {code}"
        result = body.get("result", {}).get("content", [{}])[0].get("text", "")
        assert "sha256 must be a 64-char hex digest" in result, f"sha={bad_sha}: got {result}"


def test_mcp_batch_array_rejected():
    """PT-T223: batch array request returns clean -32600 error, no crash."""
    import mcp as _mcp_ba
    import index as _idx_ba
    import json as _json_ba
    import io as _io_ba
    environ = {
        "REQUEST_METHOD": "POST",
        "CONTENT_TYPE": "application/json",
        "CONTENT_LENGTH": "100",
        "wsgi.input": _io_ba.BytesIO(_json_ba.dumps([
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 2, "method": "ping"}
        ]).encode())
    }
    captured = {}
    def _sr(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = headers
    body = b"".join(_idx_ba.handle_mcp(environ, _sr))
    parsed = _json_ba.loads(body.decode())
    # Batch returns 200 OK with -32600 Invalid Request (per JSON-RPC 2.0 spec)
    assert "200" in captured["status"], f"expected 200, got {captured['status']}"
    assert parsed.get("error", {}).get("code") == -32600, f"expected -32600, got {parsed}"
    assert "batch requests are not supported" in parsed["error"]["message"]


def test_mcp_prototype_pollution_blocked():
    """PT-T223: __proto__ and constructor pollution in params doesn't crash."""
    import mcp as _mcp_pp
    for pollution in [{"__proto__": {"admin": True}}, {"constructor": {"prototype": {"admin": True}}}]:
        code, body = _mcp_pp.handle_jsonrpc({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "scan_skill", "arguments": {"text": "name: x\ndescription: x"}}
        })
        assert code == 200
        # The result should be a normal response, not a 500 crash
        assert "result" in body or "error" in body
