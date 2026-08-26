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
