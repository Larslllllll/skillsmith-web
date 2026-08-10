"""
skillsmith-web scan history + safe-skills registry ("VirusTotal for
SKILL.md files" -- but also actually usable, not just a verdict).

Every scanned SKILL.md's raw text is hashed with SHA-256. By default we
never store the raw text itself (privacy: "nothing you paste is retained"
stays true for a plain scan) -- only the hash, the analysis result, and a
seen-count/timestamps. Re-scanning the exact same file is then instant
(cache hit) and shows "scanned N times before" the way a hash-lookup
malware scanner would.

Publishing (opt-in, explicit): if you pass publish=true on a clean,
lint-ok scan, we ALSO store the actual SKILL.md content, so the public
Safe Skills Database is a real place to fetch and use a vetted skill --
not just a list of hashes with a safety verdict. Unpublished scans are
never exposed this way; publishing is a deliberate, separate action from
scanning, and only ever applies to your own submission.
"""
from __future__ import annotations

import hashlib
import time

try:
    from .account import _blob_get, _blob_put, BLOB_API_BASE, _blob_headers
except ImportError:  # local/script execution without package context
    from account import _blob_get, _blob_put, BLOB_API_BASE, _blob_headers
import urllib.request
import json


def sha256_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _scan_path(digest: str) -> str:
    return f"scans/{digest}.json"


def _registry_path(digest: str) -> str:
    return f"safe_registry/{digest}.json"


def _content_path(digest: str) -> str:
    return f"scan_content/{digest}.json"


def get_scan_record(digest: str) -> dict | None:
    return _blob_get(_scan_path(digest))


def get_published_content(digest: str) -> str | None:
    """Returns the actual SKILL.md text if this hash was explicitly
    published, else None. This is the "use the skill" read path."""
    doc = _blob_get(_content_path(digest))
    return doc.get("text") if doc else None


def record_scan(digest: str, analysis: dict, name: str = "", publish: bool = False, text: str = "") -> dict:
    """Upsert the scan-history record for this hash and, if the result is
    clean, add/refresh its entry in the public safe-skills registry.

    If publish=True and the result is clean+lint-ok, also store the actual
    SKILL.md content so the Safe Skills Database entry is fetchable/usable,
    not just a pass/fail verdict.
    """
    existing = get_scan_record(digest) or {
        "sha256": digest,
        "first_seen_at": time.time(),
        "seen_count": 0,
    }
    existing["last_seen_at"] = time.time()
    existing["seen_count"] = existing.get("seen_count", 0) + 1
    existing["name"] = name or existing.get("name", "")
    existing["risk_level"] = analysis.get("risk_level")
    existing["risk_score"] = analysis.get("risk_score")
    existing["lint_ok"] = analysis.get("lint_ok")
    existing["parse_ok"] = analysis.get("parse_ok")
    existing["findings"] = analysis.get("findings", [])
    existing["lint_issues"] = analysis.get("lint_issues", [])

    is_safe = (
        analysis.get("parse_ok")
        and analysis.get("lint_ok")
        and analysis.get("risk_level") == "clean"
    )

    has_content = existing.get("has_content", False)
    if publish and is_safe and text:
        _blob_put(_content_path(digest), {"text": text, "published_at": time.time()})
        has_content = True
    existing["has_content"] = has_content

    _blob_put(_scan_path(digest), existing)

    if is_safe:
        registry_entry = {
            "sha256": digest,
            "name": name,
            "first_seen_at": existing["first_seen_at"],
            "last_seen_at": existing["last_seen_at"],
            "seen_count": existing["seen_count"],
            "has_content": has_content,
        }
        _blob_put(_registry_path(digest), registry_entry)

    return existing


def list_safe_registry(limit: int = 50) -> list[dict]:
    """List entries in the safe-skills registry, newest-first.

    Labeled everywhere in the UI as automated-heuristic-clean only, not a
    manual audit -- see DISCLAIMER in index.py. Entries with has_content
    True can be fetched in full via GET /api/skill?sha256=...
    """
    url = f"{BLOB_API_BASE}/?prefix=safe_registry/&limit={max(1, min(limit, 200))}"
    req = urllib.request.Request(url, headers=_blob_headers(), method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            listing = json.loads(resp.read().decode())
    except Exception:  # noqa: BLE001
        return []

    entries = []
    for b in listing.get("blobs", []):
        try:
            dl_req = urllib.request.Request(b["url"], headers=_blob_headers(), method="GET")
            with urllib.request.urlopen(dl_req, timeout=10) as resp:
                entries.append(json.loads(resp.read().decode()))
        except Exception:  # noqa: BLE001
            continue

    entries.sort(key=lambda e: e.get("last_seen_at", 0), reverse=True)
    return entries[:limit]
