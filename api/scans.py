"""
skillsmith-web scan history + safe-skills registry ("VirusTotal for
SKILL.md files").

Every scanned SKILL.md's raw text is hashed with SHA-256. We never store
the raw text itself (privacy: "nothing you paste is retained" stays true)
-- only the hash, the analysis result, and a seen-count/timestamps. Re-
scanning the exact same file is then instant (cache hit) and shows
"scanned N times before" the way a hash-lookup malware scanner would.

Clean, lint-ok scans are additionally indexed into a small "safe skills"
registry that the UI can browse -- explicitly labeled as automated-heuristic-
only, not a manual security audit (see the disclaimer shown in the UI).
"""
from __future__ import annotations

import hashlib
import time

from account import _blob_get, _blob_put, BLOB_API_BASE, _blob_headers
import urllib.request
import json


def sha256_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _scan_path(digest: str) -> str:
    return f"scans/{digest}.json"


def _registry_path(digest: str) -> str:
    return f"safe_registry/{digest}.json"


def get_scan_record(digest: str) -> dict | None:
    return _blob_get(_scan_path(digest))


def record_scan(digest: str, analysis: dict, name: str = "") -> dict:
    """Upsert the scan-history record for this hash and, if the result is
    clean, add/refresh its entry in the public safe-skills registry."""
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
    _blob_put(_scan_path(digest), existing)

    is_safe = (
        analysis.get("parse_ok")
        and analysis.get("lint_ok")
        and analysis.get("risk_level") == "clean"
    )
    if is_safe:
        registry_entry = {
            "sha256": digest,
            "name": name,
            "first_seen_at": existing["first_seen_at"],
            "last_seen_at": existing["last_seen_at"],
            "seen_count": existing["seen_count"],
        }
        _blob_put(_registry_path(digest), registry_entry)

    return existing


def list_safe_registry(limit: int = 50) -> list[dict]:
    """List entries in the safe-skills registry, newest-first.

    Labeled everywhere in the UI as automated-heuristic-clean only, not a
    manual audit -- see DISCLAIMER in index.py.
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
