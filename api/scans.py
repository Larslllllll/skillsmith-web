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


def purge_blob_versions(path: str) -> int:
    """Delete EVERY stored object whose pathname matches this logical path.

    Vercel Blob's addRandomSuffix=false still appends random suffixes to
    some writes (see account._blob_get docstring), so several physical
    objects can exist for one logical path. A single DELETE by pathname can
    leave older versions behind -- and _blob_get resurrects those (pentest
    tick PT-T8: a depublished malicious skill came back exactly that way).
    Returns the number of objects deleted."""
    import urllib.parse as _up
    prefix = path.rsplit(".", 1)[0] if "." in path else path
    req = urllib.request.Request(
        f"{BLOB_API_BASE}/?prefix={_up.quote(prefix)}&limit=100",
        headers=_blob_headers(), method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            blobs = json.loads(resp.read().decode()).get("blobs", [])
    except Exception:  # noqa: BLE001 - best effort, like _blob_delete
        return 0
    n = 0
    # a physical copy is either the exact logical path or the same path with
    # Vercel's random suffix inserted before the extension ("abc-XY12.json");
    # require a ".", "-" or end-of-string boundary after the prefix so
    # unrelated paths sharing a prefix ("abcd.json") are never touched.
    for b in blobs:
        pn = b.get("pathname", "")
        if not pn.startswith(prefix):
            continue
        rest = pn[len(prefix):]
        if rest and rest[0] not in (".", "-"):
            continue
        try:
            dreq = urllib.request.Request(
                f"{BLOB_API_BASE}?pathname={_up.quote(b['pathname'])}",
                headers=_blob_headers(), method="DELETE")
            with urllib.request.urlopen(dreq, timeout=10) as resp:
                resp.read()
            n += 1
        except Exception:  # noqa: BLE001
            pass
    return n


def _blob_delete(path: str) -> None:
    """Best-effort delete via the Blob store's REST delete endpoint."""
    req = urllib.request.Request(
        f"{BLOB_API_BASE}?pathname={urllib.parse.quote(path)}",
        headers=_blob_headers(), method="DELETE")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception:  # noqa: BLE001 - best effort by design
        pass
import urllib.request
import urllib.parse
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
    existing["security_score"] = analysis.get("security_score")  # needed for score-trend
    existing["lint_ok"] = analysis.get("lint_ok")
    existing["parse_ok"] = analysis.get("parse_ok")
    existing["findings"] = analysis.get("findings", [])
    existing["lint_issues"] = analysis.get("lint_issues", [])

    # score history for the UI trend sparkline (keep the last 10 scans)
    hist = list(existing.get("score_history") or [])
    if not hist and existing.get("security_score") is not None:
        hist = [[existing.get("last_seen_at") or time.time(), existing["security_score"]]]
    hist.append([time.time(), analysis.get("security_score")])
    existing["score_history"] = hist[-10:]

    is_safe = (
        analysis.get("parse_ok")
        and analysis.get("lint_ok")
        and analysis.get("risk_level") == "clean"
    )

    has_content = existing.get("has_content", False)
    if publish and is_safe and text:
        _blob_put(_content_path(digest), {"text": text, "published_at": time.time()})
        has_content = True

    # logic audit L4: publishing must be reversible. If a later scan of the
    # SAME hash comes back not-clean, the stale clean registry entry and any
    # stored content would keep serving a skill that no longer passes -- pull
    # both immediately.
    if not is_safe:
        # PT-T8: purge ALL versions -- a single DELETE can leave older
        # suffixed blob copies that _blob_get would resurrect.
        purge_blob_versions(_registry_path(digest))
        purge_blob_versions(_content_path(digest))
        has_content = False

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


# --- community reports (feature: crowd verdicts) ---

def _reports_path(digest: str) -> str:
    return f"reports/{digest}.json"


def add_report(digest: str, entry: dict) -> dict:
    """Append a user report (false_positive / malicious / note) for a hash."""
    record = _blob_get(_reports_path(digest)) or {"sha256": digest, "reports": []}
    entry = {k: str(v)[:500] for k, v in entry.items()}
    entry["at"] = time.time()
    record["reports"].append(entry)
    record["tally"] = {}
    for r_ in record["reports"]:
        k_ = r_.get("verdict", "note")
        record["tally"][k_] = record["tally"].get(k_, 0) + 1
    _blob_put(_reports_path(digest), record)
    return {"sha256": digest, "total": len(record["reports"]), "tally": record["tally"]}


def get_reports(digest: str) -> dict:
    return _blob_get(_reports_path(digest)) or {"sha256": digest, "reports": [], "tally": {}}


# --- global stats counter (feature: public live stats) ---

def _stats_path() -> str:
    return "meta/stats.json"


def bump_stats(risk_level: str) -> dict:
    stats = _blob_get(_stats_path()) or {"total_scans": 0, "by_risk": {}, "started_at": time.time()}
    stats["total_scans"] = int(stats.get("total_scans", 0)) + 1
    by = stats.setdefault("by_risk", {})
    by[risk_level] = int(by.get(risk_level, 0)) + 1
    stats["updated_at"] = time.time()
    _blob_put(_stats_path(), stats)
    return stats


def get_stats() -> dict:
    return _blob_get(_stats_path()) or {"total_scans": 0, "by_risk": {}}


# --- watch list / diff guard (feature: rug-pull detection) ---

def _watch_path(watch_id: str) -> str:
    return f"watch/{watch_id}.json"


def create_watch(url: str, digest: str, webhook_url: str = "") -> dict:
    import secrets as _secrets
    wid = _secrets.token_urlsafe(12)
    rec = {"watch_id": wid, "url": url[:300], "baseline_sha256": digest,
           "created_at": time.time(), "webhook_url": webhook_url[:300] if webhook_url else "",
           "checks": 0, "last_checked_at": 0}
    _blob_put(_watch_path(wid), rec)
    return rec


def get_watch(watch_id: str) -> dict | None:
    return _blob_get(_watch_path(watch_id))


def update_watch(rec: dict) -> None:
    _blob_put(_watch_path(rec["watch_id"]), rec)


# --- skill DNA storage ---

def store_dna(digest: str, dna: str, risk_level: str, name: str) -> None:
    _blob_put(f"dna/{dna}_{digest[:12]}.json",
              {"sha256": digest, "dna": dna, "risk_level": risk_level,
               "name": name[:120], "at": time.time()})


def find_similar_dna(dna: str, exclude_digest: str = "", max_results: int = 5) -> list[dict]:
    """Scan stored DNA blobs; return entries within Hamming distance <= 12."""
    try:
        from .features import hamming_hex
    except ImportError:  # local/script execution without package context
        from features import hamming_hex
    url = f"{BLOB_API_BASE}/?prefix=dna/&limit=200"
    req = urllib.request.Request(url, headers=_blob_headers(), method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            listing = json.loads(resp.read().decode())
    except Exception:  # noqa: BLE001
        return []
    out = []
    for b in listing.get("blobs", []):
        if exclude_digest and exclude_digest[:12] in b["pathname"]:
            continue
        try:
            dl_req = urllib.request.Request(b["url"], headers=_blob_headers(), method="GET")
            with urllib.request.urlopen(dl_req, timeout=10) as resp:
                e = json.loads(resp.read().decode())
        except Exception:  # noqa: BLE001
            continue
        dist = hamming_hex(dna, e.get("dna", ""))
        if dist <= 12:
            out.append({"sha256": e.get("sha256"), "name": e.get("name"),
                        "risk_level": e.get("risk_level"), "distance": dist})
    out.sort(key=lambda x: x["distance"])
    return out[:max_results]
