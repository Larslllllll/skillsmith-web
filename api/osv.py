"""OSV.dev dependency vulnerability lookup.

Extracts pinned Python/JS package requirements from a SKILL.md's code
blocks and checks them against OSV.dev's batch API. Fail-open by design:
if OSV is slow or unreachable, the scan still returns its static results,
just without the osv section.
"""
import json
import re
import urllib.request

# package==1.2.3 / package>=1.0,<2.0 style pins (python) and "pkg": "1.2.3" (npm-ish)
_PY_PIN_RE = re.compile(r"^\s*([a-zA-Z0-9_.\-]+)\s*[=~>]{1,2}\s*(\d+\.\d+(?:\.\d+)?)", re.M)
_NPM_PIN_RE = re.compile(r'"([@a-zA-Z0-9/_.\-]+)"\s*:\s*"(?:~|\^)?(\d+\.\d+\.\d+)"')
_ECOSYSTEMS = ("PyPI", "npm")
_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_MAX_PACKAGES = 25


def extract_pins(text: str) -> list[dict]:
    """Pull (ecosystem, package, version) triples out of code blocks."""
    seen, pins = set(), []
    for m in _PY_PIN_RE.finditer(text):
        eco, pkg, ver = "PyPI", m.group(1).lower(), m.group(2)
        key = (eco, pkg, ver)
        if key not in seen:
            seen.add(key)
            pins.append({"ecosystem": eco, "package": pkg, "version": ver})
    for m in _NPM_PIN_RE.finditer(text):
        eco, pkg, ver = "npm", m.group(1).lower(), m.group(2)
        key = (eco, pkg, ver)
        if key not in seen:
            seen.add(key)
            pins.append({"ecosystem": eco, "package": pkg, "version": ver})
    return pins[:_MAX_PACKAGES]


def query_osv(pins: list[dict], timeout: float = 6.0) -> list[dict]:
    """Return one entry per pin with any known OSV vulnerabilities.

    Never raises: on network trouble returns entries with error=None data so
    callers can keep going."""
    if not pins:
        return []
    queries = [{"package": {"ecosystem": p["ecosystem"], "name": p["package"]},
                "version": p["version"]} for p in pins]
    body = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(_OSV_BATCH_URL, data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        results = data.get("results", [])
    except Exception:  # noqa: BLE001 - fail open
        return [{**p, "error": "osv_unavailable"} for p in pins]

    out = []
    for p, r in zip(pins, results):
        vulns = []
        for v in (r or {}).get("vulns", []):
            vulns.append({
                "id": v.get("id", ""),
                "summary": (v.get("summary") or "")[:200],
                "severity": (v.get("database_specific") or {}).get("severity", ""),
                "fixed": sorted({fx for aff in v.get("affected", [])
                                 for fx in (aff.get("ranges", [{}])[0].get("events", []) or [])
                                 if isinstance(fx, dict) and fx.get("fixed")}) or [],
            })
        out.append({**p, "vulnerabilities": vulns})
    return out
