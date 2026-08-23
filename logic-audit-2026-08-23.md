# Logic Audit — skillsmith-web Backend (2026-08-23)

Scope: `api/index.py`, `api/account.py`, `api/scans.py`, `api/mcp.py`, `api/osv.py`,
`api/features.py`, `api/sandbox.py`, `vercel.json`, `public/*.html` (JS logic).
Method: full read of every file + local reproduction where possible.
Excluded (already known/fixed): XFF spoofing, MCP batch crash, payment-signature
replay (`_claim_payment_signature`), quota races (two-phase confirm), MCP signup
rate limit, ReDoS homoglyph regex, route enumeration, chunked-base64 evasion.

## L1 — Critical — Pro-Tier-Scan wirft IMMER UnboundLocalError (und verbrennt trotzdem Quota)

**Datei:Zeile:** `api/account.py:379` (Nutzung) vs. `api/account.py:394` (`def _confirm_over`)

**Beschreibung:** In `check_and_consume_quota()` ruft der Pro-Zweig
`_confirm_over("pro_used_count", PRO_DAILY_LIMIT)` auf, aber die Funktion
`_confirm_over` wird erst SPÄTER im Funktionskörper (im Free-Zweig, Zeile 394)
per `def` gebunden. Python löst den Namen zur Laufzeit auf dem lokalen Scope auf:
auf dem Pro-Pfad wurde das `def` nie ausgeführt → `UnboundLocalError`.

Lokal reproduziert (fake Blob-Store, Pro-Account):

```
EXCEPTION: UnboundLocalError: cannot access local variable '_confirm_over'
where it is not associated with a value
record after call: {'pro_used_count': 1, ...}   # Quota VOR dem Crash erhöht!
```

Folgen:
1. Jeder zahlende Pro-User bekommt bei JEDEM `/api/scan`-Versuch HTTP 400 mit
   geleakter interner Fehlermeldung (`handle_scan` gibt `str(e)` zurück).
2. Die Quota wird VOR dem Crash bereits inkrementiert und gespeichert —
   Pro-User verbrennen Scans ohne Ergebnis.
3. Widerspruch zur Schwesterfunktion `check_and_consume_lookup_quota()`, die den
   Confirm-Schritt korrekt inline (sleep + re-read) implementiert.

**Fix:** Helper vor beide Zweige ziehen bzw. inline wie im Lookup-Pendant:

```python
    today = _today()

    def _confirm_over(field, limit):          # VOR dem is_pro-Zweig definieren
        time.sleep(0.15)
        check = _blob_get(_blob_path(api_key)) or {}
        return int(check.get(field, 0) or 0) > limit

    is_pro = record.get("pro_expires_at", 0) > time.time()
    if is_pro:
        ...
```
Zusätzlich: interne Fehler nicht als `{"error": str(e)}` an Clients leaken
(generische 400-Meldung + Logging).

## L2 — High — MCP: komplette Quota-Umgehung durch Weglassen des api_key (anonym = unmetered)

**Datei:Zeile:** `api/mcp.py:149, 172, 182, 191` (`check_and_consume_quota(api_key or None)` usw.)

**Beschreibung:** `check_and_consume_quota(None)` / `check_and_consume_lookup_quota(None)`
geben `(True, {"tier": "anonymous"})` zurück — absichtlich, für den REST-Pfad, wo
`_client_api_key()` vorher garantiert einen serverseitigen `ip_<hash>`-Pseudo-Key
einfügt und `/api/scan` zusätzlich einen expliziten Key verlangt (401 ohne).

Der MCP-Tool-Dispatcher macht das Gegenteil: `args.get("api_key", "")` wird per
`api_key or None` zu `None`, wenn der Client den Key einfach weglässt. Damit ist:

- `scan_skill` OHNE api_key → unbegrenzt viele Scans (auch publish=true!),
- `lookup_hash`, `get_skill_content`, `list_safe_skills` OHNE api_key →
  unbegrenzte DB-Lookups,

während die Web-/REST-Frontdoors dieselben Aktionen auf 5/Tag (+IP-Cap) begrenzen.
Das MCP-Frontdoor bricht damit das eigene Versprechen aus dem Modulheader
("one quota system, three front doors"). Der bekannte Fix "Signup-Rate-Limit via
MCP" betrifft nur `skillsmith_signup`, nicht diese vier Tools.

**Fix:** In `_call_tool()` vor allen Tools außer `skillsmith_signup`:

```python
    if name != "skillsmith_signup" and not api_key:
        return _tool_result({"error": "api_key required",
                             "signup": "call skillsmith_signup first"})
```
Alternativ in mcp.py den anonymen Fall auf `pseudo_key_for_ip(client_ip)`
mappen (wie es der REST-Pfad tut), damit zumindest der IP-Kohortenlimit greift.

## L3 — High — vercel.json: Routen für /api/lookup, /api/registry, /api/skill, /api/buy_credit fehlen

**Datei:Zeile:** `vercel.json` (routes-Array) vs. `api/index.py`
(`handle_lookup`, `handle_registry`, `handle_get_skill`, `handle_buy_credit`)
und `public/index.html` (`loadRegistry()`, `useSkill()`, `searchBtn.onclick`,
`buyOneCredit()`, `buyLookupCredit()`).

**Beschreibung:** Das Projekt ist als Single-Entrypoint gebaut ("Vercel's Python
builder wants a single entrypoint per project", siehe index.py-Kommentar): ALLE
Endpunkte hängen am PATH_INFO-Dispatch von `/api/index.py`. Die legacy `routes`-
Liste in vercel.json mapped aber nur:

```
/api/scan_pro, /api/scan-pro, /api/signup, /api/scan, /api/auth/(.*),
/mcp, /health, /badge, /api/public_scan
```

Es gibt KEINE Route für `/api/lookup`, `/api/registry`, `/api/skill` und
`/api/buy_credit` — und es existiert auch keine gleichnamige Datei unter `api/`,
die Vercel als eigene Funktion mounten könnte. Diese vier Endpunkte erreichen den
WSGI-Dispatcher daher nie; die Requests fallen auf Filesystem-Routing → 404.
Betroffene Produktfeatures:

- Safe-Skills-Registry im UI (`loadRegistry()` → GET /api/registry)
- "Use"-Button / Skill-Fetch (`useSkill()` → GET /api/skill)
- Hash-Lookup im DB-Tab (`searchBtn.onclick` → GET /api/lookup)
- Pay-per-use-Kauf (`buyOneCredit()`/`buyLookupCredit()` → POST /api/buy_credit)

Caveat: ob Vercel in der konkreten Deployment-Konfiguration doch ein implizites
Fallback macht, lässt sich ohne Deploy nicht beweisen — aber die routes-Liste ist
zumindest inkonsistent mit dem eigenen Single-Entrypoint-Design, und der Fix ist
kostenlos.

**Fix:** Routen ergänzen:

```json
    { "src": "/api/lookup", "dest": "/api/index.py" },
    { "src": "/api/registry", "dest": "/api/index.py" },
    { "src": "/api/skill", "dest": "/api/index.py" },
    { "src": "/api/buy_credit", "dest": "/api/index.py" },
    { "src": "/api/buy-credit", "dest": "/api/index.py" }
```

## L4 — High — Publish/Registry: einmal published bleibt für immer published (kein Risiko-Recheck, keine Depublish)

**Datei:Zeile:** `api/scans.py` — `record_scan()` (Registry-Write nur
`if is_safe:`), `get_published_content()`; `api/index.py`
(`handle_get_skill`, `handle_public_scan`, Badge).

**Beschreibung:** Mehrere zusammenwirkende Lücken im Publish-Lebenszyklus:

1. **Sticky Clean-Status:** `record_scan()` schreibt den Registry-Eintrag NUR,
   wenn der aktuelle Scan clean ist (`if is_safe:`). Wird derselbe Hash später
   rescanned und jetzt (z. B. nach einer Ruleset-Aktualisierung oder neuen
   OSV-Daten) als `high` bewertet, wird der Registry-Eintrag NICHT aktualisiert
   und NICHT gelöscht. `list_safe_registry()` zeigt weiter "clean, seen Nx",
   während `/api/lookup`, Badge und `/api/public_scan` denselben Hash als high
   melden — widersprüchliche Verdicts je Oberfläche.
2. **Content ohne Recheck:** `get_published_content()` prüft nur, ob ein Content-
   Blob existiert — kein Blick auf den aktuellen `risk_level` des Scan-Records
   und nicht auf Community-Reports. Ein als malicious gemeldeter Skill
   (`add_report(verdict="malicious")`) bleibt unbegrenzt über `/api/skill` und
   MCP `get_skill_content` abrufbar. Der Watch-List/"rug-pull"-Mechanismus
   (`create_watch` etc.) ist ebenfalls rein informativ und ändert nichts.
3. **has_content=True ist unumkehrbar:** einmal gesetztes `has_content` wird in
   `record_scan()` vom Bestand übernommen und nie zurückgesetzt; es gibt keinen
   Depublish-Pfad (auch nicht durch den Publisher selbst).
4. **Zertifikate verstärken das:** `make_certificate()` signiert den Clean-Verdict
   mit 90 Tagen Gültigkeit — ein Zertifikat bleibt kryptographisch gültig,
   nachdem die Plattform denselben Hash längst anders bewertet; `verify_certificate()`
   kennt keinen Widerruf.

Da der Hash den Inhalt festlegt, ändert sich der Inhalt nicht — aber das Urteil
über ihn schon, und genau dafür gibt es keinerlei Propagation.

**Fix:**
```python
# record_scan(): Registry immer synchronisieren, bei !is_safe löschen/flaggen
    if is_safe:
        _blob_put(_registry_path(digest), registry_entry)
    elif existing.get("has_content") or get_scan_record(digest):  # vorher clean
        reg = _blob_get(_registry_path(digest))
        if reg:
            reg["revoked"] = True
            reg["risk_level"] = analysis.get("risk_level")
            _blob_put(_registry_path(digest), reg)

# get_published_content(): Risiko-Recheck vor Auslieferung
def get_published_content(digest: str) -> str | None:
    rec = get_scan_record(digest)
    if not rec or rec.get("risk_level") != "clean":
        return None                      # Inhalt nicht mehr ausliefern
    doc = _blob_get(_content_path(digest))
    return doc.get("text") if doc else None
```
Und `list_safe_registry()` / `/api/skill` sollen Einträge mit `revoked` filtern;
Community-Tally ("malicious" >= Schwelle) soll denselben Weg gehen.

## L5 — Medium — OSV-Recompute aktualisiert risk_score/risk_level, aber NICHT security_score

**Datei:Zeile:** `api/index.py:544-548` (handle_scan, OSV-Block); `security_score`
wird nur in `analyze()` (Zeile 311) gesetzt.

**Beschreibung:** Nach dem Anhängen der OSV-Findings (weight 8 je verwundbares
Paket) werden `risk_score` und `risk_level` neu berechnet — `security_score`
bleibt aber auf dem Wert aus `analyze()` stehen. Ein Skill mit Static-Fund=0 und
3 verwundbaren Pins liefert:

```
risk_score: 24, risk_level: "high", security_score: 100   # inkonsistent
```

Das Frontend rendert den Security-Score prominent als Gauge ("100 / 100" in grün),
während das Badge daneben HIGH zeigt. Auch der in der DB gespeicherte Scan-Record
(`record_scan` speichert nur risk_level/risk_score) und spätere Badge-/Lookup-
Antworten kennen den security_score nicht — die Zahl ist systematisch zu
optisch, sobald OSV zuschlägt.

**Fix:**

```python
                    rs = result["risk_score"]
                    result["risk_level"] = ("clean" if rs == 0 else "low" if rs < 8 else
                                            "medium" if rs < 20 else "high")
                    result["security_score"] = max(0, 100 - rs * 4)   # fehlt bisher
```

## L6 — Medium — MCP scan_skill: seen_before immer true + DB-Verdict weicht vom REST-Verdict ab (kein OSV)

**Datei:Zeile:** `api/mcp.py:155-165` vs. `api/index.py:528-567` (handle_scan).

**Beschreibung:** Zwei Inkonsistenzen desselben Hashes je Eingangstür:

1. **seen_before logisch falsch:** REST liest `cached = get_scan_record(digest)`
   VOR `record_scan()`. MCP ruft `get_scan_record(digest)` erst NACH
   `record_scan()` auf → der Eintrag existiert dann per Definition schon;
   `seen_before` ist also auch beim allerersten Scan `true`.
2. **OSV-Stufe fehlt komplett:** MCP ruft nur `idx.analyze(text)` und überspringt
   den OSV-Block von handle_scan. Derselbe SKILL.md-Inhalt bekommt damit über
   MCP ein anderes risk_level/risk_score/Findings-Set als über REST, und genau
   dieses (zu freundliche) Ergebnis landet via `record_scan()` in der globalen
   Scan-Historie, im Registry-Gating (`is_safe`) und im Badge. Ein Publisher,
   der über MCP published, umgeht die OSV-Vulnerability-Gating-Stufe.

**Fix:** Scan-Pipeline in eine gemeinsame Funktion ziehen und aus beiden Handlern
aufrufen, z. B. in index.py:

```python
def scan_and_record(text: str, publish: bool = False):
    digest = sha256_of(text)
    cached = get_scan_record(digest)
    result = analyze(text)
    result.update(_osv_enrich(result, text))     # bestehender OSV-Block als Helper
    history = record_scan(digest, result, name=result.get("name") or "",
                          publish=publish, text=text)
    return digest, cached, history, result
```
MCP nutzt dieselbe Funktion; `seen_before` kommt dann aus `cached`.

## L7 — Medium — Tier-Anzeige: whoami nutzt Truthiness statt Zeitvergleich; GET /api/signup kennt Premium nicht

**Datei:Zeile:** `api/mcp.py:206` (whoami); `api/index.py:860-890`
(handle_signup GET).

**Beschreibung:**

1. **mcp.py whoami:** `"premium" if record.get("premium_expires_at", 0)` — das
   prüft nur >0, NICHT `> time.time()`. Ein abgelaufenes Premium/Pro wird in
   whoami für immer als "premium"/"pro" gemeldet, obwohl
   check_and_consume_quota denselben Account korrekt als free behandelt.
   Agent-Clients, die whoami als Tier-Quelle nutzen, zeigen/verhalten sich falsch.
   (Zusätzlich fehlen die versprochenen Lookup-Zähler `pro_lookup_count`/
   `free_lookup_count` in der Antwort.)
2. **index.py handle_signup GET:** Die Tier-Kaskade ist
   unlimited → pro → free. Es gibt keinen Premium-Zweig: Ein zahlender Premium-
   User (premium_expires_at aktiv) bekommt `"tier": "free", "used": <free_used_count>`.
   Das Frontend (`refreshAccountBar()`) zeigt ihm daraufhin "Free: 3/5 scans used
   today" und blendet Kauf-Links ein — obwohl er unbegrenzte Scans hat.

Die eigentliche Enforcement-Reihenfolge in check_and_consume_quota ist korrekt
(unlimited → premium → pro → free); nur die beiden Anzeige-Pfade weichen davon ab.

**Fix:**

```python
# mcp.py whoami
now = time.time()
tier = ("unlimited" if record.get("unlimited")
        else "premium" if record.get("premium_expires_at", 0) > now
        else "pro" if record.get("pro_expires_at", 0) > now
        else "free")

# index.py handle_signup GET — Zweig VOR is_pro einfügen
if record.get("unlimited"):
    ...
elif record.get("premium_expires_at", 0) > time.time():
    body = {"tier": "premium", "name": record.get("name", "")}
elif is_pro:
    ...
```

## L8 — Medium — Pay-per-use-Credits: Race macht bonus_credits negativ; Rollback kann Fremde-Einheiten mitabbuchen

**Datei:Zeile:** `api/account.py` — Credit-Verbrauch im Free-Zweig von
`check_and_consume_quota()` (ca. Zeile 415-418) und beide Rollback-Stellen
(`max(0, int(latest.get(...)) - 1)`), analog in `check_and_consume_lookup_quota()`.

**Beschreibung:**

1. **Negativer Credit-Stand:** Der Bonus-Credit-Verbrauch ist ein nackter
   Read-Modify-Write OHNE den Two-Phase-Confirm, den die Free-/Pro-Zähler haben:
   ```
   if record.get("bonus_credits", 0) > 0:
       record["bonus_credits"] -= 1
       _blob_put(...)
   ```
   Zwei parallele Requests lesen beide `bonus_credits=1`, beide dekrementieren →
   `-1` wird persistiert. Da Credits für echtes Geld (0.02 USDC) gekauft werden,
   ist das ein Double-Spend bezahlter Einheiten. Gleiches Muster für
   `bonus_lookup_credits`. (Kann zusätzlich durch `add_pay_per_use_credit`-
   Races weiter ins Minus rutschen.)
2. **Rollback bucht fremde Einheiten ab:** Der Lost-Race-Rollback liest
   `latest` neu und dekrementiert pauschal um 1. Ist zwischen eigenem Write und
   Re-Read eine andere, erfolgreiche Anfrage geschrieben worden, senkt der
   Rollback deren Zählerstand — die eigene verlorene Einheit wird nie
   zurückgebucht, dafür eine fremde. Bei Datumwechsel um Mitternacht UTC trifft
   der Rollback u. U. den Zähler des NEUEN Tages (dort steht z. B. 2, wird zu 1),
   während der alte Tageszähler stehen bleibt.

**Fix:**
```python
    if record.get("free_used_count") >= FREE_DAILY_LIMIT:
        credits = int(record.get("bonus_credits", 0) or 0)
        if credits > 0:
            record["bonus_credits"] = max(0, credits - 1)
            _blob_put(_blob_path(api_key), record)
            # Confirm wie bei free/pro: re-read; wenn < erwarteter Stand -> Retry/Deny
            ...
```
Und der Rollback soll nur dekrementieren, wenn `latest.get("free_used_date") ==
today` und der Stand > 0 ist — oder besser: gar kein pauschaler Decrement,
sondern Vergleich gegen die eigene erwartete Menge (CAS-artig über `_v`).

## L9 — Medium — osv.extract_pins: False Positives aus Fließtext erhöhen risk_level um bis zu "high"

**Datei:Zeile:** `api/osv.py:14-16` (`_PY_PIN_RE`, `_NPM_PIN_RE`) und
`api/index.py:536-543` (weight-8-Findings aus OSV-Treffern).

**Beschreibung:** `extract_pins(text)` läuft über den GESAMTEN SKILL.md-Text,
nicht nur über Code-Blöcke oder Requirement-Dateien:

- `_PY_PIN_RE` (`^\s*([a-zA-Z0-9_.\-]+)\s*[=~>]{1,2}\s*(\d+\.\d+...)`) greift auf
  jede Zeile, die wie eine Versionsbedingung aussieht — auch Prosa wie
  `Requires python>=3.8` (Package "python"), `app>=1.0 recommended`,
  `compatibility: numpy==1.24.0 or newer`.
- `_NPM_PIN_RE` matcht JEDES JSON-artige Paar `"x": "1.2.3"` — auch
  Versions-Mappings, Beispiel-Konfigurationen in Doku-Codeblöcken
  (`"node": "18.0.0"`) oder erfundene Namen.

Jedes davon erzeugt einen OSV-Query-Eintrag; trifft OSV (z. B. für reale
Packages wie `requests`, `numpy`), wird pro Paket ein Finding mit **weight 8**
angehängt und risk_level neu berechnet. Ein ansonsten CLEANER Skill mit dem Satz
"Tested with requests>=2.28" kann dadurch auf medium/high springen, im Registry-
Gating (`is_safe`) durchfallen bzw. — via L4 — fälschlich als gefährlich gelten.
Das ist genau die gefragte "Versionsnummern in Prosa"-False-Positive-Klasse.

**Fix:** Pins nur aus abgegrenzten Zonen ziehen und Gewicht dämpfen:

```python
_FENCED_RE = re.compile(r"```(?:python|bash|sh|txt|text)?\n(.*?)```", re.S)

def extract_pins(text: str) -> list[dict]:
    blocks = "\n".join(m.group(1) for m in _FENCED_RE.finditer(text))
    lines = [ln for ln in blocks.split("\n")
             if re.match(r"^\s*[a-zA-Z0-9_.\-]+\s*[=~>]", ln)]   # requirements-Stil
    ...
```
und/oder das OSV-Finding von weight 8 auf 3 senken (Hinweischarakter statt
Verdachtsmoment), da ein verwundbarer Pin kein böser Wille ist.

## L10 — Low — osv.query_osv: Tippfehler `"**pin"` im Error-Eintrag

**Datei:Zeile:** `api/osv.py:55`

**Beschreibung:** Im Fail-open-Zweig werden fehlerhafte Einträge als
`{"**pin": p, "error": "osv_unavailable"}` statt `{"pin": p, ...}` gebaut.
Alle Konsumenten erwarten die Struktur `{**p, ...}` (flaches dict mit
`package`/`version`) bzw. den Key `pin`; das API-Output-Feld
`osv.packages` enthält dann Objekte ohne `package`, was Downstream-Code
(z. B. spätere Auswertungen, die `p["package"]` lesen) zum KeyError zwingt.

**Fix:**
```python
        return [{**p, "error": "osv_unavailable"} for p in pins]
```

## L11 — Low — sha256-Validierung inkonsistent: /api/lookup und /api/public_scan akzeptieren Nicht-Hex

**Datei:Zeile:** `api/index.py` — `handle_lookup`
(`if len(digest) != 64:`), `handle_public_scan`
(`if len(digest) != 64 or not any(c.isalpha() or c.isdigit() ...)`), im
Vergleich dazu korrekt: `handle_badge` und `handle_get_skill`(MCP prüft nur Länge).

**Beschreibung:** Nur der Badge-Handler erzwingt `[0-9a-f]{64}`. `/api/lookup`
und MCP `lookup_hash`/`get_skill_content` prüfen ausschließlich die Länge,
`/api/public_scan` sogar nur "mindestens ein alnum-Zeichen". Der ungeprüfte
String wird direkt in Blob-Pfade interpoliert (`f"scans/{digest}.json"`),
d. h. Zeichen wie `/`, `.`, `..` gelangen in Storage-Key-Namen (64-Zeichen-Limit
begrenzt praktischen Pfad-Traversal-Schaden; primär ein Konsistenz- und
Hygieneproblem — aber derselbe Input fließt auch in Antworten/Badges zurück).

**Fix:** Ein gemeinsamer Validator:

```python
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

def _valid_digest(s: str) -> bool:
    return bool(_HEX64_RE.match(s))
```
und in handle_lookup / handle_get_skill / handle_public_scan / mcp lookup_hash /
get_skill_content verwenden.

## L12 — Low — Quota wird vor Input-Validierung verbraucht

**Datei:Zeile:** `api/index.py` — `handle_get_skill` und `handle_lookup`
(check_and_consume_lookup_quota VOR sha256-Validierung), `handle_scan_pro`
(check_and_consume_quota VOR files-Validierung).

**Beschreibung:** Bei `GET /api/skill?sha256=zu-kurz&api_key=...` wird zuerst die
Lookup-Quota dekrementiert und DANACH der 400 "must be a 64-char hex digest"
geliefert. Dasselbe in `/api/scan_pro`: Der Scan-Zähler läuft hoch, bevor
geprüft wird, ob `files` überhaupt eine gültige nicht-leere Liste ist — ein
Tippfehler im Payload kostet einen (bezahlten) Scan. Bei MCP `lookup_hash`/
`get_skill_content` ebenso.

**Fix:** Validierung vor Quota-Konsum ziehen, z. B. in handle_get_skill:

```python
        qs = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""))
        digest = (qs.get("sha256") or [""])[0].lower()
        if len(digest) != 64:
            ... 400 ...
        allowed, quota_info = check_and_consume_lookup_quota(explicit_api_key)
```

## L13 — Low — Frontend: decodeURIComponent auf #key kann das GESAMTE Hauptskript abwerfen

**Datei:Zeile:** `public/index.html` — `captureOAuthKey()` IIFE (Anfang des
Haupt-<script>-Blocks).

**Beschreibung:** `decodeURIComponent(location.hash.slice(5))` wirft `URIError`
bei fehlerhaften Escape-Sequenzen (z. B. Link `https://skillsmith.ch/#key=%ZZ`).
Die IIFE läuft top-level im Hauptskript; eine unbehandelte Exception bricht die
Ausführung des GESAMTEN Skriptblocks ab → keine Button-Handler, kein
`refreshAccountBar()`, kein `loadRegistry()`. Ein böser Link macht die Seite für
Normaluser funktionslos bis das Fragment manuell entfernt wird.

**Fix:**
```javascript
  if (location.hash.startsWith('#key=')) {
    try {
      const key = decodeURIComponent(location.hash.slice(5));
      if (/^sk_[A-Za-z0-9_-]+$/.test(key)) localStorage.setItem('skillsmith-api-key', key);
    } catch (e) { /* malformed fragment: ignore */ }
    history.replaceState(null, '', location.pathname + location.search);
  }
```

## L14 — Low — Frontend: fetch-Fehler in runScan / Hash-Lookup unbehandelt (kein User-Feedback)

**Datei:Zeile:** `public/index.html` — `runScan()` (try/finally OHNE catch),
`searchBtn.onclick` (gar kein try/catch).

**Beschreibung:**
1. `runScan()`: Netzwerkfehler oder eine 500 mit Nicht-JSON-Body lässt
   `fetch(...)`/`res.json()` werfen. Das `finally` stellt den Button wieder her,
   aber die Exception verschwindet als unhandled promise rejection — der User
   sieht gar nichts (kein Fehler-Tab, Button tut so, als wäre nichts gewesen).
   Dasselbe gilt für `doSignup`, `activatePro`, `buyOneCredit`,
   `activatePremium`, `buyLookupCredit` (alle ohne catch).
2. `searchBtn.onclick` (DB-Tab): `await res.json()` ohne try/catch — ein 500
   (z. B. Blob-Store-Ausfall) wirft unhandled; der Klick scheint tot.

**Fix:**

```javascript
async function runScan(payload, btn) {
  ...
  btn.disabled = true; btn.textContent = 'Scanning...';
  try {
    const res = await fetch('/api/scan', {...});
    const data = await res.json();
    ...
  } catch (e) {
    showResultError('NETWORK ERROR', 'Scan could not be completed: ' + e.message);
  } finally {
    btn.disabled = false; btn.textContent = originalLabel;
  }
}
```

## L15 — Low — Simhash: leere/kurze Skills bekommen identische All-Zero-DNA → Schein-Cluster

**Datei:Zeile:** `api/features.py` — `simhash()` (`if n == 0: return "0"*16`),
`scans.store_dna()`/`find_similar_dna()`.

**Beschreibung:** Skills mit weniger als 3 Wörtern im gescannten Text erzeugen
`n == 0` und damit die DNA `"0000000000000000"`. Jeder solche Eintrag hat
Hamming-Distanz 0 zu jedem anderen — `find_similar_dna()` meldet sie als
"near-duplicate (distance 0)", obwohl die Skills nichts gemeinsam haben. Auch
generell: Distanz-Schwelle 12 auf 64 Bit ist großzügig; kurze generische
SKILL.md-Vorlagen clustern stark. Folge: irreführende "ähnliche Skills"-Treffer
im UI/API, im Zweifel Falschbeschuldigung von Nachahmern harmloser Skills.

**Fix:**

```python
    if n < 8:                       # Mindest-Shingle-Anzahl für belastbare DNA
        return None                 # Caller speichert dann keine DNA
```
und in store_dna/find_similar_dna None-/Zero-DNA-Einträge überspringen:
```python
    if dna is None or dna == "0" * 16:
        return
```

## L16 — Low — Zertifikats-Secret: harcoded Fallback erlaubt gefälschte Certs bei fehlender Env

**Datei:Zeile:** `api/features.py` — `_cert_secret()`
(`... or "skillsmith-dev-secret"`).

**Description:** Ist weder `SKILLSMITH_CERT_SECRET` noch
`BLOB_READ_WRITE_TOKEN` gesetzt (falsch konfiguriertes Deployment, Preview-
Umgebung, lokaler Mirror), signiert `make_certificate()` mit einem öffentlich im
Quellcode stehenden Secret. `verify_certificate()` akzeptiert dann beliebig
gefälschte Verdict-Zertifikate ("clean") für beliebige Hashes. Fail-open statt
fail-closed.

**Fix:**
```python
def _cert_secret() -> bytes:
    s = os.environ.get("SKILLSMITH_CERT_SECRET") or os.environ.get("BLOB_READ_WRITE_TOKEN")
    if not s:
        raise RuntimeError("certificate secret not configured")
    return hashlib.sha256(("cert:" + s).encode()).digest()
```


---

## Explizit geprüft und NICHT als Bug befunden

- `_today()` nutzt durchgehend `time.gmtime()` (UTC) — auch in handle_signup GET
  und den Rollback-Pfaden. Kein Zeitzonen-Mismatch gefunden.
- Tier-Priorität in der Enforcement (`check_and_consume_quota` /
  `check_and_consume_lookup_quota`): unlimited > premium > pro > free,
  zeitbasierte Vergleiche korrekt. Nur die ANZEIGE weicht ab (L7).
- Frontend-Rendering (`render()`, `addRow`, scan.html `esc()`): durchgängig
  textContent/createTextNode bzw. HTML-Escaping — kein localStorage-XSS-Vektor
  über Skill-Inhalte gefunden; der api_key-in-localStorage-Risikobereich wird
  sauber behandelt.
- Tab-Races: Buttons werden während des Scans disabled; render() löscht nur
  eigene Container. Restrisiko paralleler URL-/Text-Scan-Buttons ist kosmetisch.
- Badge-Cache (60 s) nach Verdict-Änderung: kurz, aber bewusst gewählt — kein Bug.
- sandbox.py capability/trace patterns: Heuristik-Qualität, keine Logikfehler
  (false positives wie IPv4-lookalike-Versionen sind dokumentierte Heuristik-Grenzen).
