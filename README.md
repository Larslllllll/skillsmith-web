# skillsmith-web

Live browser demo for [skillsmith](https://github.com/Larslllllll/skillsmith):
paste a `SKILL.md`, get instant lint + static security-scan results.
Stateless — nothing submitted is stored.

- `public/index.html` — single-page paste-and-scan UI
- `api/scan.py` — Vercel Python (WSGI) serverless function running the same
  lint/scan heuristics as the `skillsmith` CLI
