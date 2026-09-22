# Haak Anvil

> Modern, multi-format pentest report generator. Mexican-built, professional-grade.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange)]()

**Haak Anvil** turns raw scanner output (Nmap, Nessus, and many more coming) into
**professional, multi-format pentest reports** with consistent severity scoring,
engagement-scoped metadata, CVE/CWE enrichment, and templates ready to ship to a
client.

Built for offensive security teams who deliver **real engagements**, not just
PDFs full of bullet points.

---

## Why another report tool?

Existing tools either:

- Output Excel-only with no engagement context.
- Hard-code a single tool's format and break when you switch scanners.
- Are unmaintained Python 2 relics.
- Hide everything behind a SaaS paywall.

Haak Anvil is:

- **Modern Python 3.10+** (type-hinted, pydantic v2, async-ready).
- **Multi-tool first**: Nmap, Nessus, **Burp Suite**, and **Nuclei** today; ZAP / sqlmap / Subfinder next.
- **Multi-format output**: JSON (machine), Markdown (humans), HTML (clients), **DOCX** (editable deliverable).
- **Engagement-scoped**: every report is tied to a YAML-defined engagement (client, scope, dates, methodology, analyst).
- **CVE/CWE-aware + enrichment**: pulls IDs from tags and free text, then `--enrich` fills CVSS from **NVD 2.0** and adds **EPSS** exploitation scores (locally cached).
- **Apache 2.0**: use it commercially, no obligations.

---

## Quickstart

```bash
git clone https://github.com/CEOHaak/Haak_Anvil.git
cd Haak_Anvil
python -m pip install -e .            # core
python -m pip install -e ".[docx]"   # + DOCX output
```

### Parse an Nmap scan and emit HTML

```bash
nmap -sV -oX out.xml 10.0.0.0/24
haak-anvil nmap out.xml --format html --output report.html
```

### Parse a Nessus export

```bash
haak-anvil nessus client.nessus --format md --output report.md
```

### Parse Burp Suite / Nuclei

```bash
haak-anvil burp burp-report.xml -f html -o burp.html
haak-anvil nuclei scan.jsonl -f docx -o nuclei.docx
```

### Enrich with NVD CVSS + EPSS

```bash
export NVD_API_KEY=...        # optional, raises NVD rate limits
haak-anvil nuclei scan.jsonl --enrich -f docx -o report.docx
```

`--enrich` fills any missing CVSS from NVD 2.0, backfills CWE, and annotates each
finding with its EPSS score (probability of exploitation in 30 days). Lookups are
cached under `~/.haak-anvil/cache/`.

### Scaffold an engagement

```bash
haak-anvil init -o engagement.yaml
```

### Scoped engagement

Create `engagement.yaml`:

```yaml
id: HK-2026-001
client:
  name: Acme Corp
  contact: ciso@acme.example
scope: "External perimeter + corporate WLAN"
methodology: PTES
period:
  start: 2026-05-10
  end:   2026-05-20
analyst: Alan Contreras
language: es-MX
```

Then:

```bash
haak-anvil nmap out.xml -e engagement.yaml -f html -o reports/
haak-anvil nessus client.nessus -e engagement.yaml -f json -o reports/
```

### Merge multi-tool results

```bash
haak-anvil nmap out.xml -e engagement.yaml -f json -o reports/nmap.json
haak-anvil nessus client.nessus -e engagement.yaml -f json -o reports/nessus.json
haak-anvil merge reports/nmap.json reports/nessus.json -e engagement.yaml -f html -o reports/final.html
```

---

## Architecture

```
haak_anvil/
├── core/         # Engagement, Asset, Port, Finding, CVSS, Severity, ReportBundle
├── parsers/      # ParserBase + nmap, nessus, burp, nuclei  (zap, sqlmap... v0.3)
├── renderers/    # RendererBase + json, markdown, html, docx  (pdf... v0.3)
├── enrichers/    # NVD 2.0 CVSS + EPSS enrichment + local TTL cache
├── templates/    # Jinja2 HTML templates
└── cli.py        # Typer CLI
```

Every parser maps tool-specific output into a unified `ReportBundle`. Every
renderer consumes a `ReportBundle` and emits a format. Adding a new tool is a
~150-line module that subclasses `ParserBase`.

---

## Supported tools (v0.2)

| Tool        | Status | Notes                                              |
|-------------|--------|----------------------------------------------------|
| Nmap        | ✅     | XML output (`-oX`); 7.x tested                    |
| Nessus      | ✅     | `.nessus` v2 export; CVSS v3 preferred over v2    |
| Burp Suite  | ✅     | XML export; base64 decode, CVE/CWE + CVSS vector  |
| Nuclei      | ✅     | `-jsonl` (and legacy `-json` array)               |
| OWASP ZAP   | 🚧 v0.3 | JSON/XML reports                                 |
| sqlmap      | 🚧 v0.3 | Output dir parsing                               |
| Subfinder   | 🚧 v0.3 | JSON output                                      |

---

## Output formats (v0.2)

| Format      | Status | Use case                                  |
|-------------|--------|-------------------------------------------|
| JSON        | ✅     | Machine ingest (TheHive, SIEM, custom)    |
| Markdown    | ✅     | GitHub wikis, internal docs               |
| HTML        | ✅     | Client deliverable (Tailwind CDN, single file) |
| DOCX        | ✅     | Editable client deliverable (python-docx) |
| PDF         | 🚧 v0.3 | Printable, WeasyPrint                    |

---

## Enrichment (v0.2)

| Source      | What it adds                                             |
|-------------|----------------------------------------------------------|
| NVD 2.0     | CVSS v3.1 base score/vector for findings missing one; CWE backfill |
| EPSS (FIRST)| Probability + percentile of exploitation in next 30 days |

Enable with `--enrich`. Results are cached under `~/.haak-anvil/cache/` (NVD 30d,
EPSS 3d TTL). Set `NVD_API_KEY` to raise NVD rate limits.

---

## Roadmap

- **v0.2** (shipped 2026-09-22): Burp + Nuclei parsers, NVD 2.0 + EPSS enrichment with cache, DOCX renderer, `init` scaffolder.
- **v0.3**: OWASP ZAP + sqlmap parsers, PDF renderer (WeasyPrint), HTML template variants, AI executive summary (Claude API).
- **v0.4**: Optional FastAPI + HTMX web UI, TheHive / Wazuh / MISP push integrations, chain-of-custody signing (Ed25519).

See [CHANGELOG.md](CHANGELOG.md) for full release history.

---

## Development

```bash
python -m pip install -e ".[dev,docx]"   # docx extra unlocks the DOCX renderer tests
ruff check src tests
pytest --cov=haak_anvil --cov-report=term-missing
```

PRs welcome. Open an issue first for big changes.

---

## License

Apache License 2.0. See [LICENSE](LICENSE).

---

## Author

**Alan Contreras** — CEO & Co-Founder, [Haak Cybersecurity Consulting](https://haak.com.mx)
México · [contacto@haak.com.mx](mailto:contacto@haak.com.mx) · [LinkedIn](https://mx.linkedin.com/in/alan-contreras-)

Built in the tradition of pentest report tooling (dradis-ce, faraday-ng, secutils),
rewritten from scratch with modern Python for 2026 workflows.
