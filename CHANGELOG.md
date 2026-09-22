# Changelog

All notable changes to Haak Anvil will be documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned for v0.3
- OWASP ZAP JSON parser
- PDF renderer via WeasyPrint
- AI executive summary (Claude API)
- HTML template variants (executive / technical / pretty-print)
- Exploit-availability enrichment (ExploitDB / GitHub PoCs)

## [0.2.0] — 2026-09-22

### Added
- **Burp Suite XML parser** — `haak-anvil burp report.xml`. Decodes base64 blobs,
  strips HTML to plain text, extracts CVE/CWE and CVSS vectors from free text.
- **Nuclei JSONL parser** — `haak-anvil nuclei out.jsonl`. Handles `-jsonl`
  (line-delimited) and legacy `-json` (array); reads `classification` CVSS/CVE/CWE.
- **CVE enrichment via NVD 2.0** (`--enrich`) — fills missing CVSS on findings and
  backfills CWE; honors `NVD_API_KEY` for higher rate limits.
- **EPSS scoring** (FIRST.org) — annotates findings with exploitation probability
  and percentile; `ReportBundle.findings_by_epss()` sorts by likelihood.
- **Local TTL cache** for NVD + EPSS lookups under `~/.haak-anvil/cache/`.
- **DOCX renderer** (`-f docx` / `-o report.docx`) — client-ready Word report via
  python-docx (optional `docx` extra).
- **`haak-anvil init`** — scaffolds an `engagement.yaml` template.
- CLI: output extension now overrides `--format` (e.g. `-o report.docx`).
- Tests + fixtures for Burp, Nuclei, enrichers (offline via `httpx.MockTransport`),
  DOCX renderer, and CLI.

### Changed
- `Finding` gained `epss_score`, `epss_percentile`, `enriched` fields.
- `ReportBundle` gained `unique_cves` and `findings_by_epss()`.
- Repository moved to `github.com/CEOHaak/Haak_Anvil`.

## [0.1.0] — 2026-05-15

### Added
- Initial release.
- Core data models (`Engagement`, `Asset`, `Port`, `Service`, `Finding`, `CVSS`, `Severity`, `ReportBundle`)
- Severity normalization helpers (CVSS → Severity, Nessus risk_factor → Severity)
- Nmap XML parser (Nmap 7.x compatible, defusedxml)
- Nessus v2 .nessus parser (CVSS v3 preferred, CVE/CWE extraction from tags + free text)
- Renderers: JSON (machine), Markdown (human), HTML (Jinja2 + Tailwind CDN)
- CLI: `haak-anvil nmap | nessus | merge | version`
- ReportBundle merge across multiple tools on same engagement
- Test suite (pytest, fixtures for Nmap + Nessus samples)
- GitHub Actions CI (Linux/Mac/Windows × Python 3.10/3.11/3.12)
- Apache 2.0 license
- README + CHANGELOG + .gitignore

### Authors
- Alan Contreras (`@HaakConsulting` / contacto@haak.com.mx)

[Unreleased]: https://github.com/CEOHaak/Haak_Anvil/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/CEOHaak/Haak_Anvil/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/CEOHaak/Haak_Anvil/releases/tag/v0.1.0
