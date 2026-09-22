import json

from haak_anvil.core.severity import Severity
from haak_anvil.parsers import NucleiParser


def test_nuclei_parses_all_records(nuclei_file, engagement):
    bundle = NucleiParser(engagement).parse(nuclei_file)
    assert len(bundle.findings) == 3
    titles = [f.title for f in bundle.findings]
    assert any("Log4j" in t for t in titles)
    assert any("Exposed .git" in t for t in titles)


def test_nuclei_severity_and_cvss(nuclei_file, engagement):
    bundle = NucleiParser(engagement).parse(nuclei_file)
    log4j = next(f for f in bundle.findings if "Log4j" in f.title)
    assert log4j.severity == Severity.CRITICAL
    assert log4j.cvss is not None
    assert log4j.cvss.score == 10.0
    assert "CVE-2021-44228" in log4j.cve
    assert "CWE-502" in log4j.cwe


def test_nuclei_host_with_port(nuclei_file, engagement):
    bundle = NucleiParser(engagement).parse(nuclei_file)
    addrs = {a.address for a in bundle.assets}
    assert "acme.example" in addrs
    asset = next(a for a in bundle.assets if a.address == "acme.example")
    assert {443, 8443, 80} <= {p.number for p in asset.ports}


def test_nuclei_evidence_and_references(nuclei_file, engagement):
    bundle = NucleiParser(engagement).parse(nuclei_file)
    git = next(f for f in bundle.findings if "Exposed .git" in f.title)
    assert git.severity == Severity.HIGH
    assert git.evidence and "/.git/config" in git.evidence
    assert "extracted" in git.evidence
    log4j = next(f for f in bundle.findings if "Log4j" in f.title)
    assert any("logging.apache.org" in r for r in log4j.references)


def test_nuclei_legacy_json_array(tmp_path, engagement):
    records = [
        {
            "template-id": "ssl-dns-names",
            "info": {"name": "SSL DNS Names", "severity": "info"},
            "host": "https://acme.example",
        }
    ]
    p = tmp_path / "legacy.json"
    p.write_text(json.dumps(records), encoding="utf-8")
    bundle = NucleiParser(engagement).parse(p)
    assert len(bundle.findings) == 1
    assert bundle.findings[0].severity == Severity.INFO


def test_nuclei_empty_file(tmp_path, engagement):
    p = tmp_path / "empty.jsonl"
    p.write_text("\n\n", encoding="utf-8")
    bundle = NucleiParser(engagement).parse(p)
    assert bundle.findings == []


def test_nuclei_bad_line_raises(tmp_path, engagement):
    p = tmp_path / "bad.jsonl"
    p.write_text('{"template-id":"ok","info":{"name":"x","severity":"low"},"host":"h"}\nnot-json\n', encoding="utf-8")
    try:
        NucleiParser(engagement).parse(p)
    except ValueError as e:
        assert "line 2" in str(e)
    else:
        raise AssertionError("expected ValueError on malformed JSONL")
