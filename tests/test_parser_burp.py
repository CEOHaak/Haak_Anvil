import base64

from haak_anvil.core.severity import Severity
from haak_anvil.parsers import BurpParser


def test_burp_parses_assets(burp_file, engagement):
    bundle = BurpParser(engagement).parse(burp_file)
    # Two distinct host:port endpoints share one hostname → one asset, two ports
    addrs = {a.address for a in bundle.assets}
    assert addrs == {"acme.example"}
    asset = bundle.assets[0]
    port_numbers = {p.number for p in asset.ports}
    assert {443, 8443} <= port_numbers


def test_burp_extracts_findings(burp_file, engagement):
    bundle = BurpParser(engagement).parse(burp_file)
    titles = [f.title for f in bundle.findings]
    assert any("Cross-site scripting" in t for t in titles)
    assert any("Heartbleed" in t for t in titles)
    assert len(bundle.findings) == 3


def test_burp_severity_mapping(burp_file, engagement):
    bundle = BurpParser(engagement).parse(burp_file)
    xss = next(f for f in bundle.findings if "Cross-site" in f.title)
    assert xss.severity == Severity.HIGH
    info = next(f for f in bundle.findings if "Information disclosure" in f.title)
    assert info.severity == Severity.INFO


def test_burp_extracts_cve_cwe(burp_file, engagement):
    bundle = BurpParser(engagement).parse(burp_file)
    tls = next(f for f in bundle.findings if "Heartbleed" in f.title)
    assert "CVE-2014-0160" in tls.cve
    assert "CWE-125" in tls.cwe
    xss = next(f for f in bundle.findings if "Cross-site" in f.title)
    assert "CWE-79" in xss.cwe


def test_burp_cvss_from_vector(burp_file, engagement):
    bundle = BurpParser(engagement).parse(burp_file)
    tls = next(f for f in bundle.findings if "Heartbleed" in f.title)
    assert tls.cvss is not None
    assert tls.cvss.vector is not None and tls.cvss.vector.startswith("CVSS:3.1")
    # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 (HIGH), overriding Burp's "Medium"
    assert tls.cvss.score == 7.5
    assert tls.severity == Severity.HIGH


def test_burp_html_tags_stripped(burp_file, engagement):
    bundle = BurpParser(engagement).parse(burp_file)
    xss = next(f for f in bundle.findings if "Cross-site" in f.title)
    assert "<p>" not in xss.description
    assert "reflected cross-site scripting" in xss.description.lower()


def test_burp_extracts_reference_links(burp_file, engagement):
    bundle = BurpParser(engagement).parse(burp_file)
    xss = next(f for f in bundle.findings if "Cross-site" in f.title)
    assert any("portswigger.net" in r for r in xss.references)


def test_burp_base64_decoding_roundtrip():
    plain = "<p>secret detail with CVE-2020-0601</p>"
    encoded = base64.b64encode(plain.encode()).decode()
    assert BurpParser._maybe_b64(encoded) == plain
    # A plain HTML blob is left untouched (not valid base64)
    assert BurpParser._maybe_b64("<p>hello world</p>") == "<p>hello world</p>"


def test_burp_rejects_wrong_root(tmp_path, engagement):
    bad = tmp_path / "bad.xml"
    bad.write_text("<notissues></notissues>", encoding="utf-8")
    try:
        BurpParser(engagement).parse(bad)
    except ValueError as e:
        assert "Burp" in str(e)
    else:
        raise AssertionError("expected ValueError for non-Burp XML")
