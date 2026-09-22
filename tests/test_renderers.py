import json

from haak_anvil.parsers import NessusParser, NmapParser
from haak_anvil.renderers import HtmlRenderer, JsonRenderer, MarkdownRenderer, get_renderer


def test_get_renderer_factory():
    assert get_renderer("json") is JsonRenderer
    assert get_renderer("md") is MarkdownRenderer
    assert get_renderer("markdown") is MarkdownRenderer
    assert get_renderer("html") is HtmlRenderer


def test_get_renderer_unknown_raises():
    import pytest as _pt

    with _pt.raises(ValueError):
        get_renderer("bogus-format")


def test_json_renders_valid_json(nmap_xml, engagement):
    bundle = NmapParser(engagement).parse(nmap_xml)
    out = JsonRenderer().render(bundle)
    data = json.loads(out)
    assert data["engagement"]["id"] == "TEST-2026-001"
    assert len(data["assets"]) == 2
    assert len(data["findings"]) == 4


def test_markdown_renders_with_severity_section(nessus_file, engagement):
    bundle = NessusParser(engagement).parse(nessus_file)
    out = MarkdownRenderer().render(bundle)
    assert "Pentest Report" in out
    assert "CRITICAL" in out
    assert "OpenSSH" in out


def test_html_renders_with_template(nessus_file, engagement):
    bundle = NessusParser(engagement).parse(nessus_file)
    out = HtmlRenderer().render(bundle)
    assert "<!doctype html>" in out
    assert "Acme Test Corp" in out
    assert "OpenSSH" in out
    assert "haak.com.mx" in out


def test_write_creates_file(nmap_xml, engagement, tmp_path):
    bundle = NmapParser(engagement).parse(nmap_xml)
    p = JsonRenderer().write(bundle, tmp_path / "out.json")
    assert p.exists()
    assert json.loads(p.read_text(encoding="utf-8"))["assets"]
