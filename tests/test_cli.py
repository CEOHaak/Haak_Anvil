from typer.testing import CliRunner

from haak_anvil.cli import app
from haak_anvil.core.engagement import Engagement

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "haak-anvil" in result.stdout


def test_init_writes_valid_engagement(tmp_path):
    target = tmp_path / "engagement.yaml"
    result = runner.invoke(app, ["init", "-o", str(target)])
    assert result.exit_code == 0
    assert target.exists()
    # The scaffold must round-trip through the loader
    eng = Engagement.from_yaml(target)
    assert eng.id == "HK-2026-001"
    assert eng.client_name == "Acme Corp"
    assert eng.methodology == "PTES"


def test_init_refuses_overwrite(tmp_path):
    target = tmp_path / "engagement.yaml"
    target.write_text("id: X\nclient_name: Y\nscope: s\n", encoding="utf-8")
    result = runner.invoke(app, ["init", "-o", str(target)])
    assert result.exit_code != 0


def test_burp_cli_json_output(tmp_path, burp_file):
    out = tmp_path / "burp.json"
    result = runner.invoke(app, ["burp", str(burp_file), "-o", str(out)])
    assert result.exit_code == 0, result.stdout
    assert out.exists()
    assert '"tool": "burp"' in out.read_text(encoding="utf-8")


def test_nuclei_cli_summary(tmp_path, nuclei_file):
    result = runner.invoke(app, ["nuclei", str(nuclei_file)])
    assert result.exit_code == 0
    assert "CRITICAL" in result.stdout


def test_docx_without_output_errors(tmp_path, nuclei_file):
    result = runner.invoke(app, ["nuclei", str(nuclei_file), "-f", "docx"])
    assert result.exit_code != 0


def test_output_extension_overrides_format(tmp_path, burp_file):
    out = tmp_path / "report.md"
    # -f json but .md extension → markdown wins
    result = runner.invoke(app, ["burp", str(burp_file), "-f", "json", "-o", str(out)])
    assert result.exit_code == 0
    content = out.read_text(encoding="utf-8")
    assert content.lstrip().startswith("#")  # markdown heading, not JSON
