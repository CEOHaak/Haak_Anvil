"""Haak Anvil CLI — entry point for `haak-anvil` shell command."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from haak_anvil import __version__
from haak_anvil.core.engagement import Engagement
from haak_anvil.core.models import ReportBundle
from haak_anvil.enrichers import enrich_bundle
from haak_anvil.enrichers.cve import CveEnricher
from haak_anvil.parsers import BurpParser, NessusParser, NmapParser, NucleiParser
from haak_anvil.renderers import get_renderer

app = typer.Typer(
    name="haak-anvil",
    help="Modern multi-format pentest report generator. "
    "https://github.com/CEOHaak/Haak_Anvil",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

_BINARY_FORMATS = {"docx", "word"}

# Shared option annotations
EngagementOpt = Annotated[
    Path | None, typer.Option("--engagement", "-e", help="engagement.yaml path")
]
OutputOpt = Annotated[
    Path | None,
    typer.Option("--output", "-o", help="Output file (extension may set the format)"),
]
FormatOpt = Annotated[
    str, typer.Option("--format", "-f", help="json | md | html | docx")
]
EnrichOpt = Annotated[
    bool,
    typer.Option("--enrich", help="Enrich CVEs with NVD CVSS + EPSS (needs network)"),
]


def _load_engagement(path: Path | None) -> Engagement:
    if path is None:
        return Engagement(
            id="adhoc",
            client_name="Anonymous",
            scope="Ad-hoc parse",
            analyst="Haak Cybersecurity Consulting",
        )
    return Engagement.from_yaml(path)


def _print_summary(bundle: ReportBundle) -> None:
    t = Table(title=f"Report — {bundle.engagement.id}", show_header=True)
    t.add_column("Severity", style="bold")
    t.add_column("Count", justify="right")
    palette = {
        "critical": "red",
        "high": "orange1",
        "medium": "yellow",
        "low": "blue",
        "info": "white",
    }
    for sev, count in bundle.severity_breakdown.items():
        t.add_row(f"[{palette[sev]}]{sev.upper()}[/]", str(count))
    console.print(t)
    console.print(
        f"  [bold]Assets:[/] {len(bundle.assets)}   "
        f"[bold]Findings:[/] {len(bundle.findings)}"
    )


def _maybe_enrich(bundle: ReportBundle, enrich: bool) -> ReportBundle:
    if not enrich:
        return bundle
    api_key = os.environ.get("NVD_API_KEY")
    with console.status("[cyan]Enriching CVEs (NVD + EPSS)…"):
        bundle = asyncio.run(
            enrich_bundle(bundle, cve_enricher=CveEnricher(api_key=api_key))
        )
    scored = sum(1 for f in bundle.findings if f.epss_score is not None)
    console.print(f"[green]✓[/] Enriched — {scored} finding(s) got an EPSS score")
    return bundle


# --------------------------------------------------------------------- commands


@app.command()
def version() -> None:
    """Print Haak Anvil version."""
    console.print(f"haak-anvil {__version__}")


@app.command()
def init(
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Where to write engagement.yaml")
    ] = Path("engagement.yaml"),
    force: Annotated[bool, typer.Option("--force", help="Overwrite if it exists")] = False,
) -> None:
    """Scaffold an engagement.yaml template."""
    if output.exists() and not force:
        raise typer.BadParameter(f"{output} already exists (use --force to overwrite)")
    output.write_text(_ENGAGEMENT_TEMPLATE, encoding="utf-8")
    console.print(f"[green]✓[/] Wrote engagement template to {output}")
    console.print("  Edit it, then: [bold]haak-anvil nmap scan.xml -e " f"{output}[/]")


@app.command()
def nmap(
    input: Annotated[Path, typer.Argument(help="Nmap XML file (-oX output)")],
    engagement: EngagementOpt = None,
    output: OutputOpt = None,
    format: FormatOpt = "json",
    enrich: EnrichOpt = False,
) -> None:
    """Parse Nmap XML and render a report."""
    eng = _load_engagement(engagement)
    bundle = _maybe_enrich(NmapParser(eng).parse(input), enrich)
    _print_summary(bundle)
    _emit(bundle, format=format, output=output)


@app.command()
def nessus(
    input: Annotated[Path, typer.Argument(help=".nessus v2 file")],
    engagement: EngagementOpt = None,
    output: OutputOpt = None,
    format: FormatOpt = "json",
    enrich: EnrichOpt = False,
) -> None:
    """Parse Nessus .nessus v2 and render a report."""
    eng = _load_engagement(engagement)
    bundle = _maybe_enrich(NessusParser(eng).parse(input), enrich)
    _print_summary(bundle)
    _emit(bundle, format=format, output=output)


@app.command()
def burp(
    input: Annotated[Path, typer.Argument(help="Burp Suite XML export")],
    engagement: EngagementOpt = None,
    output: OutputOpt = None,
    format: FormatOpt = "json",
    enrich: EnrichOpt = False,
) -> None:
    """Parse a Burp Suite XML export and render a report."""
    eng = _load_engagement(engagement)
    bundle = _maybe_enrich(BurpParser(eng).parse(input), enrich)
    _print_summary(bundle)
    _emit(bundle, format=format, output=output)


@app.command()
def nuclei(
    input: Annotated[Path, typer.Argument(help="Nuclei JSONL (-jsonl) output")],
    engagement: EngagementOpt = None,
    output: OutputOpt = None,
    format: FormatOpt = "json",
    enrich: EnrichOpt = False,
) -> None:
    """Parse Nuclei JSONL output and render a report."""
    eng = _load_engagement(engagement)
    bundle = _maybe_enrich(NucleiParser(eng).parse(input), enrich)
    _print_summary(bundle)
    _emit(bundle, format=format, output=output)


@app.command()
def merge(
    inputs: Annotated[
        list[Path],
        typer.Argument(help="JSON bundles previously generated by haak-anvil"),
    ],
    engagement: EngagementOpt = None,
    output: OutputOpt = None,
    format: FormatOpt = "json",
    enrich: EnrichOpt = False,
) -> None:
    """Merge multiple haak-anvil JSON bundles into one report."""
    if len(inputs) < 2:
        raise typer.BadParameter("merge requires at least 2 input bundles")

    bundles = [ReportBundle.model_validate_json(p.read_text(encoding="utf-8")) for p in inputs]
    merged = bundles[0]
    for b in bundles[1:]:
        merged = merged.merge(b)
    if engagement is not None:
        merged = ReportBundle(
            engagement=_load_engagement(engagement),
            assets=merged.assets,
            findings=merged.findings,
        )
    merged = _maybe_enrich(merged, enrich)
    _print_summary(merged)
    _emit(merged, format=format, output=output)


# --------------------------------------------------------------------- helpers


def _emit(bundle: ReportBundle, *, format: str, output: Path | None) -> None:
    # An output extension overrides -f (so `-o report.docx` just works).
    if output is not None and output.suffix:
        format = output.suffix.lstrip(".").lower()
    renderer = get_renderer(format)()
    if format.lower() in _BINARY_FORMATS and output is None:
        raise typer.BadParameter(f"{format} is a binary format; pass --output/-o")
    if output is None:
        console.print(renderer.render(bundle))
        return
    written = renderer.write(bundle, output)
    console.print(f"[green]✓[/] Wrote {written}")


_ENGAGEMENT_TEMPLATE = """\
# Haak Anvil engagement descriptor
# Docs: https://github.com/CEOHaak/Haak_Anvil#readme
id: HK-2026-001
client:
  name: Acme Corp
  contact: ciso@acme.example
scope: "External perimeter + corporate WLAN"
# One of: PTES | OWASP | NIST-SP800-115 | MITRE-ATTACK | Custom
methodology: PTES
period:
  start: 2026-01-10
  end:   2026-01-20
analyst: Alan Contreras
# One of: es-MX | en-US | pt-BR
language: es-MX
"""


if __name__ == "__main__":
    app()
