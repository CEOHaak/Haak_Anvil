"""Enrichers — augment findings with external intel (NVD CVSS + EPSS).

Public entry point is :func:`enrich_bundle`, which annotates a ReportBundle
in place-ish (returns the same bundle) with:
  - CVSS pulled from NVD for findings that lack one (severity recomputed)
  - EPSS score + percentile (max across each finding's CVEs)
  - ``enriched=True`` on every finding that was processed
"""

from __future__ import annotations

import httpx

from haak_anvil.core.models import ReportBundle
from haak_anvil.core.severity import severity_from_cvss
from haak_anvil.enrichers.cve import CveEnricher, CveRecord
from haak_anvil.enrichers.epss import EpssClient, EpssScore

__all__ = ["CveEnricher", "EpssClient", "enrich_bundle"]


async def enrich_bundle(
    bundle: ReportBundle,
    *,
    cve_enricher: CveEnricher | None = None,
    epss_client: EpssClient | None = None,
    client: httpx.AsyncClient | None = None,
    do_cve: bool = True,
    do_epss: bool = True,
) -> ReportBundle:
    """Enrich every finding's CVEs with NVD CVSS + EPSS, in place."""
    cves = bundle.unique_cves
    if not cves:
        for f in bundle.findings:
            f.enriched = True
        return bundle

    cve_enricher = cve_enricher or CveEnricher()
    epss_client = epss_client or EpssClient()

    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=20.0)
    try:
        cve_data: dict[str, CveRecord] = (
            await cve_enricher.fetch(cves, client=client) if do_cve else {}
        )
        epss_data: dict[str, EpssScore] = (
            await epss_client.fetch(cves, client=client) if do_epss else {}
        )
    finally:
        if owns_client:
            await client.aclose()

    for f in bundle.findings:
        f_cves = [c.upper() for c in f.cve]

        # Fill CVSS from NVD if the finding has none.
        if f.cvss is None and do_cve:
            for c in f_cves:
                rec = cve_data.get(c)
                if rec is not None and rec.cvss is not None:
                    f.cvss = rec.cvss
                    f.severity = severity_from_cvss(rec.cvss.score)
                    break

        # Backfill CWE from NVD when the tool didn't provide any.
        if not f.cwe and do_cve:
            merged: set[str] = set()
            for c in f_cves:
                rec = cve_data.get(c)
                if rec is not None:
                    merged.update(rec.cwe)
            if merged:
                f.cwe = sorted(merged)

        # EPSS: take the worst (max) across the finding's CVEs.
        if do_epss:
            best: EpssScore | None = None
            for c in f_cves:
                score = epss_data.get(c)
                if score is not None and (best is None or score.score > best.score):
                    best = score
            if best is not None:
                f.epss_score = best.score
                f.epss_percentile = best.percentile

        f.enriched = True

    return bundle
