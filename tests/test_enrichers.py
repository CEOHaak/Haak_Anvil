import asyncio

import httpx

from haak_anvil.core.models import Finding, ReportBundle
from haak_anvil.core.severity import Severity
from haak_anvil.enrichers import enrich_bundle
from haak_anvil.enrichers.cache import JsonCache
from haak_anvil.enrichers.cve import CveEnricher
from haak_anvil.enrichers.epss import EpssClient

_NVD_LOG4J = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 10.0,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            }
                        }
                    ]
                },
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-502"}]}
                ],
                "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI RCE"}],
            }
        }
    ]
}


def _handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    if "nvd.nist.gov" in host:
        cve = request.url.params.get("cveId")
        if cve == "CVE-2021-44228":
            return httpx.Response(200, json=_NVD_LOG4J)
        return httpx.Response(200, json={"vulnerabilities": []})
    if "first.org" in host:
        requested = (request.url.params.get("cve") or "").split(",")
        data = []
        if "CVE-2021-44228" in requested:
            data.append({"cve": "CVE-2021-44228", "epss": "0.97540", "percentile": "0.99990"})
        return httpx.Response(200, json={"status": "OK", "data": data})
    return httpx.Response(404)


def _bundle(engagement) -> ReportBundle:
    return ReportBundle(
        engagement=engagement,
        findings=[
            Finding(
                id="f-log4j",
                title="Log4Shell",
                severity=Severity.INFO,  # deliberately wrong; enrichment should fix
                cve=["CVE-2021-44228"],
                tool="nuclei",
            ),
            Finding(id="f-nocve", title="No CVE finding", severity=Severity.LOW, tool="manual"),
        ],
    )


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(_handler))


def test_enrich_fills_cvss_and_epss(tmp_path, engagement):
    bundle = _bundle(engagement)
    cve_enricher = CveEnricher(cache=JsonCache("nvd", root=tmp_path))
    epss_client = EpssClient(cache=JsonCache("epss", root=tmp_path))

    async def run():
        async with _client() as client:
            return await enrich_bundle(
                bundle, cve_enricher=cve_enricher, epss_client=epss_client, client=client
            )

    out = asyncio.run(run())
    log4j = next(f for f in out.findings if f.id == "f-log4j")
    assert log4j.cvss is not None and log4j.cvss.score == 10.0
    assert log4j.severity == Severity.CRITICAL  # recomputed from CVSS
    assert log4j.epss_score == 0.9754
    assert log4j.epss_percentile == 0.9999
    assert "CWE-502" in log4j.cwe  # backfilled from NVD
    assert log4j.enriched is True

    nocve = next(f for f in out.findings if f.id == "f-nocve")
    assert nocve.enriched is True
    assert nocve.epss_score is None


def test_enrich_no_cves_marks_enriched(engagement):
    bundle = ReportBundle(
        engagement=engagement,
        findings=[Finding(id="x", title="t", severity=Severity.LOW, tool="manual")],
    )
    out = asyncio.run(enrich_bundle(bundle, do_cve=False, do_epss=False))
    assert all(f.enriched for f in out.findings)


def test_epss_uses_cache_without_network(tmp_path):
    cache = JsonCache("epss", root=tmp_path)
    client = EpssClient(cache=cache)

    async def first():
        async with _client() as c:
            return await client.fetch(["CVE-2021-44228"], client=c)

    scores = asyncio.run(first())
    assert scores["CVE-2021-44228"].score == 0.9754

    # Second call with a transport that would 404 everything → served from cache
    def deny(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    async def second():
        async with httpx.AsyncClient(transport=httpx.MockTransport(deny)) as c:
            return await client.fetch(["CVE-2021-44228"], client=c)

    cached = asyncio.run(second())
    assert cached["CVE-2021-44228"].percentile == 0.9999


def test_cache_ttl_expiry(tmp_path):
    cache = JsonCache("t", root=tmp_path, ttl_seconds=-1)  # everything is stale
    cache.set("k", {"v": 1})
    assert cache.get("k") is None
    fresh = JsonCache("t2", root=tmp_path, ttl_seconds=3600)
    fresh.set("k", {"v": 2})
    assert fresh.get("k") == {"v": 2}
    assert fresh.get("missing") is None


def test_cve_enricher_handles_missing_cve(tmp_path, engagement):
    enricher = CveEnricher(cache=JsonCache("nvd", root=tmp_path))

    async def run():
        async with _client() as client:
            return await enricher.fetch(["CVE-1999-0001"], client=client)

    out = asyncio.run(run())
    assert out == {}
