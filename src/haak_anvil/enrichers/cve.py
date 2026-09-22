"""CVE enrichment via the NVD 2.0 API.

Fetches CVSS v3.1 (falling back to v3.0, then v2) base scores and vectors for
each CVE referenced by a report, caches them locally, and fills in the CVSS on
findings that lack one. Combined with EPSS scoring in
:func:`haak_anvil.enrichers.enrich_bundle`.

NVD rate-limits anonymous callers to ~5 requests / 30s; an API key raises this
to ~50 / 30s. Pass one via ``api_key`` (env ``NVD_API_KEY``). This client keeps
things simple and sequential — enrichment is a convenience, not a hot path.
"""

from __future__ import annotations

import httpx

from haak_anvil.core.severity import CVSS
from haak_anvil.enrichers.cache import JsonCache

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CveRecord:
    """Normalized subset of an NVD CVE we care about for reports."""

    __slots__ = ("cve", "cvss", "cwe", "description")

    def __init__(
        self,
        cve: str,
        cvss: CVSS | None,
        cwe: list[str],
        description: str | None,
    ) -> None:
        self.cve = cve
        self.cvss = cvss
        self.cwe = cwe
        self.description = description


class CveEnricher:
    """Fetch NVD data for CVEs, with a local TTL cache."""

    def __init__(
        self,
        *,
        cache: JsonCache | None = None,
        timeout: float = 20.0,
        api_key: str | None = None,
    ) -> None:
        self.cache = cache if cache is not None else JsonCache("nvd", ttl_seconds=30 * 24 * 3600)
        self.timeout = timeout
        self.api_key = api_key

    async def fetch(
        self, cves: list[str], *, client: httpx.AsyncClient | None = None
    ) -> dict[str, CveRecord]:
        """Return {CVE: CveRecord} for CVEs resolvable via NVD (or cache)."""
        want = sorted({c.upper() for c in cves if c})
        out: dict[str, CveRecord] = {}
        missing: list[str] = []
        for cve in want:
            cached = self.cache.get(cve)
            if cached is not None:
                out[cve] = self._record_from_cache(cve, cached)
            else:
                missing.append(cve)

        if not missing:
            return out

        owns_client = client is None
        client = client or httpx.AsyncClient(timeout=self.timeout)
        try:
            for cve in missing:
                raw = await self._fetch_cve(cve, client=client)
                if raw is None:
                    continue
                record = self._parse_vuln(cve, raw)
                out[cve] = record
                self.cache.set(cve, self._record_to_cache(record))
        finally:
            if owns_client:
                await client.aclose()
        return out

    # ------------------------------------------------------------------ network

    async def _fetch_cve(self, cve_id: str, *, client: httpx.AsyncClient) -> dict | None:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        try:
            r = await client.get(NVD_API, params={"cveId": cve_id}, headers=headers)
            r.raise_for_status()
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            return vulns[0] if vulns else None
        except (httpx.HTTPError, ValueError):
            return None

    # ------------------------------------------------------------------ parsing

    @staticmethod
    def _parse_vuln(cve_id: str, vuln: dict) -> CveRecord:
        cve_obj = vuln.get("cve", {}) if isinstance(vuln, dict) else {}
        metrics = cve_obj.get("metrics", {}) or {}

        cvss: CVSS | None = None
        for key, version in (
            ("cvssMetricV31", "3.1"),
            ("cvssMetricV30", "3.0"),
            ("cvssMetricV2", "2.0"),
        ):
            entries = metrics.get(key) or []
            if entries:
                data = entries[0].get("cvssData", {})
                try:
                    cvss = CVSS(
                        score=float(data.get("baseScore")),
                        vector=data.get("vectorString"),
                        version=version,
                    )
                except (TypeError, ValueError):
                    cvss = None
                if cvss is not None:
                    break

        cwe: list[str] = []
        for weakness in cve_obj.get("weaknesses", []) or []:
            for desc in weakness.get("description", []) or []:
                val = desc.get("value", "")
                if val.upper().startswith("CWE-"):
                    cwe.append(val.upper())

        description = None
        for d in cve_obj.get("descriptions", []) or []:
            if d.get("lang") == "en":
                description = d.get("value")
                break

        return CveRecord(cve_id, cvss, sorted(set(cwe)), description)

    # ------------------------------------------------------------------ cache glue

    @staticmethod
    def _record_to_cache(rec: CveRecord) -> dict:
        return {
            "cvss": None
            if rec.cvss is None
            else {"score": rec.cvss.score, "vector": rec.cvss.vector, "version": rec.cvss.version},
            "cwe": rec.cwe,
            "description": rec.description,
        }

    @staticmethod
    def _record_from_cache(cve: str, cached: dict) -> CveRecord:
        cvss = None
        if cached.get("cvss"):
            c = cached["cvss"]
            cvss = CVSS(score=c["score"], vector=c.get("vector"), version=c.get("version", "3.1"))
        return CveRecord(cve, cvss, list(cached.get("cwe") or []), cached.get("description"))
