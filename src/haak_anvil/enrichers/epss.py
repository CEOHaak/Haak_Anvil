"""EPSS scoring via FIRST.org.

EPSS (Exploit Prediction Scoring System) estimates the probability a CVE will
be exploited in the wild in the next 30 days. We fetch scores from the public
FIRST.org API (batched, up to ~100 CVEs per request) and cache them locally.

API: https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2020-0601
"""

from __future__ import annotations

import httpx

from haak_anvil.enrichers.cache import JsonCache

EPSS_API = "https://api.first.org/data/v1/epss"
_BATCH = 100


class EpssScore:
    """A single CVE's EPSS score/percentile (both in 0..1)."""

    __slots__ = ("cve", "percentile", "score")

    def __init__(self, cve: str, score: float, percentile: float) -> None:
        self.cve = cve
        self.score = score
        self.percentile = percentile


class EpssClient:
    """Fetch EPSS scores for CVEs, with a local TTL cache."""

    def __init__(
        self,
        *,
        cache: JsonCache | None = None,
        timeout: float = 15.0,
    ) -> None:
        self.cache = cache if cache is not None else JsonCache("epss", ttl_seconds=3 * 24 * 3600)
        self.timeout = timeout

    async def fetch(
        self, cves: list[str], *, client: httpx.AsyncClient | None = None
    ) -> dict[str, EpssScore]:
        """Return {CVE: EpssScore} for the CVEs that have a score.

        Cache hits are served without any network call; only the missing CVEs
        are requested, in batches.
        """
        want = sorted({c.upper() for c in cves if c})
        out: dict[str, EpssScore] = {}
        missing: list[str] = []
        for cve in want:
            cached = self.cache.get(cve)
            if cached is not None:
                out[cve] = EpssScore(cve, cached["score"], cached["percentile"])
            else:
                missing.append(cve)

        if not missing:
            return out

        owns_client = client is None
        client = client or httpx.AsyncClient(timeout=self.timeout)
        try:
            for start in range(0, len(missing), _BATCH):
                batch = missing[start : start + _BATCH]
                for score in await self._fetch_batch(batch, client=client):
                    out[score.cve] = score
                    self.cache.set(score.cve, {"score": score.score, "percentile": score.percentile})
        finally:
            if owns_client:
                await client.aclose()
        return out

    async def _fetch_batch(
        self, batch: list[str], *, client: httpx.AsyncClient
    ) -> list[EpssScore]:
        try:
            resp = await client.get(EPSS_API, params={"cve": ",".join(batch)})
            resp.raise_for_status()
            payload = resp.json()
        except (httpx.HTTPError, ValueError):
            return []
        results: list[EpssScore] = []
        for row in payload.get("data", []):
            cve = str(row.get("cve", "")).upper()
            try:
                score = float(row.get("epss"))
                percentile = float(row.get("percentile"))
            except (TypeError, ValueError):
                continue
            if cve:
                results.append(EpssScore(cve, score, percentile))
        return results
