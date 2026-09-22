"""Core data models for assets, ports, services, findings."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

from haak_anvil.core.engagement import Engagement
from haak_anvil.core.severity import CVSS, Severity


class Service(BaseModel):
    """A service detected on a port (banner/version)."""

    name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    cpe: str | None = None


class Port(BaseModel):
    """One open port on an asset."""

    number: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp", "sctp"] = "tcp"
    state: Literal["open", "filtered", "open|filtered", "closed"] = "open"
    service: Service | None = None
    reason: str | None = None


class Asset(BaseModel):
    """A host/IP/URL discovered or attacked during the engagement."""

    address: str
    hostname: str | None = None
    os: str | None = None
    ports: list[Port] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @property
    def open_port_count(self) -> int:
        return sum(1 for p in self.ports if p.state == "open")


class Finding(BaseModel):
    """A single vulnerability/finding to be reported.

    Unified shape regardless of source tool. Parsers normalize into this.
    """

    id: str = Field(description="Unique within report, stable across runs")
    title: str
    severity: Severity
    cvss: CVSS | None = None
    description: str = ""
    impact: str | None = None
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    asset: str | None = Field(default=None, description="address or hostname")
    port: int | None = None
    protocol: str | None = None
    evidence: str | None = None
    plugin_id: str | None = Field(default=None, description="Source tool's native ID")
    plugin_family: str | None = None
    tool: str = Field(description="nmap | nessus | burp | nuclei | zap | manual | ...")
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # ----- enrichment (populated by enrichers; empty until `--enrich`) -----
    epss_score: float | None = Field(
        default=None, ge=0.0, le=1.0,
        description="EPSS probability (0-1) of exploitation in the next 30 days",
    )
    epss_percentile: float | None = Field(
        default=None, ge=0.0, le=1.0,
        description="EPSS percentile rank vs all scored CVEs",
    )
    enriched: bool = Field(
        default=False, description="True once an enricher has processed this finding"
    )


class ReportBundle(BaseModel):
    """The full report dataset — engagement + assets + findings, what renderers consume."""

    engagement: Engagement
    assets: list[Asset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    generator: str = "haak-anvil"
    generator_version: str = "0.2.0"

    # ----- aggregation helpers -----

    @property
    def severity_breakdown(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    @property
    def critical_count(self) -> int:
        return self.severity_breakdown[Severity.CRITICAL.value]

    @property
    def high_count(self) -> int:
        return self.severity_breakdown[Severity.HIGH.value]

    @property
    def unique_cves(self) -> list[str]:
        """All distinct CVE IDs across findings, sorted (newest-looking last is fine)."""
        seen: set[str] = set()
        for f in self.findings:
            seen.update(c.upper() for c in f.cve)
        return sorted(seen)

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def findings_by_epss(self) -> list[Finding]:
        """Findings sorted by EPSS score descending; unscored (None) sink to the bottom."""
        return sorted(
            self.findings,
            key=lambda f: (f.epss_score if f.epss_score is not None else -1.0),
            reverse=True,
        )

    def findings_sorted(self) -> list[Finding]:
        """Critical first, info last, stable by id within tier."""
        return sorted(
            self.findings,
            key=lambda f: (-f.severity.numeric, f.id),
        )

    def merge(self, other: ReportBundle) -> ReportBundle:
        """Combine two bundles (e.g., results from multiple tools on same engagement)."""
        if self.engagement.id != other.engagement.id:
            raise ValueError(
                f"Cannot merge: engagement IDs differ "
                f"({self.engagement.id} vs {other.engagement.id})"
            )
        # Dedupe assets by address
        by_addr: dict[str, Asset] = {a.address: a for a in self.assets}
        for a in other.assets:
            if a.address in by_addr:
                # Merge port lists
                seen = {(p.number, p.protocol) for p in by_addr[a.address].ports}
                for p in a.ports:
                    if (p.number, p.protocol) not in seen:
                        by_addr[a.address].ports.append(p)
            else:
                by_addr[a.address] = a
        return ReportBundle(
            engagement=self.engagement,
            assets=list(by_addr.values()),
            findings=self.findings + other.findings,
        )
