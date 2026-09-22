"""Nuclei JSONL output parser.

Parses the output of ``nuclei -jsonl`` (one JSON object per line). Also
tolerates ``nuclei -json`` legacy output that emits a single JSON array.
Each result becomes a :class:`Finding`; each distinct host becomes an
:class:`Asset`.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from haak_anvil.core.models import Asset, Finding, Port, ReportBundle, Service
from haak_anvil.core.severity import CVSS, Severity, severity_from_cvss
from haak_anvil.parsers.base import ParserBase

_NUCLEI_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


class NucleiParser(ParserBase):
    """Parse Nuclei JSONL (or legacy JSON array) into a ReportBundle."""

    tool_name = "nuclei"

    def parse(self, path: Path) -> ReportBundle:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(path)

        records = self._load_records(path)

        assets_by_addr: dict[str, Asset] = {}
        findings: list[Finding] = []

        for idx, rec in enumerate(records):
            finding, address, port_obj = self._parse_record(rec, idx)
            if finding is None:
                continue
            findings.append(finding)
            if address:
                asset = assets_by_addr.get(address)
                if asset is None:
                    asset = Asset(address=address)
                    assets_by_addr[address] = asset
                if port_obj is not None and not any(
                    p.number == port_obj.number and p.protocol == port_obj.protocol
                    for p in asset.ports
                ):
                    asset.ports.append(port_obj)

        return ReportBundle(
            engagement=self.engagement,
            assets=list(assets_by_addr.values()),
            findings=findings,
        )

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _load_records(path: Path) -> list[dict]:
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            return []
        # Legacy `-json`: a single JSON array.
        if text[0] == "[":
            data = json.loads(text)
            if not isinstance(data, list):
                raise ValueError("Nuclei JSON root is not a list")
            return [r for r in data if isinstance(r, dict)]
        # `-jsonl`: one object per line.
        records: list[dict] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_no}: {exc}") from exc
            if isinstance(obj, dict):
                records.append(obj)
        return records

    def _parse_record(self, rec: dict, idx: int) -> tuple[Finding | None, str | None, Port | None]:
        info = rec.get("info") or {}
        if not isinstance(info, dict):
            info = {}

        template_id = rec.get("template-id") or rec.get("templateID") or f"nuclei-{idx}"
        name = info.get("name") or template_id
        severity = _NUCLEI_SEVERITY.get(str(info.get("severity", "info")).lower(), Severity.INFO)

        host = rec.get("host") or rec.get("matched-at") or rec.get("matched") or ""
        matched_at = rec.get("matched-at") or rec.get("matched") or host
        ip = rec.get("ip") or ""

        address, port_obj = self._host_to_asset(host, ip, rec.get("type"))

        classification = info.get("classification") or {}
        if not isinstance(classification, dict):
            classification = {}
        cve = sorted({str(c).upper() for c in (classification.get("cve-id") or []) if c})
        cwe = sorted({str(c).upper() for c in (classification.get("cwe-id") or []) if c})

        cvss_obj: CVSS | None = None
        cvss_score = classification.get("cvss-score")
        cvss_metrics = classification.get("cvss-metrics")
        if isinstance(cvss_score, (int, float)) and 0.0 <= float(cvss_score) <= 10.0:
            cvss_obj = CVSS(
                score=float(cvss_score),
                vector=cvss_metrics if isinstance(cvss_metrics, str) else None,
                version="3.1",
            )
            severity = severity_from_cvss(float(cvss_score))

        references = [str(r) for r in (info.get("reference") or []) if r]
        description = str(info.get("description") or "").strip() or name
        remediation = str(info.get("remediation") or "").strip() or None

        extracted = rec.get("extracted-results") or rec.get("extracted_results") or []
        evidence_parts = []
        if isinstance(matched_at, str) and matched_at:
            evidence_parts.append(matched_at)
        if isinstance(extracted, list) and extracted:
            evidence_parts.append("extracted: " + ", ".join(str(e) for e in extracted))
        matcher = rec.get("matcher-name")
        if matcher:
            evidence_parts.append(f"matcher: {matcher}")
        evidence = "\n".join(evidence_parts) or None

        tags = info.get("tags")
        plugin_family = tags[0] if isinstance(tags, list) and tags else (tags if isinstance(tags, str) else "nuclei")

        finding = Finding(
            id=f"nuclei-{template_id}-{address or 'host'}-{idx}",
            title=name,
            severity=severity,
            cvss=cvss_obj,
            description=description,
            impact=str(info.get("impact") or "").strip() or None,
            remediation=remediation,
            references=references,
            cve=cve,
            cwe=cwe,
            asset=address,
            port=port_obj.number if port_obj else None,
            protocol="tcp" if port_obj else None,
            evidence=evidence,
            plugin_id=template_id,
            plugin_family=plugin_family,
            tool="nuclei",
        )
        return finding, address, port_obj

    @staticmethod
    def _host_to_asset(host: str, ip: str, rec_type: str | None) -> tuple[str | None, Port | None]:
        if not host:
            return (ip or None), None
        # host may be a bare host, host:port, or a full URL.
        if "://" in host:
            split = urlsplit(host)
            address = split.hostname or host
            scheme = split.scheme or "http"
            port_num = split.port or (443 if scheme == "https" else 80)
            return address, Port(number=port_num, protocol="tcp", state="open", service=Service(name=scheme))
        if ":" in host and host.rsplit(":", 1)[-1].isdigit():
            address, port_s = host.rsplit(":", 1)
            return address, Port(number=int(port_s), protocol="tcp", state="open")
        return host, None
