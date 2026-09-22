"""Nessus .nessus (v2) XML output parser.

Supports the modern Nessus Pro/Expert .nessus v2 format. CVSS v3 base score
is preferred over v2 when both are present.
"""

from __future__ import annotations

import contextlib
import re
from pathlib import Path

from defusedxml import ElementTree as ET  # noqa: N817

from haak_anvil.core.models import Asset, Finding, Port, ReportBundle, Service
from haak_anvil.core.severity import CVSS, severity_from_cvss, severity_from_nessus
from haak_anvil.parsers.base import ParserBase

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


class NessusParser(ParserBase):
    """Parse a `.nessus` v2 export into a ReportBundle."""

    tool_name = "nessus"

    def parse(self, path: Path) -> ReportBundle:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(path)

        tree = ET.parse(str(path))
        root = tree.getroot()
        if root.tag != "NessusClientData_v2":
            raise ValueError(f"Not a Nessus v2 export (root={root.tag!r})")

        assets: list[Asset] = []
        findings: list[Finding] = []

        for report in root.findall("Report"):
            for host in report.findall("ReportHost"):
                asset, host_findings = self._parse_host(host)
                if asset is not None:
                    assets.append(asset)
                findings.extend(host_findings)

        return ReportBundle(
            engagement=self.engagement,
            assets=assets,
            findings=findings,
        )

    # ------------------------------------------------------------------ helpers

    def _parse_host(self, host: ET.Element) -> tuple[Asset | None, list[Finding]]:
        host_name = host.attrib.get("name", "unknown")
        props = {
            tag.attrib.get("name", ""): (tag.text or "")
            for tag in host.findall("HostProperties/tag")
        }
        ip = props.get("host-ip") or host_name
        hostname = props.get("host-fqdn") or props.get("hostname")
        os_name = props.get("operating-system")

        # Build asset with placeholder for ports (filled while iterating findings)
        port_seen: dict[tuple[int, str], Port] = {}
        findings: list[Finding] = []

        for item in host.findall("ReportItem"):
            try:
                port_num = int(item.attrib.get("port", "0"))
            except ValueError:
                port_num = 0
            protocol = item.attrib.get("protocol", "tcp")
            svc_name = item.attrib.get("svc_name") or None
            plugin_id = item.attrib.get("pluginID")
            plugin_family = item.attrib.get("pluginFamily")
            plugin_name = item.attrib.get("pluginName", "Unnamed")

            # Track open ports
            if port_num > 0 and (port_num, protocol) not in port_seen:
                port_seen[(port_num, protocol)] = Port(
                    number=port_num,
                    protocol=protocol,  # type: ignore[arg-type]
                    state="open",
                    service=Service(name=svc_name) if svc_name else None,
                )

            # Build finding
            risk_factor = self._text(item, "risk_factor", default="None")
            severity = severity_from_nessus(risk_factor)

            # Prefer CVSS v3 base, fall back to v2
            cvss_obj: CVSS | None = None
            v3_score = self._text(item, "cvss3_base_score")
            v2_score = self._text(item, "cvss_base_score")
            if v3_score:
                try:
                    cvss_obj = CVSS(
                        score=float(v3_score),
                        vector=self._text(item, "cvss3_vector") or None,
                        version="3.1",
                    )
                    severity = severity_from_cvss(cvss_obj.score)
                except ValueError:
                    pass
            elif v2_score:
                with contextlib.suppress(ValueError):
                    cvss_obj = CVSS(
                        score=float(v2_score),
                        vector=self._text(item, "cvss_vector") or None,
                        version="2.0",
                    )

            description = self._text(item, "description") or ""
            solution = self._text(item, "solution") or None
            see_also = self._text(item, "see_also") or ""
            references = [r.strip() for r in see_also.splitlines() if r.strip()]

            # Pull CVE/CWE from cve/cwe tags AND from free text
            cve_tags = [c.text for c in item.findall("cve") if c.text]
            cwe_tags = [c.text for c in item.findall("cwe") if c.text]
            haystack = f"{description}\n{see_also}\n{self._text(item, 'plugin_output')}"
            cve_set = {x.upper() for x in cve_tags} | {m.upper() for m in _CVE_RE.findall(haystack)}
            cwe_set = {x.upper() for x in cwe_tags} | {m.upper() for m in _CWE_RE.findall(haystack)}

            finding_id = f"nessus-{plugin_id or 'noid'}-{ip}-{protocol}-{port_num}"
            findings.append(
                Finding(
                    id=finding_id,
                    title=plugin_name,
                    severity=severity,
                    cvss=cvss_obj,
                    description=description,
                    impact=self._text(item, "synopsis") or None,
                    remediation=solution,
                    references=references,
                    cve=sorted(cve_set),
                    cwe=sorted(cwe_set),
                    asset=hostname or ip,
                    port=port_num or None,
                    protocol=protocol,
                    evidence=self._text(item, "plugin_output") or None,
                    plugin_id=plugin_id,
                    plugin_family=plugin_family,
                    tool="nessus",
                )
            )

        asset = Asset(
            address=ip,
            hostname=hostname,
            os=os_name,
            ports=list(port_seen.values()),
        )
        return asset, findings

    @staticmethod
    def _text(elem: ET.Element, tag: str, default: str = "") -> str:
        child = elem.find(tag)
        if child is None or child.text is None:
            return default
        return child.text.strip()
