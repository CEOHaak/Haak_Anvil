"""Nmap XML output parser.

Tested against Nmap 7.94+ XML format. Uses defusedxml for safe parsing.
"""

from __future__ import annotations

from pathlib import Path

from defusedxml import ElementTree as ET  # noqa: N817

from haak_anvil.core.models import Asset, Finding, Port, ReportBundle, Service
from haak_anvil.core.severity import Severity
from haak_anvil.parsers.base import ParserBase


class NmapParser(ParserBase):
    """Parse `nmap -oX output.xml` into a ReportBundle.

    Findings emitted:
      - One INFO finding per open port (so reports always show what was found)
      - Higher-severity findings can be promoted by enrichers downstream
    """

    tool_name = "nmap"

    def parse(self, path: Path) -> ReportBundle:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(path)

        tree = ET.parse(str(path))
        root = tree.getroot()
        if root.tag != "nmaprun":
            raise ValueError(f"Not an nmap XML (root={root.tag!r})")

        assets: list[Asset] = []
        findings: list[Finding] = []

        for host in root.findall("host"):
            asset = self._parse_host(host)
            if asset is None:
                continue
            assets.append(asset)
            findings.extend(self._findings_for_asset(asset))

        return ReportBundle(
            engagement=self.engagement,
            assets=assets,
            findings=findings,
        )

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _parse_host(host: ET.Element) -> Asset | None:
        status = host.find("status")
        if status is not None and status.attrib.get("state") == "down":
            return None

        # IP (prefer ipv4 then ipv6, fall back to first <address>)
        addr_elem = host.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            addr_elem = host.find("address[@addrtype='ipv6']")
        if addr_elem is None:
            addr_elem = host.find("address")
        address = addr_elem.attrib.get("addr", "unknown") if addr_elem is not None else "unknown"

        hostname_elem = host.find("hostnames/hostname")
        hostname = hostname_elem.attrib.get("name") if hostname_elem is not None else None

        # OS guess
        os_elem = host.find("os/osmatch")
        os_name = os_elem.attrib.get("name") if os_elem is not None else None

        ports: list[Port] = []
        for port_elem in host.findall("ports/port"):
            state = port_elem.find("state")
            if state is None:
                continue
            state_val = state.attrib.get("state", "closed")
            if state_val == "closed":
                continue

            svc_elem = port_elem.find("service")
            service = None
            if svc_elem is not None:
                service = Service(
                    name=svc_elem.attrib.get("name"),
                    product=svc_elem.attrib.get("product"),
                    version=svc_elem.attrib.get("version"),
                    extra_info=svc_elem.attrib.get("extrainfo"),
                    cpe=(svc_elem.find("cpe").text if svc_elem.find("cpe") is not None else None),
                )

            ports.append(
                Port(
                    number=int(port_elem.attrib["portid"]),
                    protocol=port_elem.attrib.get("protocol", "tcp"),  # type: ignore[arg-type]
                    state=state_val,  # type: ignore[arg-type]
                    service=service,
                    reason=state.attrib.get("reason"),
                )
            )

        return Asset(address=address, hostname=hostname, os=os_name, ports=ports)

    @staticmethod
    def _findings_for_asset(asset: Asset) -> list[Finding]:
        """Emit a baseline INFO finding per open port for audit trail visibility."""
        out: list[Finding] = []
        for p in asset.ports:
            if p.state != "open":
                continue
            svc_str = ""
            if p.service:
                parts = [p.service.name, p.service.product, p.service.version]
                svc_str = " ".join(s for s in parts if s)
            title = f"Open port {p.number}/{p.protocol} on {asset.address}"
            if svc_str:
                title += f" ({svc_str})"
            out.append(
                Finding(
                    id=f"nmap-{asset.address}-{p.protocol}-{p.number}",
                    title=title,
                    severity=Severity.INFO,
                    description=(
                        f"Nmap detected port {p.number}/{p.protocol} as open on "
                        f"{asset.hostname or asset.address}."
                    ),
                    asset=asset.hostname or asset.address,
                    port=p.number,
                    protocol=p.protocol,
                    tool="nmap",
                    plugin_family="port-scan",
                )
            )
        return out
