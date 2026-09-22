"""Burp Suite XML report parser.

Parses the XML export produced by Burp Suite Professional
("Report" → "XML"). Each `<issue>` becomes a :class:`Finding` and each
distinct host becomes an :class:`Asset`.

Burp encodes several fields (requests, responses, some detail blobs) in
base64 when the report is generated with "base64-encode requests and
responses" enabled; we decode transparently. Severity is Burp's own scale
(High/Medium/Low/Information) plus an optional CVSS pulled from free text.
"""

from __future__ import annotations

import base64
import re
from pathlib import Path
from urllib.parse import urlsplit

from defusedxml import ElementTree as ET  # noqa: N817

from haak_anvil.core.models import Asset, Finding, Port, ReportBundle, Service
from haak_anvil.core.severity import CVSS, Severity, severity_from_cvss
from haak_anvil.parsers.base import ParserBase

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_CVSS_VEC_RE = re.compile(r"CVSS:3\.[01]/[A-Z:/.]+")
_TAG_RE = re.compile(r"<[^>]+>")

_BURP_SEVERITY = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "information": Severity.INFO,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}


class BurpParser(ParserBase):
    """Parse a Burp Suite XML export into a ReportBundle."""

    tool_name = "burp"

    def parse(self, path: Path) -> ReportBundle:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(path)

        tree = ET.parse(str(path))
        root = tree.getroot()
        if root.tag != "issues":
            raise ValueError(f"Not a Burp XML export (root={root.tag!r})")

        assets_by_addr: dict[str, Asset] = {}
        findings: list[Finding] = []

        for idx, issue in enumerate(root.findall("issue")):
            finding, host, port_obj = self._parse_issue(issue, idx)
            findings.append(finding)
            if host:
                asset = assets_by_addr.get(host)
                if asset is None:
                    asset = Asset(address=host)
                    assets_by_addr[host] = asset
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

    def _parse_issue(self, issue: ET.Element, idx: int) -> tuple[Finding, str | None, Port | None]:
        name = self._text(issue, "name") or "Unnamed Burp issue"
        host_el = issue.find("host")
        url_host = (host_el.attrib.get("ip") if host_el is not None else "") or ""
        host_text = (host_el.text if host_el is not None else "") or ""
        path_part = self._text(issue, "path")
        location = self._text(issue, "location")

        # Derive address + port from the host URL (e.g. https://acme.example:443)
        address: str | None = None
        port_obj: Port | None = None
        if host_text:
            split = urlsplit(host_text)
            address = split.hostname or host_text
            port_num = split.port or (443 if split.scheme == "https" else 80 if split.scheme == "http" else None)
            if port_num:
                port_obj = Port(
                    number=port_num,
                    protocol="tcp",
                    state="open",
                    service=Service(name=split.scheme or "http"),
                )
        if not address and url_host:
            address = url_host

        severity = _BURP_SEVERITY.get((self._text(issue, "severity") or "").lower(), Severity.INFO)

        # Burp free-text blocks (HTML). Decode → strip tags for a clean report.
        background = self._clean(self._text(issue, "issueBackground"))
        detail = self._clean(self._text(issue, "issueDetail"))
        remediation_bg = self._clean(self._text(issue, "remediationBackground"))
        remediation_detail = self._clean(self._text(issue, "remediationDetail"))
        references_html = self._text(issue, "references")

        description = "\n\n".join(x for x in (background, detail) if x) or name
        remediation = "\n\n".join(x for x in (remediation_bg, remediation_detail) if x) or None

        haystack = " ".join(
            filter(None, [background, detail, references_html, self._text(issue, "vulnerabilityClassifications")])
        )
        cve = sorted({m.upper() for m in _CVE_RE.findall(haystack)})
        cwe = sorted({m.upper() for m in _CWE_RE.findall(haystack)})

        cvss_obj: CVSS | None = None
        vec_match = _CVSS_VEC_RE.search(haystack)
        if vec_match:
            score = self._cvss_from_vector(vec_match.group(0))
            if score is not None:
                cvss_obj = CVSS(score=score, vector=vec_match.group(0), version="3.1")
                severity = severity_from_cvss(score)

        references = self._extract_links(references_html)

        serial = issue.find("serialNumber")
        plugin_id = (serial.text.strip() if serial is not None and serial.text else None) or (
            self._text(issue, "type") or None
        )
        finding_id = f"burp-{plugin_id or idx}-{address or 'host'}-{idx}"

        finding = Finding(
            id=finding_id,
            title=name,
            severity=severity,
            cvss=cvss_obj,
            description=description,
            impact=background or None,
            remediation=remediation,
            references=references,
            cve=cve,
            cwe=cwe,
            asset=address,
            port=port_obj.number if port_obj else None,
            protocol="tcp" if port_obj else None,
            evidence=(path_part or location) or None,
            plugin_id=plugin_id,
            plugin_family="burp",
            tool="burp",
        )
        return finding, address, port_obj

    @staticmethod
    def _text(elem: ET.Element, tag: str, default: str = "") -> str:
        child = elem.find(tag)
        if child is None:
            return default
        raw = "".join(child.itertext()) if len(child) else (child.text or "")
        return raw.strip()

    @classmethod
    def _clean(cls, value: str) -> str:
        """Decode base64 if applicable and strip HTML tags to plain text."""
        if not value:
            return ""
        decoded = cls._maybe_b64(value)
        no_tags = _TAG_RE.sub(" ", decoded)
        return re.sub(r"[ \t]+", " ", no_tags).replace(" \n", "\n").strip()

    @staticmethod
    def _maybe_b64(value: str) -> str:
        stripped = value.strip()
        # Heuristic: only attempt decode on base64-looking blobs with no spaces/tags.
        if len(stripped) >= 8 and re.fullmatch(r"[A-Za-z0-9+/=\r\n]+", stripped):
            try:
                out = base64.b64decode(stripped, validate=True).decode("utf-8", "replace")
                if out.isprintable() or "\n" in out or "<" in out:
                    return out
            except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
                pass
        return value

    @staticmethod
    def _extract_links(references_html: str) -> list[str]:
        if not references_html:
            return []
        urls = re.findall(r"https?://[^\s\"'<>]+", references_html)
        seen: list[str] = []
        for u in urls:
            if u not in seen:
                seen.append(u)
        return seen

    @staticmethod
    def _cvss_from_vector(vector: str) -> float | None:
        """Best-effort base-score estimate from a CVSS v3.x vector string.

        A full CVSS engine is out of scope; we map the coarse impact of a vector
        so severity ordering is sane. If the vector can't be reasoned about we
        return None and leave severity as Burp reported it.
        """
        m = dict(
            part.split(":", 1)
            for part in vector.split("/")
            if ":" in part and not part.startswith("CVSS")
        )
        if not {"AV", "AC", "C", "I", "A"} <= set(m):
            return None
        weights_ci = {"N": 0.0, "L": 0.22, "H": 0.56}
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(m["AV"], 0.55)
        ac = {"L": 0.77, "H": 0.44}.get(m["AC"], 0.77)
        conf, integ, avail = (weights_ci.get(m[k], 0.0) for k in ("C", "I", "A"))
        iss = 1 - (1 - conf) * (1 - integ) * (1 - avail)
        if iss <= 0:
            return 0.0
        impact = 6.42 * iss
        exploitability = 8.22 * av * ac * 0.85 * 0.85  # PR:N, UI:N assumed
        score = min(impact + exploitability, 10.0)
        return round(score * 10) / 10
