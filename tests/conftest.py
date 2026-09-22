from pathlib import Path

import pytest

from haak_anvil.core.engagement import Engagement

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def engagement() -> Engagement:
    return Engagement(
        id="TEST-2026-001",
        client_name="Acme Test Corp",
        scope="Test scope",
        analyst="Haak Cybersecurity Consulting",
    )


@pytest.fixture
def nmap_xml() -> Path:
    return FIXTURES / "nmap_sample.xml"


@pytest.fixture
def nessus_file() -> Path:
    return FIXTURES / "nessus_sample.nessus"


@pytest.fixture
def burp_file() -> Path:
    return FIXTURES / "burp_sample.xml"


@pytest.fixture
def nuclei_file() -> Path:
    return FIXTURES / "nuclei_sample.jsonl"
