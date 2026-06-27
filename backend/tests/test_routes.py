"""Tests for the POST /api/v1/scan endpoint.

OSV is faked at the client boundary (no network), and the Anthropic client is
faked too, so these tests exercise the wiring: input handling (multipart vs
JSON), ecosystem detection, the body-size cap, error mapping, the fixer merge,
bring-your-own-key enrichment, and rate limiting.
"""

import pytest
from fastapi.testclient import TestClient

from app.api import routes
from app.main import app
from app.models.schemas import Vulnerability
from app.services import ai_service
from app.services.osv_client import OsvUnavailableError

SCAN_URL = "/api/v1/scan"

PACKAGE_JSON = '{"dependencies": {"lodash": "4.17.20"}}'
REQUIREMENTS = "requests==2.25.0\n"


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """Disable rate limiting and stub OSV out by default for each test.

    The rate-limit test re-enables the limiter explicitly. Stubbing OSV to return
    nothing keeps every other test off the network; tests that need findings
    install their own fake.
    """
    routes.limiter.enabled = False
    routes.limiter.reset()
    monkeypatch.setattr(routes, "osv_client", _FakeOsv())
    ai_service._explanation_cache.clear()
    yield
    routes.limiter.enabled = True


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


class _FakeOsv:
    def __init__(self, vulns=None, error=None) -> None:
        self._vulns = vulns or []
        self._error = error

    async def find_vulnerabilities(self, packages, ecosystem):
        if self._error is not None:
            raise self._error
        return list(self._vulns)


class _FakeTextBlock:
    type = "text"

    def __init__(self, text: str) -> None:
        self.text = text


class _FakeMessage:
    def __init__(self, text: str) -> None:
        self.content = [_FakeTextBlock(text)]


class _FakeAnthropic:
    def __init__(self, text: str) -> None:
        self._text = text
        self.messages = self
        self.closed = False

    async def create(self, **kwargs):
        return _FakeMessage(self._text)

    async def close(self) -> None:
        self.closed = True


def _lodash_vuln() -> Vulnerability:
    return Vulnerability(
        id="GHSA-test",
        package="lodash",
        current_version="4.17.20",
        severity="high",
        summary="Prototype pollution in lodash.",
        is_direct=True,
        fixed_version="4.17.21",
    )


# --------------------------------------------------------------------------- #
# Input handling: multipart vs JSON
# --------------------------------------------------------------------------- #


def test_multipart_upload_detects_npm_from_filename(client):
    response = client.post(
        SCAN_URL,
        files={"file": ("package.json", PACKAGE_JSON, "application/json")},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ecosystem"] == "npm"
    assert body["total_packages"] == 1
    assert body["total_vulnerabilities"] == 0
    assert body["executive_summary"] is None


def test_json_body_with_ecosystem_hint(client):
    response = client.post(
        SCAN_URL,
        json={"content": REQUIREMENTS, "ecosystem": "pypi"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ecosystem"] == "PyPI"
    assert body["total_packages"] == 1


def test_content_sniff_detects_npm_without_filename_or_hint(client):
    # No filename, no hint: a leading "{" should be sniffed as package.json.
    response = client.post(SCAN_URL, json={"content": PACKAGE_JSON})
    assert response.status_code == 200
    assert response.json()["ecosystem"] == "npm"


def test_hint_overrides_filename(client):
    # Filename says package.json, but the explicit hint wins -> PyPI parser,
    # which then rejects the JSON content as an invalid requirement.
    response = client.post(
        SCAN_URL,
        files={"file": ("package.json", REQUIREMENTS, "application/json")},
        data={"ecosystem": "PyPI"},
    )
    assert response.status_code == 200
    assert response.json()["ecosystem"] == "PyPI"


# --------------------------------------------------------------------------- #
# Findings + fixer merge
# --------------------------------------------------------------------------- #


def test_vulnerability_is_reported_with_fixer_decision(client, monkeypatch):
    monkeypatch.setattr(routes, "osv_client", _FakeOsv(vulns=[_lodash_vuln()]))

    response = client.post(SCAN_URL, json={"content": PACKAGE_JSON, "ecosystem": "npm"})
    assert response.status_code == 200
    body = response.json()

    assert body["total_vulnerabilities"] == 1
    vuln = body["packages"][0]["vulnerabilities"][0]
    assert vuln["id"] == "GHSA-test"
    # The fixer owns the upgrade decision; a patch bump is non-breaking.
    assert vuln["is_breaking_upgrade"] is False
    assert vuln["fixed_version"] == "4.17.21"
    # The exact pin was rewritten, so a fixed manifest is surfaced.
    assert body["fixed_manifest"] is not None
    assert "4.17.21" in body["fixed_manifest"]
    assert body["fix_notice"]


# --------------------------------------------------------------------------- #
# Error mapping
# --------------------------------------------------------------------------- #


def test_unsupported_content_type_is_415(client):
    response = client.post(SCAN_URL, content="raw", headers={"content-type": "text/plain"})
    assert response.status_code == 415


def test_invalid_json_body_is_422(client):
    response = client.post(
        SCAN_URL,
        content="{not json",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 422


def test_missing_content_field_is_422(client):
    response = client.post(SCAN_URL, json={"ecosystem": "npm"})
    assert response.status_code == 422


def test_unknown_ecosystem_hint_is_422(client):
    response = client.post(SCAN_URL, json={"content": REQUIREMENTS, "ecosystem": "cargo"})
    assert response.status_code == 422


def test_unparseable_manifest_is_422(client):
    # A line PyPI's parser rejects as an invalid requirement.
    response = client.post(SCAN_URL, json={"content": "===bad===", "ecosystem": "PyPI"})
    assert response.status_code == 422


def test_osv_unavailable_is_503(client, monkeypatch):
    monkeypatch.setattr(routes, "osv_client", _FakeOsv(error=OsvUnavailableError("db down")))
    response = client.post(SCAN_URL, json={"content": REQUIREMENTS, "ecosystem": "PyPI"})
    assert response.status_code == 503


def test_body_over_size_cap_is_413(client):
    oversized = "x" * (routes.MAX_BODY_BYTES + 10)
    response = client.post(SCAN_URL, json={"content": oversized, "ecosystem": "PyPI"})
    assert response.status_code == 413


# --------------------------------------------------------------------------- #
# Bring-your-own-key enrichment
# --------------------------------------------------------------------------- #


def test_enrichment_runs_with_key_and_does_not_leak_it(client, monkeypatch):
    monkeypatch.setattr(routes, "osv_client", _FakeOsv(vulns=[_lodash_vuln()]))
    valid = (
        '{"what_it_is": "x", "real_world_risk": "y", "should_i_worry": "Fix now", "fix_note": "z"}'
    )
    monkeypatch.setattr(ai_service, "_build_client", lambda api_key: _FakeAnthropic(valid))

    secret = "sk-super-secret-key"
    response = client.post(
        SCAN_URL,
        json={"content": PACKAGE_JSON, "ecosystem": "npm"},
        headers={"X-Anthropic-Key": secret},
    )
    assert response.status_code == 200
    body = response.json()

    explanation = body["packages"][0]["vulnerabilities"][0]["ai_explanation"]
    assert explanation is not None
    assert ai_service.VulnExplanation.model_validate_json(explanation).should_i_worry == "Fix now"
    # The key must never appear anywhere in the response.
    assert secret not in response.text


def test_no_key_means_no_explanation(client, monkeypatch):
    monkeypatch.setattr(routes, "osv_client", _FakeOsv(vulns=[_lodash_vuln()]))

    response = client.post(SCAN_URL, json={"content": PACKAGE_JSON, "ecosystem": "npm"})
    assert response.status_code == 200
    body = response.json()
    assert body["packages"][0]["vulnerabilities"][0]["ai_explanation"] is None


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #


def test_rate_limit_returns_clean_429(client):
    routes.limiter.reset()
    routes.limiter.enabled = True

    payload = {"content": REQUIREMENTS, "ecosystem": "PyPI"}
    # The limit is 10/minute; the 11th request from the same client trips it.
    statuses = [client.post(SCAN_URL, json=payload).status_code for _ in range(11)]

    assert statuses[:10] == [200] * 10
    assert statuses[10] == 429
    last = client.post(SCAN_URL, json=payload)
    assert last.status_code == 429
    assert "10 scans per minute" in last.json()["detail"]
