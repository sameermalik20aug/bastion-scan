"""Tests for the POST /api/v1/scan endpoint.

OSV is faked at the client boundary (no network), and the Anthropic client is
faked too, so these tests exercise the wiring: input handling (multipart vs
JSON), ecosystem detection, the body-size cap, error mapping, the fixer merge,
bring-your-own-key enrichment, and rate limiting.
"""

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.api import routes
from app.main import app
from app.models.schemas import Vulnerability
from app.services import ai_service
from app.services.osv_client import OsvClient, OsvUnavailableError

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


class _BranchingAnthropic:
    """Returns per-vuln explanation JSON, or summary prose for the summary call.

    The summary prompt is the only one carrying a ``<scan_data>`` block, so the
    request content distinguishes the two call shapes — letting one fake serve a
    realistic enrichment (explanations + a distinct executive summary).
    """

    def __init__(self, explanation: str, summary: str) -> None:
        self._explanation = explanation
        self._summary = summary
        self.messages = self
        self.closed = False

    async def create(self, **kwargs):
        user = kwargs["messages"][0]["content"]
        return _FakeMessage(self._summary if "<scan_data>" in user else self._explanation)

    async def close(self) -> None:
        self.closed = True


VALID_EXPLANATION = (
    '{"what_it_is": "Prototype pollution.", "real_world_risk": "Object tampering.", '
    '"should_i_worry": "Fix now", "fix_note": "Upgrade to the patched release."}'
)

# A representative npm GHSA record for the respx-backed integration test: a CVSS
# vector (scores critical) and a fixed event in the affected ranges.
GHSA_RECORD = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "summary": "Prototype pollution in lodash",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
        }
    ],
}


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


def test_multipart_file_wins_over_a_pasted_content_field(client):
    # A request that carries BOTH an uploaded file and a pasted `content` form
    # field: the multipart path reads the file part and ignores the stray
    # `content`, so the uploaded package.json (npm) is what gets scanned.
    response = client.post(
        SCAN_URL,
        files={"file": ("package.json", PACKAGE_JSON, "application/json")},
        data={"content": REQUIREMENTS},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ecosystem"] == "npm"  # from the file, not the pasted requirements
    assert body["total_packages"] == 1


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


def test_streaming_body_over_cap_is_413_without_content_length(client):
    # A chunked body declares no Content-Length, so the up-front header check
    # can't catch it — only the streaming counter in _read_capped_body can. We
    # stream just over the cap and expect a 413 before any JSON parsing happens.
    chunk = b"x" * 100_001

    def oversized_stream():
        for _ in range(11):  # 1,100,011 bytes total, trips partway through
            yield chunk

    response = client.post(
        SCAN_URL,
        content=oversized_stream(),
        headers={"content-type": "application/json"},
    )
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


# --------------------------------------------------------------------------- #
# Integration: the full /scan pipeline end to end
# --------------------------------------------------------------------------- #

# A manifest with one vulnerable pin (lodash) and one clean pin (left-pad), so
# the pipeline must report a finding for one and nothing for the other.
MIXED_PACKAGE_JSON = (
    '{"dependencies": {"lodash": "4.17.20", "left-pad": "1.3.0"}}'
)


def test_full_scan_mixed_manifest_with_osv_and_ai(client, monkeypatch):
    # End to end with OSV faked at the client and Anthropic faked at the factory:
    # a mixed manifest -> one finding, AI explanation + executive summary attached,
    # a rewritten manifest surfaced, and the key never echoed back.
    monkeypatch.setattr(routes, "osv_client", _FakeOsv(vulns=[_lodash_vuln()]))
    monkeypatch.setattr(
        ai_service,
        "_build_client",
        lambda api_key: _BranchingAnthropic(VALID_EXPLANATION, "One critical issue; upgrade lodash."),
    )

    secret = "sk-do-not-leak"
    response = client.post(
        SCAN_URL,
        json={"content": MIXED_PACKAGE_JSON, "ecosystem": "npm"},
        headers={"X-Anthropic-Key": secret},
    )
    assert response.status_code == 200
    body = response.json()

    assert body["total_packages"] == 2
    assert body["total_vulnerabilities"] == 1
    packages = {pkg["name"]: pkg for pkg in body["packages"]}
    # The clean package carries no findings; the vulnerable one is enriched.
    assert packages["left-pad"]["vulnerabilities"] == []
    (vuln,) = packages["lodash"]["vulnerabilities"]
    explanation = ai_service.VulnExplanation.model_validate_json(vuln["ai_explanation"])
    assert explanation.should_i_worry == "Fix now"

    # Whole-scan enrichment and the deterministic fixer output both come through.
    assert body["executive_summary"] == "One critical issue; upgrade lodash."
    assert body["fixed_manifest"] is not None
    assert '"lodash": "4.17.21"' in body["fixed_manifest"]
    assert '"left-pad": "1.3.0"' in body["fixed_manifest"]  # clean pin untouched
    assert secret not in response.text


@respx.mock
def test_full_scan_drives_real_osv_client_over_mocked_http(client, monkeypatch):
    # The most integration-y path: a real OsvClient runs through the route, its
    # OSV HTTP mocked with respx, the fixer runs for real, and Anthropic is faked.
    # Exercises parse -> querybatch -> per-id fetch -> fixer -> AI in one request.
    respx.post("https://api.osv.dev/v1/querybatch").mock(
        return_value=httpx.Response(
            200, json={"results": [{"vulns": [{"id": "GHSA-xxxx-yyyy-zzzz"}]}]}
        )
    )
    respx.get("https://api.osv.dev/v1/vulns/GHSA-xxxx-yyyy-zzzz").mock(
        return_value=httpx.Response(200, json=GHSA_RECORD)
    )
    # A fresh client so this test's findings aren't served from a shared cache.
    monkeypatch.setattr(routes, "osv_client", OsvClient())
    monkeypatch.setattr(
        ai_service,
        "_build_client",
        lambda api_key: _BranchingAnthropic(VALID_EXPLANATION, "Upgrade lodash now."),
    )

    response = client.post(
        SCAN_URL,
        json={"content": PACKAGE_JSON, "ecosystem": "npm"},
        headers={"X-Anthropic-Key": "sk-test"},
    )
    assert response.status_code == 200
    body = response.json()

    assert body["total_vulnerabilities"] == 1
    (vuln,) = body["packages"][0]["vulnerabilities"]
    assert vuln["id"] == "GHSA-xxxx-yyyy-zzzz"
    assert vuln["severity"] == "critical"
    # The fixer derived 4.17.21 from OSV's affected ranges and rewrote the pin.
    assert vuln["fixed_version"] == "4.17.21"
    assert vuln["ai_explanation"] is not None
    assert '"lodash": "4.17.21"' in body["fixed_manifest"]
    assert body["executive_summary"] == "Upgrade lodash now."
