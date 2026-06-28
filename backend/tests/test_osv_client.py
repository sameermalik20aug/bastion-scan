"""Tests for the OSV.dev client.

Every OSV HTTP call is mocked with respx — these tests never touch the real API.
"""

import httpx
import pytest
import respx

from app.models.schemas import ParsedPackage
from app.services.osv_client import (
    OsvClient,
    OsvUnavailableError,
    derive_severity,
    _extract_fixed_version,
    _is_concrete_version,
)
from app.services import osv_client as osv_module

QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"


def _vuln_url(vuln_id: str) -> str:
    return f"https://api.osv.dev/v1/vulns/{vuln_id}"


def _pkg(name: str, version: str, *, is_direct: bool = True) -> ParsedPackage:
    return ParsedPackage(name=name, version=version, is_direct=is_direct)


# A representative GHSA-style record: CVSS vector in `severity`, a fixed event in
# the affected ranges, and a database_specific rating.
GHSA_RECORD = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "summary": "Prototype pollution in lodash",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "4.17.21"}],
                }
            ],
            "database_specific": {"severity": "HIGH"},
        }
    ],
}


# --------------------------------------------------------------------------- #
# derive_severity
# --------------------------------------------------------------------------- #


def test_derive_severity_from_cvss_vector():
    # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H scores 9.8 -> critical.
    vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    assert derive_severity(vuln) == "critical"


def test_derive_severity_bands_a_medium_vector():
    # A lower-impact vector should land in the medium band, not collapse to low.
    # This one scores 6.1 on the official CVSS v3.1 calculator.
    vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}]}
    assert derive_severity(vuln) == "medium"


def test_derive_severity_falls_back_to_database_specific():
    # No parseable CVSS score, but a GHSA rating is present.
    vuln = {
        "severity": [],
        "affected": [{"database_specific": {"severity": "MODERATE"}}],
    }
    assert derive_severity(vuln) == "medium"


def test_derive_severity_numeric_score_string():
    vuln = {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
    assert derive_severity(vuln) == "high"


def test_derive_severity_defaults_to_unknown():
    assert derive_severity({"id": "X", "summary": "no severity info"}) == "unknown"


def test_derive_severity_v4_only_falls_back_not_unknown():
    # CVSS_V4 isn't scored, but a database_specific rating keeps it off "unknown".
    vuln = {
        "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N"}],
        "database_specific": {"severity": "CRITICAL"},
    }
    assert derive_severity(vuln) == "critical"


# --------------------------------------------------------------------------- #
# _extract_fixed_version
# --------------------------------------------------------------------------- #


def test_extract_fixed_version_basic():
    assert _extract_fixed_version(GHSA_RECORD, "npm", "lodash", "4.17.15") == "4.17.21"


def test_extract_fixed_version_picks_closest_upgrade():
    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "django"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "3.2.18"},
                            {"introduced": "4.0"},
                            {"fixed": "4.1.7"},
                        ],
                    }
                ],
            }
        ]
    }
    # Installed 3.2.0 -> the closest fix strictly greater is 3.2.18, not 4.1.7.
    assert _extract_fixed_version(vuln, "PyPI", "django", "3.2.0") == "3.2.18"


def test_extract_fixed_version_skips_git_ranges_and_unmatched_packages():
    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "other-pkg"},
                "ranges": [{"type": "SEMVER", "events": [{"fixed": "9.9.9"}]}],
            },
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"type": "GIT", "events": [{"fixed": "abc123"}]}],
            },
        ]
    }
    assert _extract_fixed_version(vuln, "npm", "lodash", "1.0.0") is None


def test_extract_fixed_version_none_when_no_fix():
    vuln = {
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
            }
        ]
    }
    assert _extract_fixed_version(vuln, "npm", "lodash", "1.0.0") is None


# --------------------------------------------------------------------------- #
# _is_concrete_version
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("version", ["4.17.21", "1.2.3-beta.1", "2.0.0+build.7"])
def test_is_concrete_version_accepts_pins(version):
    assert _is_concrete_version(version) is True


@pytest.mark.parametrize("version", [">=1.26", "^4.17.21", "~18.2.0", "*", "latest", "", "1.0.0 - 2.0.0"])
def test_is_concrete_version_rejects_ranges_and_tags(version):
    assert _is_concrete_version(version) is False


# --------------------------------------------------------------------------- #
# find_vulnerabilities (two-step flow, mocked)
# --------------------------------------------------------------------------- #


@respx.mock
async def test_find_vulnerabilities_two_step_flow():
    # Step 1: one batch call for both packages. lodash is vulnerable, left-pad isn't.
    respx.post(QUERYBATCH_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {"vulns": [{"id": "GHSA-xxxx-yyyy-zzzz", "modified": "2023-01-01T00:00:00Z"}]},
                    {},  # left-pad: no vulns
                ]
            },
        )
    )
    # Step 2: detail fetch for the single returned ID.
    respx.get(_vuln_url("GHSA-xxxx-yyyy-zzzz")).mock(
        return_value=httpx.Response(200, json=GHSA_RECORD)
    )

    client = OsvClient()
    vulns = await client.find_vulnerabilities(
        [_pkg("lodash", "4.17.15"), _pkg("left-pad", "1.3.0")], "npm"
    )

    assert len(vulns) == 1
    (vuln,) = vulns
    assert vuln.id == "GHSA-xxxx-yyyy-zzzz"
    assert vuln.package == "lodash"
    assert vuln.current_version == "4.17.15"
    assert vuln.severity == "critical"
    assert vuln.fixed_version == "4.17.21"
    assert vuln.summary == "Prototype pollution in lodash"


@respx.mock
async def test_unpinned_packages_are_skipped_entirely():
    # The only package has a range version, so no HTTP call should be made.
    route = respx.post(QUERYBATCH_URL)
    client = OsvClient()
    vulns = await client.find_vulnerabilities([_pkg("lodash", "^4.0.0")], "npm")
    assert vulns == []
    assert not route.called


@respx.mock
async def test_no_vulns_returns_empty():
    respx.post(QUERYBATCH_URL).mock(
        return_value=httpx.Response(200, json={"results": [{}]})
    )
    client = OsvClient()
    vulns = await client.find_vulnerabilities([_pkg("safe-pkg", "1.0.0")], "npm")
    assert vulns == []


@respx.mock
async def test_cache_avoids_second_batch_call():
    batch = respx.post(QUERYBATCH_URL).mock(
        return_value=httpx.Response(
            200, json={"results": [{"vulns": [{"id": "GHSA-xxxx-yyyy-zzzz"}]}]}
        )
    )
    detail = respx.get(_vuln_url("GHSA-xxxx-yyyy-zzzz")).mock(
        return_value=httpx.Response(200, json=GHSA_RECORD)
    )

    client = OsvClient()
    first = await client.find_vulnerabilities([_pkg("lodash", "4.17.15")], "npm")
    second = await client.find_vulnerabilities([_pkg("lodash", "4.17.15")], "npm")

    assert len(first) == 1 and len(second) == 1
    # Both calls served, but OSV was only hit once.
    assert batch.call_count == 1
    assert detail.call_count == 1


@respx.mock
async def test_timeout_raises_osv_unavailable():
    respx.post(QUERYBATCH_URL).mock(side_effect=httpx.ConnectTimeout("timed out"))
    client = OsvClient()
    with pytest.raises(OsvUnavailableError):
        await client.find_vulnerabilities([_pkg("lodash", "4.17.15")], "npm")


@respx.mock
async def test_batch_500_raises_osv_unavailable():
    respx.post(QUERYBATCH_URL).mock(return_value=httpx.Response(500))
    client = OsvClient()
    with pytest.raises(OsvUnavailableError):
        await client.find_vulnerabilities([_pkg("lodash", "4.17.15")], "npm")


@respx.mock
async def test_partial_detail_failure_is_skipped_not_fatal():
    # Two vulns matched; one detail fetch 404s. We keep the one that resolved.
    respx.post(QUERYBATCH_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {"vulns": [{"id": "GHSA-xxxx-yyyy-zzzz"}, {"id": "GHSA-missing"}]}
                ]
            },
        )
    )
    respx.get(_vuln_url("GHSA-xxxx-yyyy-zzzz")).mock(
        return_value=httpx.Response(200, json=GHSA_RECORD)
    )
    respx.get(_vuln_url("GHSA-missing")).mock(return_value=httpx.Response(404))

    client = OsvClient()
    vulns = await client.find_vulnerabilities([_pkg("lodash", "4.17.15")], "npm")
    assert [v.id for v in vulns] == ["GHSA-xxxx-yyyy-zzzz"]


@respx.mock
async def test_module_level_client_is_shared():
    # The module exposes a process-wide instance for cache reuse across requests.
    assert isinstance(osv_module.osv_client, OsvClient)
