"""Tests for the fix suggester.

These exercise the two manifest strategies (requirements.txt in-place line edits,
package.json load/dump) and the breaking-change classification, including the
0.x carve-out and the lexical-vs-structural version ordering.
"""

from app.models.schemas import Vulnerability
from app.parsers.npm import NpmParser
from app.parsers.pypi import PypiParser
from app.services.fixer import (
    REVIEW_NOTICE,
    _is_breaking_upgrade,
    _pick_max_fix,
    suggest_fixes,
)


def _vuln(package: str, current: str, fixed: str | None) -> Vulnerability:
    return Vulnerability(
        id=f"OSV-{package}",
        package=package,
        current_version=current,
        severity="high",
        summary=f"vuln in {package}",
        is_direct=True,
        fixed_version=fixed,
    )


def _suggestion_for(result, package):
    return next(s for s in result.suggestions if s.package == package)


# --------------------------------------------------------------------------- #
# PyPI / requirements.txt
# --------------------------------------------------------------------------- #


def _pypi(manifest: str, vulns: list[Vulnerability]):
    packages = PypiParser().parse(manifest)
    return suggest_fixes(
        ecosystem="PyPI", manifest=manifest, packages=packages, vulnerabilities=vulns
    )


def test_pypi_patch_bump_is_applied_and_not_breaking():
    manifest = "requests==2.25.0\n"
    result = _pypi(manifest, [_vuln("requests", "2.25.0", "2.25.1")])

    assert result.manifest == "requests==2.25.1\n"
    s = _suggestion_for(result, "requests")
    assert s.suggested_version == "2.25.1"
    assert s.applied is True
    assert s.is_breaking_upgrade is False


def test_pypi_minor_bump_is_applied_and_not_breaking():
    manifest = "flask==2.1.0\n"
    result = _pypi(manifest, [_vuln("flask", "2.1.0", "2.3.0")])

    assert result.manifest == "flask==2.3.0\n"
    s = _suggestion_for(result, "flask")
    assert s.suggested_version == "2.3.0"
    assert s.applied is True
    assert s.is_breaking_upgrade is False


def test_pypi_major_bump_is_flagged_breaking():
    manifest = "django==2.2.0\n"
    result = _pypi(manifest, [_vuln("django", "2.2.0", "3.0.0")])

    # Still applied (it's an exact pin), but the major jump must be flagged.
    assert result.manifest == "django==3.0.0\n"
    s = _suggestion_for(result, "django")
    assert s.is_breaking_upgrade is True


def test_pypi_0x_minor_bump_is_breaking():
    # 0.x has no stable API: 0.18 -> 0.19 is a minor bump but must be flagged.
    manifest = "semver-ish==0.18.0\n"
    result = _pypi(manifest, [_vuln("semver-ish", "0.18.0", "0.19.0")])

    s = _suggestion_for(result, "semver-ish")
    assert s.suggested_version == "0.19.0"
    assert s.is_breaking_upgrade is True


def test_pypi_no_known_fix_is_left_unchanged():
    manifest = "leftpad==1.0.0\n"
    result = _pypi(manifest, [_vuln("leftpad", "1.0.0", None)])

    assert result.manifest == manifest  # untouched
    s = _suggestion_for(result, "leftpad")
    assert s.applied is False
    assert s.suggested_version is None
    assert s.skipped_reason == "no known fixed version"


def test_pypi_range_is_flagged_not_rewritten():
    # A range pin (>=) is not an exact pin: suggest, but never rewrite.
    manifest = "urllib3>=1.26.0\n"
    result = _pypi(manifest, [_vuln("urllib3", ">=1.26.0", "1.26.5")])

    assert result.manifest == manifest
    s = _suggestion_for(result, "urllib3")
    assert s.applied is False
    assert s.suggested_version == "1.26.5"
    assert s.skipped_reason == "not an exact pin"


def test_pypi_rewrite_preserves_comments_and_other_lines():
    manifest = (
        "# top-level deps\n"
        "requests==2.25.0  # pinned for the http client\n"
        "\n"
        "flask>=2.0\n"
    )
    result = _pypi(manifest, [_vuln("requests", "2.25.0", "2.26.0")])

    # Only the requests version changes; comment, blank line, and the flask
    # range line are preserved verbatim.
    assert result.manifest == (
        "# top-level deps\n"
        "requests==2.26.0  # pinned for the http client\n"
        "\n"
        "flask>=2.0\n"
    )


# --------------------------------------------------------------------------- #
# npm / package.json
# --------------------------------------------------------------------------- #


def _npm(manifest: str, vulns: list[Vulnerability]):
    packages = NpmParser().parse(manifest)
    return suggest_fixes(
        ecosystem="npm", manifest=manifest, packages=packages, vulnerabilities=vulns
    )


def test_npm_exact_pin_patch_bump_is_applied():
    import json

    manifest = json.dumps({"dependencies": {"lodash": "4.17.20"}}, indent=2) + "\n"
    result = _npm(manifest, [_vuln("lodash", "4.17.20", "4.17.21")])

    assert json.loads(result.manifest)["dependencies"]["lodash"] == "4.17.21"
    s = _suggestion_for(result, "lodash")
    assert s.applied is True
    assert s.is_breaking_upgrade is False


def test_npm_caret_range_is_flagged_not_rewritten():
    import json

    # The npm parser resolves "^4.17.0" to a concrete 4.17.0, but it's a range,
    # so it must be flagged and the manifest left untouched.
    manifest = json.dumps({"dependencies": {"lodash": "^4.17.0"}}, indent=2) + "\n"
    result = _npm(manifest, [_vuln("lodash", "4.17.0", "4.17.21")])

    assert json.loads(result.manifest)["dependencies"]["lodash"] == "^4.17.0"
    s = _suggestion_for(result, "lodash")
    assert s.applied is False
    assert s.skipped_reason == "not an exact pin"


def test_npm_0x_minor_bump_is_breaking():
    import json

    manifest = json.dumps({"dependencies": {"tiny": "0.2.0"}}, indent=2) + "\n"
    result = _npm(manifest, [_vuln("tiny", "0.2.0", "0.3.0")])

    assert json.loads(result.manifest)["dependencies"]["tiny"] == "0.3.0"
    s = _suggestion_for(result, "tiny")
    assert s.is_breaking_upgrade is True


def test_npm_major_bump_is_flagged_breaking():
    import json

    manifest = json.dumps({"dependencies": {"express": "3.21.0"}}, indent=2) + "\n"
    result = _npm(manifest, [_vuln("express", "3.21.0", "4.0.0")])

    s = _suggestion_for(result, "express")
    assert s.is_breaking_upgrade is True


def test_npm_no_known_fix_is_left_unchanged():
    import json

    manifest = json.dumps({"dependencies": {"left-pad": "1.0.0"}}, indent=2) + "\n"
    result = _npm(manifest, [_vuln("left-pad", "1.0.0", None)])

    assert json.loads(result.manifest)["dependencies"]["left-pad"] == "1.0.0"
    s = _suggestion_for(result, "left-pad")
    assert s.applied is False
    assert s.skipped_reason == "no known fixed version"


def test_npm_preserves_equals_prefix_on_exact_pin():
    import json

    manifest = json.dumps({"dependencies": {"lodash": "=4.17.20"}}, indent=2) + "\n"
    result = _npm(manifest, [_vuln("lodash", "4.17.20", "4.17.21")])

    # The '=' exact-pin marker is preserved through the rewrite.
    assert json.loads(result.manifest)["dependencies"]["lodash"] == "=4.17.21"


# --------------------------------------------------------------------------- #
# Version helpers
# --------------------------------------------------------------------------- #


def test_breaking_helper_rules():
    # patch bump, >= 1.0: not breaking
    assert _is_breaking_upgrade(1, 2, 1, 2) is False
    # minor bump, >= 1.0: not breaking
    assert _is_breaking_upgrade(1, 2, 1, 5) is False
    # major bump: breaking
    assert _is_breaking_upgrade(1, 2, 2, 0) is True
    # 0.x minor bump: breaking
    assert _is_breaking_upgrade(0, 2, 0, 3) is True
    # 0.x patch bump: not breaking
    assert _is_breaking_upgrade(0, 2, 0, 2) is False


def test_pick_max_fix_is_numeric_not_lexical_pypi():
    # Lexically "1.9.0" > "1.10.0" (because '9' > '1'); numerically 1.10.0 wins.
    assert _pick_max_fix(["1.9.0", "1.10.0"], "PyPI") == "1.10.0"


def test_pick_max_fix_is_numeric_not_lexical_npm():
    assert _pick_max_fix(["1.9.0", "1.10.0"], "npm") == "1.10.0"


def test_multiple_vulns_pick_highest_fix():
    manifest = "pkg==1.0.0\n"
    result = _pypi(
        manifest,
        [_vuln("pkg", "1.0.0", "1.9.0"), _vuln("pkg", "1.0.0", "1.10.0")],
    )
    # Must clear both vulns -> the higher (numeric) fix.
    assert result.manifest == "pkg==1.10.0\n"


def test_result_carries_review_notice():
    result = _pypi("requests==2.25.0\n", [_vuln("requests", "2.25.0", "2.25.1")])
    assert result.notice == REVIEW_NOTICE
    assert "review before applying" in result.notice
