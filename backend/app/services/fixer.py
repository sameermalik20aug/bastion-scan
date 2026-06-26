"""Produce a corrected manifest with suggested safe versions substituted in.

Given the packages a parser pulled out of a manifest and the vulnerabilities OSV
reported for them, this module decides — per package — whether it can safely
rewrite the pinned version to a known-fixed one, and regenerates the manifest
with those substitutions applied.

Two hard rules shape everything here:

1. **Only exact pins are rewritten.** A fix is written into the manifest only
   when OSV gave a concrete fixed version *and* the manifest pinned the package
   to an exact version (``requests==2.25.1``, ``"lodash": "4.17.20"``). Range or
   unpinned specs (``>=1.0``, ``^4.17.0``, ``*``) are *flagged* so the caller can
   surface them, but never silently rewritten — the resolved version of a range
   isn't something the user wrote down, so editing it would be presumptuous.

2. **Versions are compared structurally, never lexically.** PyPI versions go
   through :class:`packaging.version.Version` (PEP 440); npm versions go through
   :class:`semver.Version` (SemVer). Comparing the raw strings would order
   ``"1.10.0"`` before ``"1.9.0"`` (``'1'`` == ``'1'``, then ``'1'`` < ``'9'``),
   which is wrong — see ``_pick_max_fix``.

The output is deliberately framed as *suggestions*: see :data:`REVIEW_NOTICE`.
Nothing here verifies the suggested version is actually compatible with the
caller's code, so we never describe the result as "safe" — only as a starting
point to review.
"""

from __future__ import annotations

import json
import re

import semver
from packaging.version import InvalidVersion
from packaging.version import Version as PypiVersion
from pydantic import BaseModel, Field

from app.models.schemas import Ecosystem, ParsedPackage, Vulnerability

# The one piece of framing every consumer of this module should echo to users.
# We never call a rewritten manifest "fixed" or "safe": the upgrade may break
# the build, and we have not run the caller's tests.
REVIEW_NOTICE = "suggested safe versions, review before applying"


class FixSuggestion(BaseModel):
    """One package's upgrade outcome.

    ``applied`` records whether the suggestion was actually written into the
    regenerated manifest. It is ``False`` either because the package wasn't an
    exact pin (``skipped_reason == "not an exact pin"``) or because OSV reported
    no fixed version (``skipped_reason == "no known fixed version"``).
    """

    package: str
    current_version: str
    suggested_version: str | None = None
    is_breaking_upgrade: bool = False
    applied: bool = False
    skipped_reason: str | None = None


class FixResult(BaseModel):
    """The regenerated manifest plus a per-package account of what changed."""

    manifest: str
    suggestions: list[FixSuggestion] = Field(default_factory=list)
    # Echoed verbatim so callers don't have to remember the framing themselves.
    notice: str = REVIEW_NOTICE


# --------------------------------------------------------------------------- #
# Version handling
#
# Each ecosystem gets its own parse + breaking-change logic. The two share a
# shape — (major, minor) plus a comparison — but PyPI and npm disagree on how a
# string maps to those numbers, so we keep them separate rather than pretending
# one parser fits both.
# --------------------------------------------------------------------------- #


def _pypi_version(value: str) -> PypiVersion | None:
    """Parse a PyPI version (PEP 440), or ``None`` if it isn't parseable."""
    try:
        return PypiVersion(value)
    except (InvalidVersion, TypeError):
        return None


def _npm_version(value: str) -> semver.Version | None:
    """Parse an npm version (SemVer), or ``None`` if it isn't parseable.

    npm tolerates a leading ``v`` (``v1.2.3``) and short forms (``1``, ``1.2``)
    that strict SemVer rejects, so we coerce before handing it to the parser.
    """
    candidate = value.strip()
    if candidate[:1] in ("v", "V"):
        candidate = candidate[1:]
    try:
        return semver.Version.parse(candidate)
    except ValueError:
        # Pad short forms ("1" -> "1.0.0", "1.2" -> "1.2.0") and retry once.
        parts = candidate.split("+", 1)[0].split("-", 1)[0].split(".")
        if all(p.isdigit() for p in parts) and 1 <= len(parts) <= 2:
            padded = ".".join(parts + ["0"] * (3 - len(parts)))
            suffix = candidate[len(".".join(parts)) :]
            try:
                return semver.Version.parse(padded + suffix)
            except ValueError:
                return None
        return None


def _is_breaking_upgrade(
    current_major: int, current_minor: int, fixed_major: int, fixed_minor: int
) -> bool:
    """Decide whether moving current -> fixed crosses a breaking boundary.

    The rule, line by line:

    * A bump in the **major** component is breaking by definition under both
      SemVer and the de-facto PyPI convention — that's what a major bump *means*.
    * The ``0.x`` carve-out: SemVer says anything in ``0.y.z`` has no stable
      public API, so a **minor** bump there (``0.2.x`` -> ``0.3.0``) is allowed
      to break. We mirror that: when both versions are still pre-1.0, a minor
      increase is treated as breaking too.
    * Everything else (patch bumps, and minor bumps at ``>= 1.0``) is considered
      non-breaking.

    Only the major/minor numbers are passed in so this stays ecosystem-agnostic;
    the callers extract them with the right parser.
    """
    if fixed_major > current_major:
        return True
    # 0.x has no stability guarantee, so a minor bump can break the API.
    if current_major == 0 and fixed_major == 0 and fixed_minor > current_minor:
        return True
    return False


def _pick_max_fix(fixes: list[str], ecosystem: Ecosystem) -> str | None:
    """Return the highest fixed version among ``fixes``, compared structurally.

    A package may carry several vulnerabilities, each with its own fixed version.
    To clear *all* of them the installed version must be at or above every fix,
    so the suggestion is the **maximum** fix — and "maximum" is computed with the
    ecosystem's version type, never by string ordering.

    Lexical ``max(["1.9.0", "1.10.0"])`` returns ``"1.9.0"`` (because the second
    character ``'9'`` > ``'1'``), which would leave the ``1.10`` fix unapplied.
    Going through Version objects orders them numerically and returns ``1.10.0``.
    """
    parse = _pypi_version if ecosystem == "PyPI" else _npm_version
    parsed = [(p, raw) for raw in fixes if (p := parse(raw)) is not None]
    if not parsed:
        return None
    return max(parsed, key=lambda t: t[0])[1]


def _breaking_for(current: str, fixed: str, ecosystem: Ecosystem) -> bool:
    """Whether upgrading ``current`` -> ``fixed`` is breaking, per ecosystem.

    If either version fails to parse we can't reason about components, so we err
    toward caution and call it breaking — better an unnecessary review flag than
    a silent major jump.
    """
    parse = _pypi_version if ecosystem == "PyPI" else _npm_version
    cur = parse(current)
    fix = parse(fixed)
    if cur is None or fix is None:
        return True
    return _is_breaking_upgrade(cur.major, cur.minor, fix.major, fix.minor)


# --------------------------------------------------------------------------- #
# Exact-pin detection
# --------------------------------------------------------------------------- #

# A bare concrete version: 1, 1.2, or 1.2.3, optionally with prerelease/build
# metadata. Mirrors the npm parser's notion of "concrete".
_CONCRETE = re.compile(r"^\d+(?:\.\d+){0,2}(?:[-+][0-9A-Za-z.\-+]+)?$")


def _npm_exact_pin(spec: str) -> bool:
    """Whether an npm dependency spec is an exact pin we may rewrite.

    Exact: a bare version, optionally prefixed by a single ``=`` and/or ``v``
    (``1.2.3``, ``=1.2.3``, ``v1.2.3``). Ranges (``^1.2.3``, ``~1.2``, ``>=1``),
    wildcards (``1.x``, ``*``), dist-tags (``latest``), and url/git/workspace
    references all start with something other than a digit (after the allowed
    ``=``/``v``) and are therefore *not* exact pins.
    """
    s = spec.strip()
    if s.startswith("="):  # npm uses a single '='; a leading '==' is non-standard
        s = s[1:]
    if s[:1] in ("v", "V"):
        s = s[1:]
    return bool(_CONCRETE.match(s))


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def suggest_fixes(
    *,
    ecosystem: Ecosystem,
    manifest: str,
    packages: list[ParsedPackage],
    vulnerabilities: list[Vulnerability],
) -> FixResult:
    """Suggest safe-version substitutions and regenerate the manifest.

    Args:
        ecosystem: Which manifest format this is (drives version parsing and the
            rewrite strategy).
        manifest: The original manifest text, returned rewritten.
        packages: The parser's output for ``manifest`` — supplies ``raw_line``
            and tells exact pins from ranges.
        vulnerabilities: OSV findings; each carries the package, the affected
            version, and a ``fixed_version`` when one is known.

    Returns:
        A :class:`FixResult` with the regenerated manifest and one
        :class:`FixSuggestion` per package that had at least one vulnerability.
        The manifest is unchanged for any package that was a range/unpinned spec
        or that has no known fix.
    """
    # Track which packages are vulnerable at all, and — separately — the known
    # fixed versions reported for each. A package can be in the first set but
    # not the second when OSV has no fix for it yet.
    vulnerable_packages: set[str] = set()
    fixes_by_package: dict[str, list[str]] = {}
    for vuln in vulnerabilities:
        vulnerable_packages.add(vuln.package)
        if vuln.fixed_version:
            fixes_by_package.setdefault(vuln.package, []).append(vuln.fixed_version)

    # Index packages by name so we can pair a finding with its manifest entry.
    package_by_name = {pkg.name: pkg for pkg in packages}

    suggestions: list[FixSuggestion] = []
    # raw_line -> new version string, the substitutions to apply to the manifest.
    rewrites: dict[str, str] = {}

    # Iterate packages (not vulns) in manifest order so suggestions are stable
    # and we emit exactly one row per affected package.
    for pkg in packages:
        if pkg.name not in vulnerable_packages:
            continue  # no vulnerability at all — nothing to suggest

        fixes = fixes_by_package.get(pkg.name)
        best_fix = _pick_max_fix(fixes, ecosystem) if fixes else None
        if best_fix is None:
            # Vulnerable but OSV reports no usable fixed version (none at all, or
            # none version-parseable): flag it, leave the manifest unchanged.
            suggestions.append(
                FixSuggestion(
                    package=pkg.name,
                    current_version=pkg.version,
                    skipped_reason="no known fixed version",
                )
            )
            continue

        breaking = _breaking_for(pkg.version, best_fix, ecosystem)

        if not _is_exact_pin(pkg, ecosystem):
            # A range/unpinned dep: surface the suggestion but leave the manifest
            # alone — we won't rewrite a constraint the user didn't pin.
            suggestions.append(
                FixSuggestion(
                    package=pkg.name,
                    current_version=pkg.version,
                    suggested_version=best_fix,
                    is_breaking_upgrade=breaking,
                    applied=False,
                    skipped_reason="not an exact pin",
                )
            )
            continue

        # An exact pin with a known fix: schedule the substitution.
        if pkg.raw_line is not None:
            rewrites[pkg.raw_line] = best_fix
        suggestions.append(
            FixSuggestion(
                package=pkg.name,
                current_version=pkg.version,
                suggested_version=best_fix,
                is_breaking_upgrade=breaking,
                applied=True,
            )
        )

    new_manifest = _regenerate(ecosystem, manifest, packages, package_by_name, rewrites)
    return FixResult(manifest=new_manifest, suggestions=suggestions)


def _is_exact_pin(pkg: ParsedPackage, ecosystem: Ecosystem) -> bool:
    """Whether ``pkg`` was pinned to an exact version in the manifest.

    For PyPI the parser already collapses non-``==`` specs to their raw range
    string, so a parseable concrete ``version`` means it was an ``==`` pin. For
    npm the parser resolves ``^1.2.3`` down to ``1.2.3``, so we can't trust
    ``version`` alone — we inspect the raw spec to tell an exact pin from a
    caret/tilde range.
    """
    if ecosystem == "PyPI":
        return _pypi_version(pkg.version) is not None
    # npm: recover the raw spec from raw_line ('"name": "spec"') and inspect it.
    spec = _npm_spec_from_raw_line(pkg.raw_line)
    return spec is not None and _npm_exact_pin(spec)


# --------------------------------------------------------------------------- #
# Manifest regeneration
# --------------------------------------------------------------------------- #

# Pulls the spec value out of the npm parser's raw_line format: '"name": "spec"'.
_NPM_RAW_LINE = re.compile(r'^"(?P<name>.*)":\s*"(?P<spec>.*)"$')


def _npm_spec_from_raw_line(raw_line: str | None) -> str | None:
    """Recover the version spec from an npm ``raw_line``, or ``None``."""
    if raw_line is None:
        return None
    match = _NPM_RAW_LINE.match(raw_line)
    return match.group("spec") if match else None


def _regenerate(
    ecosystem: Ecosystem,
    manifest: str,
    packages: list[ParsedPackage],
    package_by_name: dict[str, ParsedPackage],
    rewrites: dict[str, str],
) -> str:
    """Apply ``rewrites`` to ``manifest`` using the ecosystem's edit strategy."""
    if not rewrites:
        return manifest
    if ecosystem == "npm":
        return _rewrite_package_json(manifest, package_by_name, rewrites)
    return _rewrite_requirements(manifest, rewrites)


def _rewrite_requirements(manifest: str, rewrites: dict[str, str]) -> str:
    """Rewrite only the matched lines of a requirements.txt, in place.

    Each key in ``rewrites`` is a package's ``raw_line`` (the stripped original
    line). We walk the file line by line and, when a line's stripped form matches
    a key, swap just the version that follows the ``==``/``===`` operator —
    leaving the operator, whitespace, environment markers, trailing comments, and
    every other (comment or blank) line exactly as they were.
    """
    out: list[str] = []
    for line in manifest.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        newline = line[len(body) :]
        new_version = rewrites.get(body.strip())
        if new_version is None:
            out.append(line)
            continue
        # Replace the version token after the (first) ==/=== operator only.
        rewritten = re.sub(
            r"(===?\s*)([^\s;#]+)",
            lambda m: m.group(1) + new_version,
            body,
            count=1,
        )
        out.append(rewritten + newline)
    return "".join(out)


def _rewrite_package_json(
    manifest: str,
    package_by_name: dict[str, ParsedPackage],
    rewrites: dict[str, str],
) -> str:
    """Rewrite a package.json by loading, swapping versions, and re-dumping JSON.

    JSON object key order is preserved (``json.loads`` keeps insertion order),
    so dependencies come back out in their original sequence with only the
    pinned version strings changed. We key the rewrite off ``raw_line`` to be
    sure we touch the same entry the parser saw, then preserve any ``=``/``v``
    prefix the original spec carried.
    """
    data = json.loads(manifest)
    # raw_line -> (name, new_version), so we can locate the entry by name.
    by_name = {
        pkg.raw_line: (pkg.name, new_version)
        for raw_line, new_version in rewrites.items()
        for pkg in [_find_by_raw_line(package_by_name, raw_line)]
        if pkg is not None
    }
    targets = {name: new_version for name, new_version in by_name.values()}

    for section in ("dependencies", "devDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if name in targets:
                deps[name] = _apply_npm_version(str(spec), targets[name])

    # Match the conventional 2-space package.json indentation and trailing EOL.
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def _find_by_raw_line(
    package_by_name: dict[str, ParsedPackage], raw_line: str
) -> ParsedPackage | None:
    """Find the package whose ``raw_line`` equals ``raw_line``."""
    for pkg in package_by_name.values():
        if pkg.raw_line == raw_line:
            return pkg
    return None


def _apply_npm_version(old_spec: str, new_version: str) -> str:
    """Swap the version in an exact npm pin, preserving a leading ``=``/``v``.

    Only exact pins reach here (range specs are never scheduled for rewrite), so
    the spec is at most ``=``/``v`` followed by a concrete version. We keep that
    prefix and substitute the version, so ``=1.2.3`` -> ``=1.2.4``.
    """
    prefix = ""
    rest = old_spec.strip()
    if rest.startswith("="):
        prefix += "="
        rest = rest[1:]
    if rest[:1] in ("v", "V"):
        prefix += rest[0]
    return prefix + new_version
