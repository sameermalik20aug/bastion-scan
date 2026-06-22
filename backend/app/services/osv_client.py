"""Client for the OSV.dev vulnerability database.

OSV.dev is queried in two steps because its endpoints split cheap matching
from expensive detail lookup:

1. ``POST /v1/querybatch`` takes *many* package queries in a single request and
   returns, per query, only the vulnerability **IDs** (and a ``modified``
   timestamp) that affect that exact version — no summaries, no severities, no
   fix data.
2. ``GET /v1/vulns/{id}`` returns the full OSV record for one vulnerability.

So we batch-match every package in one round trip, collect the unique IDs, then
fan out to fetch the details we actually need. See the module-level notes at the
bottom of this file for why this shape matters and how the fixed version is
pulled out of OSV's affected-ranges schema.
"""

from __future__ import annotations

import asyncio
import contextlib
import math
from collections.abc import AsyncIterator, Iterable

import httpx
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from app.models.schemas import Ecosystem, ParsedPackage, Severity, Vulnerability

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"

# OSV occasionally takes several seconds; cap it so a slow database surfaces as a
# clean 503 instead of an indefinitely hanging request.
DEFAULT_TIMEOUT = 10.0


class OsvUnavailableError(Exception):
    """OSV.dev was unreachable, timed out, or returned an unusable response.

    The API layer maps this to a 503 ("vulnerability database unavailable, try
    again"). It deliberately does *not* cover "this package simply has no known
    vulnerabilities" — that's an empty result, not an error.
    """


# --------------------------------------------------------------------------- #
# Severity derivation
#
# OSV records carry severity inconsistently. Some have a CVSS vector in the
# `severity` array, some only a rating string in a GitHub advisory's
# `database_specific` block, some nothing at all. derive_severity() tries each
# source in turn so the severity-sorted report doesn't collapse to "unknown".
# --------------------------------------------------------------------------- #

# GitHub advisory ratings -> our internal bands. GHSA uses "MODERATE" where most
# other sources say "MEDIUM".
_LABEL_MAP: dict[str, Severity] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}


def _band(score: float) -> Severity:
    """Band a 0–10 CVSS base score using the CVSS v3 qualitative ranges."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _roundup(value: float) -> float:
    """Round up to one decimal place per the CVSS v3.1 specification.

    Plain ``round()`` would give the wrong score on values like 4.02 (CVSS
    rounds that up to 4.1, not 4.0).
    """
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000
    return (math.floor(int_input / 10_000) + 1) / 10


def _cvss_v3_base_score(vector: str) -> float | None:
    """Compute the CVSS v3.x base score from a vector string.

    OSV stores CVSS as the *vector* (e.g. ``CVSS:3.1/AV:N/AC:L/...``), not a
    number, so to band a score we have to derive it. Returns ``None`` if the
    vector is missing a required base metric (e.g. it's a temporal-only string).
    """
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        key, sep, val = part.partition(":")
        if sep:
            metrics[key] = val

    try:
        attack_vector = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        attack_complexity = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        user_interaction = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        scope_changed = metrics["S"] == "C"
        # Privileges Required is weighted differently when scope changes.
        if scope_changed:
            privileges = {"N": 0.85, "L": 0.68, "H": 0.5}[metrics["PR"]]
        else:
            privileges = {"N": 0.85, "L": 0.62, "H": 0.27}[metrics["PR"]]
        impact_weights = {"H": 0.56, "L": 0.22, "N": 0.0}
        conf = impact_weights[metrics["C"]]
        integ = impact_weights[metrics["I"]]
        avail = impact_weights[metrics["A"]]
    except KeyError:
        return None

    iss = 1 - (1 - conf) * (1 - integ) * (1 - avail)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * attack_vector * attack_complexity * privileges * user_interaction
    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10)
    else:
        base = min(impact + exploitability, 10)
    return _roundup(base)


def _score_from_severity_entry(entry: dict) -> float | None:
    """Pull a numeric score out of one OSV ``severity`` array entry."""
    score = entry.get("score")
    if not score:
        return None
    # A few sources record a bare number; most record a CVSS vector string.
    try:
        return float(score)
    except (TypeError, ValueError):
        pass
    severity_type = str(entry.get("type") or "").upper()
    if severity_type.startswith("CVSS_V3"):
        return _cvss_v3_base_score(str(score))
    # CVSS v2/v4 base-score math is intentionally not implemented; those records
    # fall through to the database_specific rating below rather than to
    # "unknown", which is good enough for banding.
    return None


def _max_cvss_score(vuln: dict) -> float | None:
    """Highest CVSS score across the record's severity arrays, or ``None``.

    Severity entries live both at the top level and per-affected-package, so we
    scan both and take the most severe.
    """
    entries: list[dict] = list(vuln.get("severity") or [])
    for affected in vuln.get("affected") or []:
        entries.extend(affected.get("severity") or [])

    scores = [s for entry in entries if (s := _score_from_severity_entry(entry)) is not None]
    return max(scores) if scores else None


def _database_specific_severity(vuln: dict) -> Severity | None:
    """Map a ``database_specific.severity`` rating string to a band, if present."""
    candidates: list[str] = []
    top = vuln.get("database_specific")
    if isinstance(top, dict) and top.get("severity"):
        candidates.append(top["severity"])
    for affected in vuln.get("affected") or []:
        spec = affected.get("database_specific")
        if isinstance(spec, dict) and spec.get("severity"):
            candidates.append(spec["severity"])

    for raw in candidates:
        mapped = _LABEL_MAP.get(str(raw).strip().upper())
        if mapped:
            return mapped
    return None


def derive_severity(vuln: dict) -> Severity:
    """Best-effort severity for an OSV record.

    Tries, in order: (1) a CVSS score from the ``severity`` array, banded;
    (2) a ``database_specific.severity`` rating string; (3) ``"unknown"``.
    """
    score = _max_cvss_score(vuln)
    if score is not None:
        return _band(score)
    label = _database_specific_severity(vuln)
    if label is not None:
        return label
    return "unknown"


# --------------------------------------------------------------------------- #
# Fixed-version extraction
# --------------------------------------------------------------------------- #


def _parse_version(value: str) -> Version | None:
    """Parse a version for comparison, or ``None`` if it isn't PEP 440-parseable."""
    try:
        return Version(value)
    except (InvalidVersion, TypeError):
        return None


def _names_match(a: str, b: str, ecosystem: Ecosystem) -> bool:
    """Whether two package names refer to the same package in this ecosystem."""
    if ecosystem == "PyPI":
        return canonicalize_name(a) == canonicalize_name(b)
    return a.lower() == b.lower()


def _extract_fixed_version(
    vuln: dict, ecosystem: Ecosystem, name: str, current_version: str
) -> str | None:
    """Pull the version that fixes this vuln out of OSV's affected ranges.

    Each ``affected`` entry has ``ranges``; each range has an ``events`` list of
    ``{"introduced": ...}`` / ``{"fixed": ...}`` markers describing the vulnerable
    interval(s). We collect every ``fixed`` version from ranges matching our
    package and pick the smallest fix strictly greater than the installed
    version (the closest safe upgrade). Git ranges are skipped — they reference
    commit hashes, not versions.
    """
    fixes: list[str] = []
    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") or {}
        # OSV may suffix the ecosystem (e.g. "Debian:11"); compare the base.
        aff_ecosystem = str(pkg.get("ecosystem") or "").split(":", 1)[0]
        if aff_ecosystem != ecosystem:
            continue
        if not _names_match(str(pkg.get("name") or ""), name, ecosystem):
            continue
        for rng in affected.get("ranges") or []:
            if rng.get("type") == "GIT":
                continue
            for event in rng.get("events") or []:
                fixed = event.get("fixed")
                if fixed:
                    fixes.append(fixed)

    if not fixes:
        return None

    current = _parse_version(current_version)
    parsed = [(p, raw) for raw in fixes if (p := _parse_version(raw)) is not None]

    if current is not None:
        ahead = [(p, raw) for p, raw in parsed if p > current]
        if ahead:
            return min(ahead, key=lambda t: t[0])[1]
    if parsed:
        return min(parsed, key=lambda t: t[0])[1]
    # Nothing was version-comparable; surface the first fix verbatim.
    return fixes[0]


# --------------------------------------------------------------------------- #
# Concrete-version filtering
# --------------------------------------------------------------------------- #

# Characters that only appear in ranges, wildcards, or unresolvable specs. A
# querybatch query needs one concrete version, so anything carrying these is
# skipped rather than sent.
_RANGE_CHARS = set(" \t<>=~^*|,:/")


def _is_concrete_version(version: str) -> bool:
    """Whether ``version`` names a single concrete release we can query.

    Parsers leave unpinned/ranged dependencies with their raw spec string (e.g.
    ``>=1.26``, ``^4.17.21``, ``*``, ``latest``). Those can't be queried against
    a concrete version, so they're filtered out here.
    """
    if not version:
        return False
    if any(ch in _RANGE_CHARS for ch in version):
        return False
    # Concrete releases start with a digit; this rejects dist-tags ("latest"),
    # git shorthands, and similar that slip past the character check.
    return version[0].isdigit()


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #


class OsvClient:
    """Async client for OSV.dev with an in-memory result cache.

    A single instance can be shared across requests; its cache persists for the
    process lifetime, keyed by ``(ecosystem, package, version)``.
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        *,
        client: httpx.AsyncClient | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._timeout = timeout
        # An injected client/transport is for tests; production builds its own.
        self._client = client
        self._transport = transport
        self._cache: dict[tuple[Ecosystem, str, str], list[Vulnerability]] = {}

    @contextlib.asynccontextmanager
    async def _open_client(self) -> AsyncIterator[httpx.AsyncClient]:
        """Yield an HTTP/2 client, reusing an injected one if provided."""
        if self._client is not None:
            yield self._client
            return
        # http2=True multiplexes the batch call and every per-id fetch over one
        # connection; it needs the `h2` package (installed via httpx[http2]).
        async with httpx.AsyncClient(
            http2=True, timeout=self._timeout, transport=self._transport
        ) as client:
            yield client

    async def find_vulnerabilities(
        self, packages: Iterable[ParsedPackage], ecosystem: Ecosystem
    ) -> list[Vulnerability]:
        """Return every known vulnerability affecting ``packages``.

        Unpinned/ranged packages are skipped (no concrete version to query).
        Cached packages are served from memory; the rest go through the
        two-step querybatch -> per-id fetch flow.

        Raises:
            OsvUnavailableError: OSV was unreachable, timed out, or returned an
                unparseable response.
        """
        results: list[Vulnerability] = []
        to_query: list[ParsedPackage] = []

        for pkg in packages:
            if not _is_concrete_version(pkg.version):
                continue
            cached = self._cache.get((ecosystem, pkg.name, pkg.version))
            if cached is not None:
                results.extend(cached)
            else:
                to_query.append(pkg)

        if not to_query:
            return results

        async with self._open_client() as client:
            id_lists = await self._querybatch(client, to_query, ecosystem)
            unique_ids = {vuln_id for ids in id_lists for vuln_id in ids}
            details = await self._fetch_details(client, unique_ids)

        for pkg, ids in zip(to_query, id_lists, strict=True):
            vulns = [
                _build_vulnerability(details[vuln_id], pkg, ecosystem)
                for vuln_id in ids
                # A detail fetch may have 404'd (partial failure); skip it.
                if details.get(vuln_id) is not None
            ]
            self._cache[(ecosystem, pkg.name, pkg.version)] = vulns
            results.extend(vulns)

        return results

    async def _querybatch(
        self, client: httpx.AsyncClient, packages: list[ParsedPackage], ecosystem: Ecosystem
    ) -> list[list[str]]:
        """Step 1: match every package in one request, returning IDs per package.

        OSV returns ``results`` aligned 1:1 and in order with the queries we
        sent, so the index maps a result back to its package.
        """
        payload = {
            "queries": [
                {"package": {"name": pkg.name, "ecosystem": ecosystem}, "version": pkg.version}
                for pkg in packages
            ]
        }
        try:
            response = await client.post(OSV_QUERYBATCH_URL, json=payload)
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            # Timeout, connection failure, non-2xx, or bad JSON: without the
            # batch we have nothing to report on, so treat it all as "down".
            raise OsvUnavailableError("vulnerability database unavailable, try again") from exc

        id_lists: list[list[str]] = []
        for entry in data.get("results") or []:
            vulns = entry.get("vulns") or []
            id_lists.append([v["id"] for v in vulns if v.get("id")])
        # Defensive: pad if OSV returned fewer result objects than queries.
        while len(id_lists) < len(packages):
            id_lists.append([])
        return id_lists

    async def _fetch_details(
        self, client: httpx.AsyncClient, ids: Iterable[str]
    ) -> dict[str, dict | None]:
        """Step 2: fetch the full record for each unique vuln ID, concurrently.

        A single ID that 404s/5xxs is a partial failure — that entry maps to
        ``None`` and is dropped. A timeout or connection error, by contrast,
        means OSV itself is down and propagates as :class:`OsvUnavailableError`.
        """

        async def fetch(vuln_id: str) -> tuple[str, dict | None]:
            try:
                response = await client.get(OSV_VULN_URL.format(vuln_id=vuln_id))
                response.raise_for_status()
            except httpx.HTTPStatusError:
                return vuln_id, None
            return vuln_id, response.json()

        try:
            pairs = await asyncio.gather(*(fetch(vuln_id) for vuln_id in ids))
        except (httpx.TransportError, httpx.HTTPError, ValueError) as exc:
            raise OsvUnavailableError("vulnerability database unavailable, try again") from exc
        return dict(pairs)


def _build_vulnerability(
    detail: dict, pkg: ParsedPackage, ecosystem: Ecosystem
) -> Vulnerability:
    """Turn one OSV record + the package it affects into a Vulnerability."""
    return Vulnerability(
        id=detail.get("id", "UNKNOWN"),
        package=pkg.name,
        current_version=pkg.version,
        severity=derive_severity(detail),
        summary=detail.get("summary") or detail.get("details") or "",
        is_direct=pkg.is_direct,
        fixed_version=_extract_fixed_version(detail, ecosystem, pkg.name, pkg.version),
    )


# A shared, process-wide instance so the cache survives across requests.
osv_client = OsvClient()
