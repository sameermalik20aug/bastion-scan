"""HTTP routes for the scan API.

The single endpoint here, ``POST /api/v1/scan``, accepts a dependency manifest
two ways — a multipart file upload, or a JSON body carrying the raw text plus an
ecosystem hint — and runs the full pipeline: parse -> OSV lookup -> deterministic
fixer -> optional AI enrichment. It returns a :class:`ScanResult`.

Three cross-cutting concerns shape this module:

* **Body-size cap.** A huge upload must not tie up a worker. We reject anything
  over :data:`MAX_BODY_BYTES`, both up front via ``Content-Length`` and again
  against the bytes actually read (a client can lie about, or omit, the header).
* **Rate limiting.** Each client IP gets 10 scans per minute (slowapi). Over the
  limit returns a clean 429 with a helpful message (handler in ``main``).
* **Bring-your-own-key.** The optional Anthropic key arrives in the
  ``X-Anthropic-Key`` header, is read at the last moment, and is passed straight
  into the AI layer for this request only. It is never logged here, and never
  stored. We do not add request-logging middleware; if any is added later, it
  must exclude :data:`ANTHROPIC_KEY_HEADER`.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.datastructures import UploadFile

from app.models.schemas import Ecosystem, PackageResult, ScanResult, Vulnerability
from app.parsers import available_ecosystems, get_parser
from app.parsers.base import ParseError
from app.services.ai_service import enrich_scan
from app.services.fixer import FixSuggestion, suggest_fixes
from app.services.osv_client import OsvUnavailableError, osv_client

# Reject manifests larger than ~1 MB. Real package.json / requirements.txt files
# are far smaller; anything bigger is almost certainly abuse or a mistake, and
# parsing it would tie up the worker.
MAX_BODY_BYTES = 1_000_000

# The header carrying the user's Anthropic key. Read at the edge, handed to the
# AI layer, never logged or persisted. Kept as a constant so any future logging
# middleware can reference it as an exclusion.
ANTHROPIC_KEY_HEADER = "X-Anthropic-Key"

# Shared limiter, keyed by client IP. Registered on the app (and given its
# exception handler) in ``app.main``.
limiter = Limiter(key_func=get_remote_address)

router = APIRouter()

# Accepted ecosystem hints (case-insensitive) -> the canonical OSV identifier.
# Includes a few common synonyms and the manifest filenames themselves.
_ECOSYSTEM_ALIASES: dict[str, Ecosystem] = {
    "npm": "npm",
    "node": "npm",
    "nodejs": "npm",
    "package.json": "npm",
    "pypi": "PyPI",
    "python": "PyPI",
    "pip": "PyPI",
    "requirements": "PyPI",
    "requirements.txt": "PyPI",
    "maven": "Maven",
    "java": "Maven",
    "rubygems": "RubyGems",
    "ruby": "RubyGems",
    "gem": "RubyGems",
}


@router.post("/scan", response_model=ScanResult)
@limiter.limit("10/minute")
async def scan(request: Request) -> ScanResult:
    """Scan an uploaded manifest for known vulnerabilities.

    Accepts either ``multipart/form-data`` with a ``file`` part (and optional
    ``ecosystem`` field), or ``application/json`` with ``{"content": ...,
    "ecosystem": ...}``. The ecosystem is auto-detected from the filename and
    content; an explicit hint overrides the detection.
    """
    content, ecosystem_hint, filename = await _read_input(request)
    ecosystem = _detect_ecosystem(content=content, filename=filename, hint=ecosystem_hint)

    parser = get_parser(ecosystem)
    try:
        packages = parser.parse(content)
    except ParseError as exc:
        raise HTTPException(status_code=422, detail=f"could not parse manifest: {exc}") from exc

    try:
        vulnerabilities = await osv_client.find_vulnerabilities(packages, ecosystem)
    except OsvUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    # The fixer is the deterministic authority on which version is safe and
    # whether the upgrade is breaking. Merge its decisions onto the findings.
    fix_result = suggest_fixes(
        ecosystem=ecosystem,
        manifest=content,
        packages=packages,
        vulnerabilities=vulnerabilities,
    )
    scan_result = _build_scan_result(ecosystem, packages, vulnerabilities, fix_result)

    # Optional AI enrichment. The key is read here, at the last moment, and used
    # only for this request. With no key, enrichment is a no-op.
    api_key = request.headers.get(ANTHROPIC_KEY_HEADER)
    return await enrich_scan(scan_result=scan_result, api_key=api_key)


# --------------------------------------------------------------------------- #
# Input handling
# --------------------------------------------------------------------------- #


async def _read_input(request: Request) -> tuple[str, str | None, str | None]:
    """Extract ``(content, ecosystem_hint, filename)`` from the request.

    Branches on ``Content-Type``: a multipart upload yields the file bytes and an
    optional ``ecosystem`` form field; a JSON body yields ``content`` and an
    optional ``ecosystem`` key. Enforces the body-size cap in both paths.
    """
    content_type = request.headers.get("content-type", "")
    # Cheap rejection before reading the body, when the client declares a size.
    _reject_if_too_large(request.headers.get("content-length"))

    if content_type.startswith("multipart/form-data"):
        return await _read_multipart(request)
    if content_type.startswith("application/json"):
        return await _read_json(request)

    raise HTTPException(
        status_code=415,
        detail=(
            "send multipart/form-data with a 'file' part, or application/json "
            "with a 'content' field"
        ),
    )


async def _read_multipart(request: Request) -> tuple[str, str | None, str | None]:
    """Read the ``file`` part and optional ``ecosystem`` field from a form."""
    form = await request.form()
    upload = form.get("file")
    if not isinstance(upload, UploadFile):
        raise HTTPException(status_code=422, detail="multipart body must include a 'file' part")

    raw = await upload.read()
    # Re-check against the bytes actually read: Content-Length may be absent or
    # understated, so the header check above is not sufficient on its own.
    _reject_if_too_large(len(raw))
    text = _decode_utf8(raw)

    hint = form.get("ecosystem")
    ecosystem_hint = str(hint) if isinstance(hint, str) and hint.strip() else None
    return text, ecosystem_hint, upload.filename


async def _read_json(request: Request) -> tuple[str, str | None, str | None]:
    """Read ``content`` and optional ``ecosystem`` from a JSON body."""
    body = await request.body()
    _reject_if_too_large(len(body))
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="request body must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="JSON body must be an object")

    content = payload.get("content")
    if not isinstance(content, str) or not content.strip():
        raise HTTPException(status_code=422, detail="JSON body must include non-empty 'content'")

    hint = payload.get("ecosystem")
    ecosystem_hint = str(hint) if isinstance(hint, str) and hint.strip() else None
    return content, ecosystem_hint, None


def _reject_if_too_large(size: str | int | None) -> None:
    """Raise 413 if a declared or measured body size exceeds the cap."""
    if size is None:
        return
    try:
        value = int(size)
    except (TypeError, ValueError):
        return
    if value > MAX_BODY_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"manifest too large (limit {MAX_BODY_BYTES} bytes)",
        )


def _decode_utf8(raw: bytes) -> str:
    """Decode uploaded bytes as UTF-8, or 422 if they aren't text."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=422, detail="uploaded file must be UTF-8 text") from exc


# --------------------------------------------------------------------------- #
# Ecosystem detection
# --------------------------------------------------------------------------- #


def _detect_ecosystem(*, content: str, filename: str | None, hint: str | None) -> Ecosystem:
    """Resolve the ecosystem from the hint, then the filename, then the content.

    A hint always wins when it names a known ecosystem. Otherwise we look at the
    filename (``package.json`` -> npm, ``requirements*.txt`` -> PyPI), then sniff
    the content (a leading ``{`` looks like ``package.json``). The resolved
    ecosystem must have a registered parser, or we 422.
    """
    ecosystem = _from_hint(hint) or _from_filename(filename) or _from_content(content)

    if ecosystem not in available_ecosystems():
        raise HTTPException(
            status_code=422,
            detail=(
                f"no parser available for ecosystem {ecosystem!r}; "
                f"supported: {sorted(available_ecosystems())}"
            ),
        )
    return ecosystem


def _from_hint(hint: str | None) -> Ecosystem | None:
    """Map an explicit ecosystem hint to a canonical identifier, or 422."""
    if not hint:
        return None
    resolved = _ECOSYSTEM_ALIASES.get(hint.strip().lower())
    if resolved is None:
        raise HTTPException(
            status_code=422,
            detail=f"unknown ecosystem hint {hint!r}; try one of npm, PyPI",
        )
    return resolved


def _from_filename(filename: str | None) -> Ecosystem | None:
    """Infer the ecosystem from a manifest filename, if recognizable."""
    if not filename:
        return None
    lowered = filename.lower()
    if lowered.endswith("package.json"):
        return "npm"
    if "requirements" in lowered and lowered.endswith(".txt"):
        return "PyPI"
    return None


def _from_content(content: str) -> Ecosystem:
    """Sniff the ecosystem from the manifest body as a last resort.

    A leading ``{`` is the signature of a JSON ``package.json``; everything else
    is treated as a line-based ``requirements.txt``.
    """
    return "npm" if content.lstrip().startswith("{") else "PyPI"


# --------------------------------------------------------------------------- #
# Result assembly
# --------------------------------------------------------------------------- #


def _build_scan_result(
    ecosystem: Ecosystem,
    packages: list,
    vulnerabilities: list[Vulnerability],
    fix_result,
) -> ScanResult:
    """Assemble a :class:`ScanResult` from packages, findings, and fixer output.

    Each vulnerability is grouped under its package, and the fixer's per-package
    decision (the suggested safe version and whether it is a breaking upgrade) is
    merged onto every finding for that package — the fixer, not the model, owns
    the choice of version.
    """
    suggestion_by_package: dict[str, FixSuggestion] = {
        suggestion.package: suggestion for suggestion in fix_result.suggestions
    }

    vulns_by_package: dict[str, list[Vulnerability]] = {}
    for vuln in vulnerabilities:
        suggestion = suggestion_by_package.get(vuln.package)
        if suggestion is not None:
            vuln.is_breaking_upgrade = suggestion.is_breaking_upgrade
            if suggestion.suggested_version is not None:
                vuln.fixed_version = suggestion.suggested_version
        vulns_by_package.setdefault(vuln.package, []).append(vuln)

    package_results = [
        PackageResult(
            name=pkg.name,
            version=pkg.version,
            is_direct=pkg.is_direct,
            vulnerabilities=vulns_by_package.get(pkg.name, []),
        )
        for pkg in packages
    ]

    # Only surface a rewritten manifest when the fixer actually changed something.
    fixed_manifest = fix_result.manifest if fix_result.manifest != "" else None
    if fixed_manifest is not None and not any(s.applied for s in fix_result.suggestions):
        fixed_manifest = None

    return ScanResult(
        ecosystem=ecosystem,
        packages=package_results,
        total_packages=len(packages),
        total_vulnerabilities=len(vulnerabilities),
        fixed_manifest=fixed_manifest,
        fix_notice=fix_result.notice,
        executive_summary=None,
    )
