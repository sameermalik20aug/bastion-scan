"""Parser for npm ``package.json`` manifests."""

import json
import re

from app.models.schemas import ParsedPackage
from app.parsers import register_parser
from app.parsers.base import BaseParser, ParseError

# A concrete-ish version: 1, 1.2 or 1.2.3, optionally with a prerelease
# (``-beta.1``) or build metadata (``+exp.sha``). This is what survives after we
# strip a leading range operator from a spec like ``^1.2.3``.
_CONCRETE_VERSION = re.compile(r"^\d+(?:\.\d+){0,2}(?:[-+][0-9A-Za-z.\-+]+)?$")

# Spec values that aren't a version at all: a tarball/git/local/workspace
# reference, or a dist-tag. These can never be resolved from the manifest alone.
_NON_VERSION_PREFIXES = (
    "git+",
    "git:",
    "github:",
    "gitlab:",
    "bitbucket:",
    "http:",
    "https:",
    "file:",
    "link:",
    "portal:",
    "workspace:",
    "npm:",
    "patch:",
)
_DIST_TAGS = {"latest", "next", "*", "x", "", "rc"}


def _resolve_version(spec: str) -> str | None:
    """Reduce an npm version spec to a single concrete version.

    Returns the concrete version string if the spec pins to one (``^1.2.3`` ->
    ``1.2.3``, ``=2.0.0`` -> ``2.0.0``), or ``None`` if the spec is a range,
    wildcard, dist-tag, or a non-registry reference (git/url/workspace/etc.) —
    i.e. anything downstream can't treat as a single installed version.
    """
    spec = spec.strip()
    if spec.lower() in _DIST_TAGS:
        return None
    if spec.startswith(_NON_VERSION_PREFIXES) or "/" in spec:
        return None
    # Compound ranges: ``>=1 <2``, ``1.x || 2.x``, ``1.0.0 - 2.0.0``. Any of
    # these constructs contain whitespace or ``||``, so they're not a single pin.
    if " " in spec or "||" in spec:
        return None
    # Strip a single leading range operator: ^, ~, >=, <=, >, <, =, and an
    # optional ``v`` prefix (``v1.2.3``).
    candidate = spec.lstrip("^~<>=")
    if candidate[:1] in ("v", "V"):
        candidate = candidate[1:]
    if _CONCRETE_VERSION.match(candidate):
        return candidate
    # Wildcards (``1.x``, ``1.2.*``) and anything else: not concrete.
    return None


@register_parser
class NpmParser(BaseParser):
    """Parse a ``package.json``'s direct and dev dependencies."""

    ecosystem = "npm"

    def parse(self, content: str) -> list[ParsedPackage]:
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ParseError(f"package.json is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ParseError("package.json must contain a top-level JSON object")

        packages: list[ParsedPackage] = []
        # `dependencies` are shipped to production (direct); `devDependencies`
        # are build/test-only (not direct runtime deps).
        for section, is_direct in (("dependencies", True), ("devDependencies", False)):
            deps = data.get(section)
            if deps is None:
                continue
            if not isinstance(deps, dict):
                raise ParseError(f"'{section}' must be a JSON object of name -> version")
            for name, raw_spec in deps.items():
                # npm allows non-string values to creep in; coerce defensively so
                # we flag rather than crash.
                raw_spec = "" if raw_spec is None else str(raw_spec)
                resolved = _resolve_version(raw_spec)
                packages.append(
                    ParsedPackage(
                        name=name,
                        # Flagged (unresolvable) specs keep the raw string so
                        # downstream can detect and skip them.
                        version=resolved if resolved is not None else raw_spec,
                        is_direct=is_direct,
                        raw_line=f'"{name}": "{raw_spec}"',
                    )
                )
        return packages
