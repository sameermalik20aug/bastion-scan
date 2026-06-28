"""Parser for Python ``requirements.txt`` files."""

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from app.models.schemas import ParsedPackage
from app.parsers import register_parser
from app.parsers.base import BaseParser, ParseError

# Option lines we skip rather than treat as requirements. ``-r``/``-c`` pull in
# other files (we don't recurse for now); the rest are pip flags, not packages.
_SKIP_PREFIXES = ("-r", "--requirement", "-c", "--constraint")


def _strip_inline_comment(line: str) -> str:
    """Drop a trailing ``# ...`` comment.

    pip only treats ``#`` as a comment when it's at the start of the line or
    preceded by whitespace, so an embedded ``#`` (rare, but legal in some
    specifiers) isn't clobbered.
    """
    if line.startswith("#"):
        return ""
    idx = line.find(" #")
    if idx != -1:
        return line[:idx]
    return line


def _pinned_version(req: Requirement) -> str | None:
    """Return the exact version if the requirement is pinned with ``==``.

    Returns ``None`` for ranges (``>=1.0``, ``~=1.4``), wildcard pins
    (``==2.0.*``), or unpinned requirements — none of which name a single
    installed version.
    """
    specs = list(req.specifier)
    if len(specs) != 1:
        return None
    spec = specs[0]
    if spec.operator not in ("==", "==="):
        return None
    if "*" in spec.version:
        return None
    return spec.version


@register_parser
class PypiParser(BaseParser):
    """Parse a ``requirements.txt`` into packages.

    Every entry is treated as direct: a flat requirements file doesn't record
    which packages are top-level versus pulled in transitively.
    """

    ecosystem = "PyPI"

    def parse(self, content: str) -> list[ParsedPackage]:
        packages: list[ParsedPackage] = []
        for raw_line in content.splitlines():
            line = _strip_inline_comment(raw_line).strip()
            if not line:
                continue
            # Skip includes (no recursion) and any other pip option line.
            if line.startswith(_SKIP_PREFIXES) or line.startswith("-"):
                continue

            try:
                # Requirement parses the name, specifier set, extras, and any
                # ``; python_version < "3.8"`` environment marker.
                req = Requirement(line)
            except InvalidRequirement as exc:
                raise ParseError(f"invalid requirement {raw_line.strip()!r}: {exc}") from exc

            pinned = _pinned_version(req)
            packages.append(
                ParsedPackage(
                    # OSV's PyPI ecosystem uses PEP 503 normalized names.
                    name=canonicalize_name(req.name),
                    # Unresolvable specs keep their raw form (or ``*`` when
                    # unpinned) so downstream can detect and skip them.
                    version=pinned if pinned is not None else (str(req.specifier) or "*"),
                    is_direct=True,
                    raw_line=raw_line.strip(),
                )
            )
        return packages
