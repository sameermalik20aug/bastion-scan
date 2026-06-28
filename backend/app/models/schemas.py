from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "unknown"]

# OSV uses exact, case-sensitive ecosystem identifiers. Keep this casing as-is.
Ecosystem = Literal["npm", "PyPI", "Maven", "RubyGems"]


class ParsedPackage(BaseModel):
    """A single dependency extracted from a manifest by a parser."""

    name: str
    version: str
    is_direct: bool
    # The original manifest line this package came from. Lets the fixer rewrite
    # the manifest in place while preserving the user's formatting.
    raw_line: str | None = None


class Vulnerability(BaseModel):
    """A known vulnerability affecting a specific package version."""

    id: str
    package: str
    current_version: str
    severity: Severity
    summary: str
    ai_explanation: str | None = None
    is_direct: bool
    fixed_version: str | None = None
    is_breaking_upgrade: bool = False


class PackageResult(BaseModel):
    """Scan outcome for one package: its metadata plus any vulnerabilities found."""

    name: str
    version: str
    is_direct: bool
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)


class ScanResult(BaseModel):
    """The full result of scanning one manifest."""

    ecosystem: Ecosystem
    packages: list[PackageResult] = Field(default_factory=list)
    total_packages: int = 0
    total_vulnerabilities: int = 0
    # The fixer's regenerated manifest with suggested safe versions substituted
    # in (``None`` when nothing could be rewritten), plus the review framing.
    fixed_manifest: str | None = None
    fix_notice: str | None = None
    # One-paragraph AI overview of the whole scan. ``None`` when no Anthropic key
    # was supplied or the summary call failed — the scan is still complete.
    executive_summary: str | None = None
