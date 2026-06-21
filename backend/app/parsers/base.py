from abc import ABC, abstractmethod

from app.models.schemas import Ecosystem, ParsedPackage


class ParseError(Exception):
    """Raised when a manifest is malformed and cannot be parsed.

    Parsers raise this (rather than letting an arbitrary lower-level exception
    propagate) so callers have a single, well-defined error type to catch when a
    user uploads a corrupt or unsupported manifest.
    """


class BaseParser(ABC):
    """Abstract base for manifest parsers.

    Each concrete parser handles one ecosystem's manifest format (e.g.
    package-lock.json, requirements.txt) and turns its raw text into a list of
    :class:`ParsedPackage` instances.
    """

    #: The OSV ecosystem string this parser produces packages for. Subclasses
    #: must set this to one of the values allowed by :data:`Ecosystem`.
    ecosystem: Ecosystem

    @abstractmethod
    def parse(self, content: str) -> list[ParsedPackage]:
        """Parse raw manifest text into a list of packages.

        Args:
            content: The full text of the manifest file.

        Returns:
            One :class:`ParsedPackage` per dependency found.
        """
        raise NotImplementedError
