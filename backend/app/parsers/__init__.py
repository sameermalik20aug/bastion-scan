"""Parser registry.

Maps an OSV ecosystem string to the parser class that handles it. Concrete
parsers register themselves with :func:`register_parser` (typically via the
``@register_parser`` decorator) and are looked up with :func:`get_parser`.
"""

from app.models.schemas import Ecosystem
from app.parsers.base import BaseParser

_REGISTRY: dict[Ecosystem, type[BaseParser]] = {}


def register_parser(parser_cls: type[BaseParser]) -> type[BaseParser]:
    """Register a parser class under its declared ecosystem.

    Intended for use as a class decorator::

        @register_parser
        class NpmParser(BaseParser):
            ecosystem = "npm"
            ...
    """
    ecosystem = getattr(parser_cls, "ecosystem", None)
    if ecosystem is None:
        raise ValueError(f"{parser_cls.__name__} must declare an 'ecosystem' attribute")
    if ecosystem in _REGISTRY:
        raise ValueError(
            f"Ecosystem {ecosystem!r} already registered to {_REGISTRY[ecosystem].__name__}"
        )
    _REGISTRY[ecosystem] = parser_cls
    return parser_cls


def get_parser(ecosystem: Ecosystem) -> BaseParser:
    """Return a parser instance for the given ecosystem.

    Raises:
        KeyError: If no parser is registered for the ecosystem.
    """
    try:
        parser_cls = _REGISTRY[ecosystem]
    except KeyError as exc:
        raise KeyError(f"No parser registered for ecosystem {ecosystem!r}") from exc
    return parser_cls()


def available_ecosystems() -> list[Ecosystem]:
    """Return the ecosystems that currently have a registered parser."""
    return list(_REGISTRY)


# Import concrete parsers for their @register_parser side effects. These come
# last so register_parser is defined before the modules import it back.
from app.parsers import npm, pypi  # noqa: E402,F401
