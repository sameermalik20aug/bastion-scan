"""Security-response-header middleware.

Bastion is a security tool, so it should model good hygiene: every response
carries a small set of hardening headers. None of these change the API's
behaviour for a well-behaved client — they instruct browsers to refuse a set of
downgrade / injection / clickjacking attacks.

The header set is deliberately strict because the API only ever returns JSON: it
has no HTML, scripts, styles, or framing of its own to permit. The frontend is a
separate origin with its own (looser) CSP.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# A locked-down CSP for a pure-JSON API: nothing is allowed to load, and the
# responses may not be framed. There is no legitimate document content here, so
# "deny everything" is both correct and the safest default.
_CONTENT_SECURITY_POLICY = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"

# Two years, apply to subdomains. Browsers ignore this over plain HTTP, so it is
# safe to always send; it only takes effect once a response arrives over HTTPS.
_HSTS_VALUE = "max-age=63072000; includeSubDomains"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach hardening headers to every response."""

    def __init__(self, app: Callable, *, hsts_enabled: bool = True) -> None:
        super().__init__(app)
        self._hsts_enabled = hsts_enabled

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        headers = response.headers

        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("Referrer-Policy", "no-referrer")

        # The interactive docs (/docs, /redoc) and the schema are the only HTML
        # this app serves, and they load Swagger UI assets from a CDN. The strict
        # JSON-API CSP would blank them out, so skip the locking headers there.
        docs_paths = ("/docs", "/redoc", "/openapi.json")
        if not request.url.path.startswith(docs_paths):
            headers.setdefault("X-Frame-Options", "DENY")
            headers.setdefault("Content-Security-Policy", _CONTENT_SECURITY_POLICY)
            if self._hsts_enabled:
                headers.setdefault("Strict-Transport-Security", _HSTS_VALUE)

        return response
