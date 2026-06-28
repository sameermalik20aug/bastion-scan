from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from app.api.routes import ANTHROPIC_KEY_HEADER, limiter, router
from app.core.config import settings
from app.core.security_headers import SecurityHeadersMiddleware

app = FastAPI(title=settings.app_name)

# Hardening headers on every response (see SecurityHeadersMiddleware). Added
# before CORS so CORS runs outermost and can still answer preflight requests.
app.add_middleware(SecurityHeadersMiddleware, hsts_enabled=settings.hsts_enabled)

# CORS. The frontend is deployed on a different origin than the API, so browsers
# enforce CORS on every scan request. We allow only the configured origin(s) —
# never "*" — because requests carry the user's Anthropic key in a custom header,
# and that must only be accepted from frontends we trust. POST covers /scan;
# OPTIONS is the preflight the browser sends because of the custom key header.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", ANTHROPIC_KEY_HEADER],
    max_age=600,
)

# Wire up rate limiting: the limiter must live on app.state for slowapi's
# decorator to find it, and RateLimitExceeded needs a handler so the limit
# surfaces as a clean 429 instead of an unhandled error.
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Return a friendly 429 when a client exceeds the scan rate limit."""
    return JSONResponse(
        status_code=429,
        content={
            "detail": (
                "Rate limit exceeded — you can run up to 10 scans per minute. "
                "Please wait a moment and try again."
            )
        },
    )


app.include_router(router, prefix=settings.api_v1_prefix, tags=["scan"])


@app.get(f"{settings.api_v1_prefix}/health", tags=["health"])
async def health() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok"}
