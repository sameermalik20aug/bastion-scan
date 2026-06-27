from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from app.api.routes import limiter, router
from app.core.config import settings

app = FastAPI(title=settings.app_name)

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
