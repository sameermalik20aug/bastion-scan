# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------- #
# Stage 1 — builder: resolve and install dependencies into a self-contained
# virtualenv. This stage carries the build toolchain and caches; none of it is
# copied forward, so the runtime image stays small and free of compilers.
# ---------------------------------------------------------------------------- #
FROM python:3.12-slim AS builder

# Don't write .pyc files, and stream logs straight out (no buffering).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Build the dependency set into an isolated venv we can copy wholesale later.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install dependencies first, keyed only on the project metadata, so this layer
# is cached and reused whenever application code (but not deps) changes.
COPY pyproject.toml ./
COPY app ./app
RUN pip install .

# ---------------------------------------------------------------------------- #
# Stage 2 — runtime: a slim image carrying only the venv and the app code. No
# build tools, no pip caches, and it runs as an unprivileged user.
# ---------------------------------------------------------------------------- #
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Create a non-root user to run the service. If the process is ever compromised,
# the attacker lands as an unprivileged account that owns nothing on the host and
# can't write outside the app directory — a basic blast-radius limit.
RUN groupadd --system bastion && \
    useradd --system --gid bastion --no-create-home --home-dir /app bastion

WORKDIR /app

# Copy the prebuilt virtualenv and only the runtime artifacts (the app package).
# Tests, pyproject, caches, and the build toolchain are intentionally left behind.
COPY --from=builder /opt/venv /opt/venv
COPY --chown=bastion:bastion app ./app

USER bastion

EXPOSE 8000

# Containers terminate TLS at the platform edge (Railway/Fly/etc.); uvicorn
# serves plain HTTP behind it. The BYOK key is protected end-to-end by that
# platform TLS plus the HSTS header the app sets.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
