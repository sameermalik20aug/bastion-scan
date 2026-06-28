# Bastion

[![CI](https://github.com/sameermalik20aug/bastion-scan/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sameermalik20aug/bastion-scan/actions/workflows/ci.yml)

> Scan a dependency manifest for known vulnerabilities and get safe, deterministic fix suggestions — with optional AI explanations you pay for with your own key.

<!-- SCREENSHOT / GIF PLACEHOLDER — drop a demo capture here (top of the README is prime real estate). -->
![Bastion screenshot — replace me](docs/screenshot.png)

---

## Quick start

The whole stack runs locally with one command (Docker required):

```bash
docker compose up --build
```

Then open **http://localhost:5173**. The frontend talks to the backend on
**http://localhost:8000**; both are wired together by `docker-compose.yml`.

No keys or secrets are needed to run it. AI explanations are **bring-your-own-key**:
paste your Anthropic key in the UI and it's used for that one request only.

## Tech stack

- **Backend:** Python 3.12, FastAPI, Uvicorn, Pydantic v2
- **Vulnerability data:** [OSV.dev](https://osv.dev) (via an async httpx/HTTP-2 client)
- **Fix engine:** deterministic resolver using `packaging` (PyPI) and `semver` (npm)
- **AI layer (optional, BYOK):** Anthropic SDK — user-supplied key, per request
- **Frontend:** React 19, TypeScript, Vite 6, Tailwind CSS 4
- **Rate limiting:** slowapi (per-IP)
- **Packaging / deploy:** multi-stage Docker images, docker-compose for local dev

## Deployment

Repo / host slug: **`bastion-scan`**. The backend deploys to **Railway** and the
frontend to **Vercel**, each independently behind platform-managed TLS. Both
platforms auto-deploy from their own GitHub integration when `main` changes; CI
(below) is the gate that runs first but does not deploy.

> **Everything below must use `https://`.** The BYOK Anthropic key travels over
> the network in a request header and must never transit plain HTTP. Railway and
> Vercel both serve HTTPS automatically, and the backend sets HSTS in production
> so browsers refuse to downgrade.

### Backend → Railway

Create a service from this repo, then set:

- **Settings → Source → Root Directory:** `backend`
  (so Railway picks up [`backend/Dockerfile`](backend/Dockerfile) and
  [`backend/railway.toml`](backend/railway.toml)).
- **Builder:** Dockerfile (configured in `railway.toml`).
- The container binds `0.0.0.0:$PORT` — Railway injects `$PORT`; do **not** set
  it yourself.

**Environment variables** (Settings → Variables):

| Variable | Value |
| --- | --- |
| `BASTION_CORS_ALLOWED_ORIGINS` | your Vercel URL, e.g. `https://bastion-scan.vercel.app` |
| `BASTION_HSTS_ENABLED` | `true` |

Railway gives the service a public URL like
`https://bastion-scan-production.up.railway.app` — that is the **backend URL**
you feed to Vercel below.

### Frontend → Vercel

Import this repo as a new project, then set:

- **Root Directory:** `frontend`
- **Framework Preset:** Vite (auto-detected; pinned in
  [`frontend/vercel.json`](frontend/vercel.json))
- **Build Command:** `npm run build` · **Output Directory:** `dist`

**Environment variable** (Settings → Environment Variables, Production):

| Variable | Value |
| --- | --- |
| `VITE_API_BASE_URL` | your Railway backend URL, e.g. `https://bastion-scan-production.up.railway.app` (no trailing slash) |

Vite inlines `VITE_API_BASE_URL` at **build time**, so change it and redeploy for
it to take effect. Vercel gives the project a public URL like
`https://bastion-scan.vercel.app` — that is the **frontend URL** you put in
Railway's `BASTION_CORS_ALLOWED_ORIGINS` above.

### How the two wire together

The two URLs cross over — each side points at the other:

```
Vercel  VITE_API_BASE_URL            → https://<railway-backend-url>
Railway BASTION_CORS_ALLOWED_ORIGINS → https://<vercel-frontend-url>
```

The browser loads the app from Vercel, then calls the Railway API at
`VITE_API_BASE_URL`. That call is cross-origin, so the backend's CORS list must
name the exact Vercel origin (scheme + host, no path, no trailing slash).
**Both values must be `https://`** — a scheme mismatch (`http` vs `https`) makes
the origin fail the CORS check and the browser blocks the request.

See [`backend/.env.example`](backend/.env.example) and
[`frontend/.env.example`](frontend/.env.example) for all configuration.

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push and
pull request to `main` and verifies — but never deploys — the code:

- **Backend:** installs the app + dev tools and runs `pytest`.
- **Frontend:** runs `npm ci`, then `npm run build` (which runs `tsc -b` first,
  so a type error fails the build). No separate lint step is configured.

Deployment is handled separately by Railway and Vercel's own GitHub integrations.

## Privacy

<!-- PRIVACY SECTION PLACEHOLDER — owner to paste final copy here. -->

## Decisions & Tradeoffs

<!-- DECISIONS & TRADEOFFS PLACEHOLDER — owner to paste final copy here. -->
