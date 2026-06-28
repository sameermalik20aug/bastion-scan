# Bastion

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

Repo / host slug: **`bastion-scan`**.

Each service deploys independently behind platform-managed TLS:

- **Backend** → Railway / Fly.io (or any container host). Set
  `BASTION_CORS_ALLOWED_ORIGINS` to your deployed frontend origin.
- **Frontend** → Vercel (or any static host). Set `VITE_API_BASE_URL` to your
  deployed backend origin at build time.

HTTPS is a hard requirement — the BYOK Anthropic key travels over the network and
must never transit plain HTTP. Vercel/Railway/Fly provide TLS automatically, and
the backend sets HSTS so browsers refuse to downgrade. See
[`backend/.env.example`](backend/.env.example) and
[`frontend/.env.example`](frontend/.env.example) for all configuration.

## Privacy

<!-- PRIVACY SECTION PLACEHOLDER — owner to paste final copy here. -->

## Decisions & Tradeoffs

<!-- DECISIONS & TRADEOFFS PLACEHOLDER — owner to paste final copy here. -->
