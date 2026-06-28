# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------- #
# Stage 1 — build the static SPA with Vite. Node and node_modules live only
# here; the runtime image gets just the compiled assets.
# ---------------------------------------------------------------------------- #
FROM node:20-alpine AS build

WORKDIR /app

# The API base URL is baked into the bundle at build time (Vite inlines
# import.meta.env.VITE_* during the build). The browser — not this container —
# calls the backend, so for local docker-compose this must be a host-reachable
# URL (http://localhost:8000), and in production the deployed API origin.
ARG VITE_API_BASE_URL=http://localhost:8000
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}

# Install deps from the lockfile first for a cacheable layer.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# ---------------------------------------------------------------------------- #
# Stage 2 — serve the static build with nginx. No Node, no source, just assets.
# ---------------------------------------------------------------------------- #
FROM nginx:1.27-alpine AS runtime

# SPA routing + sane static caching.
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
