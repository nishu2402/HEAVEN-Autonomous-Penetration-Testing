# syntax=docker/dockerfile:1.6

# ── Stage 1: Build the React UI ──────────────────────────────────────
FROM node:20-slim AS ui-builder

WORKDIR /ui

COPY heaven-ui/package.json heaven-ui/package-lock.json* ./
RUN npm ci --prefer-offline

COPY heaven-ui/ ./
RUN npm run build

# ── Stage 2: Build Python packages ───────────────────────────────────
FROM python:3.12-slim AS py-builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

COPY . .
RUN pip install --no-cache-dir --prefix=/install -e .

# ── Stage 3: Runtime image ───────────────────────────────────────────
FROM python:3.12-slim

# System tools that HEAVEN shells out to (nmap, curl for health-check)
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd -r heaven && useradd -r -g heaven -u 1001 -m -d /app heaven

WORKDIR /app

# Copy installed Python packages from py-builder
COPY --from=py-builder /install /usr/local
# Copy source (needed for editable install paths & migrations)
COPY --from=py-builder /build/heaven        /app/heaven
COPY --from=py-builder /build/migrations    /app/migrations
COPY --from=py-builder /build/alembic.ini   /app/alembic.ini
COPY --from=py-builder /build/pyproject.toml /app/
COPY --from=py-builder /build/NVD_model.pkl  /app/NVD_model.pkl

# Copy the pre-built React UI so the API can serve it from /app/heaven-ui/dist
COPY --from=ui-builder /ui/dist /app/heaven-ui/dist

# Data dir owned by heaven user
RUN mkdir -p /app/data && chown -R heaven:heaven /app

USER heaven

EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8443/api/health || exit 1

CMD ["heaven", "serve", "--host", "0.0.0.0", "--port", "8443"]
