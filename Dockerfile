# syntax=docker/dockerfile:1.6
# ── Build stage ─────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

COPY . .
RUN pip install --no-cache-dir --prefix=/install -e .

# ── Runtime stage ───────────────────────────────────────────────────
FROM python:3.12-slim

# System tools that HEAVEN shells out to
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd -r heaven && useradd -r -g heaven -u 1001 -m -d /app heaven

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local
COPY --from=builder /build/heaven /app/heaven
COPY --from=builder /build/pyproject.toml /app/

# Data dir owned by heaven user
RUN mkdir -p /app/data && chown -R heaven:heaven /app

USER heaven

EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8443/api/health || exit 1

CMD ["heaven", "serve", "--host", "0.0.0.0", "--port", "8443"]
