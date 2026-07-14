# syntax=docker/dockerfile:1.6

# ── Stage 1: Build the React UI ──────────────────────────────────────
# Node 22 (active LTS): Vite 8 requires Node >=20.19/>=22.12, and Node 20 is EOL.
FROM node:22-slim AS ui-builder

WORKDIR /ui

COPY heaven-ui/package.json heaven-ui/package-lock.json* ./
RUN npm ci --prefer-offline

COPY heaven-ui/ ./
RUN npm run build

# ── Stage 2: Build Python packages ───────────────────────────────────
FROM python:3.12-slim AS py-builder

# Build under /app — the SAME path the runtime stage uses. The project is
# installed editable, so pip bakes absolute source paths into the editable
# finder; building under /app keeps those paths valid after the COPY into the
# runtime stage (building under a throwaway dir like /build would leave the
# finder pointing at a directory that no longer exists → ModuleNotFoundError).
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

COPY . .

# NVD_model.pkl is gitignored (48 MB binary). When building in CI or from a fresh
# clone it won't be present, so generate a valid stub ExtraTreesRegressor so the
# COPY in the runtime stage always succeeds. The stub predicts a flat CVSS of 5.0;
# replace it with the real model by running: heaven train-model
RUN if [ ! -f NVD_model.pkl ]; then \
        PYTHONPATH=/install/lib/python3.12/site-packages \
        python3 -c "\
import joblib, numpy as np; \
from sklearn.ensemble import ExtraTreesRegressor; \
m = ExtraTreesRegressor(n_estimators=10, random_state=42); \
m.fit(np.zeros((20, 13)), np.linspace(0.0, 10.0, 20)); \
joblib.dump(m, 'NVD_model.pkl')" \
        && echo 'Stub NVD_model.pkl generated (run heaven train-model for real accuracy)'; \
    fi

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
# Copy source. The editable install resolves `import heaven` and the
# source-relative lookups (heaven-ui/dist, vulnscan/sast_rules/, db/schema.sql)
# against this tree, so the build path (/app) must match the runtime path.
COPY --from=py-builder /app/heaven        /app/heaven
COPY --from=py-builder /app/migrations    /app/migrations
COPY --from=py-builder /app/alembic.ini   /app/alembic.ini
COPY --from=py-builder /app/pyproject.toml /app/
COPY --from=py-builder /app/NVD_model.pkl  /app/NVD_model.pkl

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
