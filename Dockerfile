# Stage 1: Build React frontend
FROM node:22-slim AS frontend
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ .
RUN npm run build

# Stage 2: Python runtime
FROM python:3.12-slim AS base
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-client && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir . && \
    rm -rf /root/.cache

COPY --from=frontend /app/web/dist web/dist/

# The package is installed into site-packages, so point it at the SPA and a
# persistent history location explicitly, and listen on all interfaces so a
# published port works.
ENV ROUTER_SECURITY_HOST=0.0.0.0 \
    ROUTER_SECURITY_WEB_DIST=/app/web/dist \
    ROUTER_SECURITY_DB=/app/data/scan_history.db
VOLUME /app/data

EXPOSE 8000

ENTRYPOINT ["router-security-web"]
