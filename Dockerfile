# Stage 1: Build React frontend
FROM node:20-slim AS frontend
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

EXPOSE 8000

ENTRYPOINT ["router-security-web"]
