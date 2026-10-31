# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Kaaval backend (FastAPI + OPC UA client + detection/correlation + agents).
#
# Build context is the REPO ROOT (it needs backend/, profiles/, docker-compose.yml):
#   docker build -f backend/Dockerfile -t kaaval-backend .
#
# The backend's lab executor contains the OT-safety gate and drives the simulated
# plant through `docker compose exec` (iptables containment, manual S7 writes,
# reset). So the image ships the docker CLI + compose plugin and, at runtime, the
# host docker socket is mounted in (docker-outside-of-docker). The gate itself is
# pure code and runs the same whether the backend is native or containerized.
FROM python:3.12-slim

ARG TARGETARCH=amd64
# Pinned, widely-mirrored versions (downloaded at BUILD time only; runtime is offline).
ARG DOCKER_VERSION=27.3.1
ARG COMPOSE_VERSION=2.30.3

# docker CLI + compose plugin as static binaries, arch-aware (amd64 + arm64).
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    case "$TARGETARCH" in \
      amd64) DARCH=x86_64 ;; \
      arm64) DARCH=aarch64 ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://download.docker.com/linux/static/stable/${DARCH}/docker-${DOCKER_VERSION}.tgz" -o /tmp/docker.tgz; \
    tar -xzf /tmp/docker.tgz -C /tmp; \
    install -m 0755 /tmp/docker/docker /usr/local/bin/docker; \
    mkdir -p /usr/local/lib/docker/cli-plugins; \
    curl -fsSL "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-${DARCH}" \
      -o /usr/local/lib/docker/cli-plugins/docker-compose; \
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose; \
    rm -rf /tmp/docker /tmp/docker.tgz; \
    docker --version; docker compose version

WORKDIR /app/backend
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# App code + the profiles and compose file the backend reads/uses at runtime.
COPY backend /app/backend
COPY profiles /app/profiles
COPY docker-compose.yml /app/docker-compose.yml

ENV PYTHONUNBUFFERED=1 \
    KAAVAL_COMPOSE_FILE=/app/docker-compose.yml

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
