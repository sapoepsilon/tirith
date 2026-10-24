# Tirith backend (FastAPI). Build context: ../backend
# Ships the docker CLI so the backend can launch scanner/lab containers on the
# host daemon through the mounted /var/run/docker.sock.
FROM python:3.12.15-slim-bookworm

COPY --from=ghcr.io/astral-sh/uv:0.8.22 /uv /uvx /usr/local/bin/

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl git gnupg; \
    install -m 0755 -d /etc/apt/keyrings; \
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc; \
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" > /etc/apt/sources.list.d/docker.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends docker-ce-cli docker-buildx-plugin; \
    rm -rf /var/lib/apt/lists/*

# Code lives at the same absolute path as the synced repo on the LXC (/opt/tirith),
# so scope.yaml's ".." and any host bind-mount paths line up.
ENV UV_PROJECT_ENVIRONMENT=/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1 \
    PATH=/venv/bin:$PATH
WORKDIR /opt/tirith/backend

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY . .
RUN uv sync --frozen --no-dev
RUN install -m 0755 bin/zap-baseline-docker /usr/local/bin/zap-baseline-docker
ENV TIRITH_ZAP_SCRIPT=/usr/local/bin/zap-baseline-docker

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
