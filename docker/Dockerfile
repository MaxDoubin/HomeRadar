FROM node:24-bookworm-slim AS dashboard
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.11-slim
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl iproute2 libcap2-bin net-tools \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system homeradar \
    && useradd --system --gid homeradar --home-dir /app --shell /usr/sbin/nologin homeradar \
    && mkdir -p /data /app/frontend \
    && chown -R homeradar:homeradar /data /app

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt \
    && setcap 'cap_net_bind_service,cap_net_raw=+ep' "$(readlink -f "$(command -v python3)")"

COPY --chown=homeradar:homeradar backend backend
COPY --chown=homeradar:homeradar kiosk kiosk
COPY --chown=homeradar:homeradar --from=dashboard /src/frontend/dist frontend/dist

ENV HOMERADAR_DB_PATH=/data/homeradar.db \
    HOMERADAR_DATA_DIR=/data \
    HOMERADAR_DNS_ENABLED=true \
    HOMERADAR_DNS_PORT=53 \
    HOMERADAR_BLOCKLIST_AUTO_UPDATE=true \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

VOLUME ["/data"]
EXPOSE 53/udp 53/tcp 8000/tcp
USER homeradar

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl --fail http://127.0.0.1:8000/health || exit 1

CMD ["python3", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
