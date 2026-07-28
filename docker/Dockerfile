FROM debian:12-slim AS dashboard
WORKDIR /src/frontend
RUN apt-get update && apt-get install -y nodejs npm
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

FROM python:3.11-slim
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 net-tools curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend backend
COPY kiosk kiosk
COPY --from=dashboard /src/frontend/dist frontend/dist

ENV HOMERADAR_DB_PATH=/data/homeradar.db \
    HOMERADAR_DATA_DIR=/data \
    HOMERADAR_DNS_ENABLED=true \
    HOMERADAR_DNS_PORT=53 \
    HOMERADAR_BLOCKLIST_AUTO_UPDATE=true \
    PYTHONUNBUFFERED=1
VOLUME ["/data"]

EXPOSE 53/udp 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl --fail http://127.0.0.1:8000/status || exit 1

CMD ["python3", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
