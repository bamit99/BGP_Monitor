# Build stage: compile the dashboard
FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# Runtime stage
FROM python:3.13-slim
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

COPY requirements-service.txt ./
RUN pip install --no-cache-dir -r requirements-service.txt

COPY bgpmon/ ./bgpmon/
COPY config/ ./config/
COPY data/ ./data/
COPY --from=web /web/dist ./web/dist

# Run unprivileged
RUN useradd --create-home --uid 10001 bgpmon && chown -R bgpmon:bgpmon /app
USER bgpmon

EXPOSE 8080
CMD ["python", "-m", "bgpmon"]
