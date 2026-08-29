# syntax=docker/dockerfile:1.7
# RedPulse - Production Multi-stage Dockerfile
# Stage 1: Builder  -> Stage 2: Runtime  -> Stage 3: Worker (same base)

# ==================== Builder Stage ====================
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# System deps for building Python C extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# ==================== Runtime Stage ====================
FROM python:3.11-slim AS runtime

# Security: read-only filesystem hints, no root
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/home/appuser/.local/bin:$PATH \
    PYTHONPATH=/app \
    NUCLEI_BIN=/usr/local/bin/nuclei \
    SUBFINDER_BIN=/usr/local/bin/subfinder \
    HTTPX_BIN=/usr/local/bin/httpx

WORKDIR /app

# Runtime system deps: fonts for PDF, curl for healthchecks, libpq for postgres
RUN apt-get update && apt-get install -y --no-install-recommends \
    fonts-dejavu-core \
    curl \
    libpq5 \
    unzip \
    tini \
    && rm -rf /var/lib/apt/lists/* \
    && fc-cache -f

# Install Nuclei binary (graceful fallback if offline)
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.0_linux_amd64.zip -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /tmp \
    && mv /tmp/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei.zip \
    || echo "Nuclei download skipped (offline build)"

# Copy Python dependencies from builder
COPY --from=builder /root/.local /home/appuser/.local

# Copy application code
COPY alembic.ini ./alembic.ini
COPY alembic ./alembic
COPY app ./app

# Create non-root user with explicit UID
RUN groupadd -g 1000 appuser \
    && useradd -u 1000 -g appuser -m -s /bin/false appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

# Healthcheck for the API
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Use tini as PID 1 for proper signal handling
ENTRYPOINT ["tini", "--"]

# Run migrations then start server
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000 --workers 2 --proxy-headers --forwarded-allow-ips '*'"]
