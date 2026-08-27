# syntax=docker/dockerfile:1.6
# RedPulse - Multi-stage Dockerfile for FastAPI + PDF + Nuclei

# ---------- Builder stage ----------
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# System deps for building Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# ---------- Runtime stage ----------
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH=/root/.local/bin:$PATH \
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
    && rm -rf /var/lib/apt/lists/* \
    && fc-cache -f

# Install Nuclei binary (optional, graceful fallback if download fails)
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.0_linux_amd64.zip -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /tmp \
    && mv /tmp/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei.zip \
    || echo "Nuclei download skipped (offline build)"

# Copy Python dependencies from builder
COPY --from=builder /root/.local /root/.local

# Copy application
COPY alembic.ini ./alembic.ini
COPY alembic ./alembic
COPY app ./app
COPY pytest.ini ./pytest.ini

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Healthcheck for the API
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run migrations then start server (production)
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000 --workers 2"]
