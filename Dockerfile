# Donjon - Multi-stage Docker Build
# Supports API server, worker, and scanner containers

# =============================================================================
# Stage 1: Base Image
# =============================================================================
FROM python:3.11-slim AS base

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    nmap \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user (CIS Docker Benchmark 4.1)
RUN groupadd -r donjon --gid=1000 && \
    useradd -r -g donjon --uid=1000 --home-dir=/app --shell=/sbin/nologin donjon

# Create application directory
WORKDIR /app

LABEL maintainer="Donjon Security" version="7.0.0" description="Donjon Platform"

# Install Python dependencies first (layer caching optimization)
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy project structure (changes here don't invalidate pip cache)
COPY --chown=donjon:donjon bin/ /app/bin/
COPY --chown=donjon:donjon lib/ /app/lib/
COPY --chown=donjon:donjon scanners/ /app/scanners/
COPY --chown=donjon:donjon utilities/ /app/utilities/
COPY --chown=donjon:donjon config/ /app/config/

# Create data directories and set ownership
RUN mkdir -p /app/data/evidence /app/data/results /app/data/logs \
    /app/data/reports /app/data/archives /app/tools && \
    chown -R donjon:donjon /app /app/data

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DONJON_HOME=/app

# =============================================================================
# Stage 2: API Server
# =============================================================================
FROM base AS api

USER donjon

# Expose API port
EXPOSE 8443

# Health check (uses HTTP internally — TLS terminates at reverse proxy or via env vars)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -fsk https://localhost:8443/api/v1/health || curl -f http://localhost:8443/api/v1/health || exit 1

# Run API server
CMD ["python", "/app/bin/start-server.py", "--host", "0.0.0.0", "--port", "8443"]

# =============================================================================
# Stage 3: Worker (Scheduler + Background Tasks)
# =============================================================================
FROM base AS worker

USER donjon

# Run background worker
CMD ["python", "/app/bin/run-worker.py"]

# =============================================================================
# Stage 4: Scanner (For running scans in container)
# =============================================================================
FROM base AS scanner

USER donjon

# Interactive scan mode
CMD ["python", "/app/bin/donjon-launcher", "--non-interactive"]
