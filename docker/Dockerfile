# ═══════════════════════════════════════════════════════════════════
# Stage 1 : Builder
# ═══════════════════════════════════════════════════════════════════
FROM python:3.11-slim AS builder

LABEL maintainer="devsecops-team"
LABEL org.opencontainers.image.title="DevSecOps Demo API"
LABEL org.opencontainers.image.version="1.0.0"

WORKDIR /build

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt

# ═══════════════════════════════════════════════════════════════════
# Stage 2 : Runtime (image finale minimale)
# ═══════════════════════════════════════════════════════════════════
FROM python:3.11-slim AS runtime

# Mise à jour des packages de sécurité
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copier les dépendances du builder
COPY --from=builder /install /usr/local

# Créer un utilisateur non-root (moindre privilège)
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --no-create-home --shell /bin/false appuser

WORKDIR /app

COPY src/ ./src/

RUN chown -R appuser:appgroup /app && \
    chmod -R 550 /app

USER appuser

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ENV=production \
    PORT=8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "src.app:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--no-access-log"]
