# ─── Build stage ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ─── Runtime stage ────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Utilizador não-root (princípio do menor privilégio)
RUN useradd --create-home --uid 1000 app

# Copia apenas as dependências instaladas, não o pip cache nem ferramentas de build
COPY --from=builder /install /usr/local

WORKDIR /app
COPY --chown=app:app app.py .

USER app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 5050

# Gunicorn: 4 workers sync. Ajustar via env em K8s se necessário.
CMD ["gunicorn", "--bind", "0.0.0.0:5050", "--workers", "4", \
     "--access-logfile", "-", "--error-logfile", "-", "app:app"]