# Pinned to a specific patch version (not the floating 3.12-slim tag) for
# reproducible builds. For full supply-chain integrity, pin by digest instead:
#   FROM python:3.12.8-slim-bookworm@sha256:<digest>
# (resolve with: docker buildx imagetools inspect python:3.12.8-slim-bookworm)
FROM python:3.12.8-slim-bookworm

# No .pyc files, unbuffered logs (so JSON security logs flush immediately).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /srv

# Install dependencies as root, then drop privileges.
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app

# Run as an unprivileged user, not root. If the app is ever compromised, the
# attacker lands as a no-login user that owns nothing on the system.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /srv
USER appuser

EXPOSE 8000

# Lightweight healthcheck using the stdlib (no curl in the slim image).
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health').status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
