# Build context is the REPO ROOT (not ui/backend) -- this image needs the
# engine source (EnterpriseCloudDiscovery/) alongside the FastAPI layer, and
# app/engine_runner.py locates the engine via a relative path from its own
# location, so the in-container layout mirrors the repo layout exactly:
# /app == repo root, /app/ui/backend/app == this package.
#
#   docker build -f ui/backend/Dockerfile -t ecisp-backend .

# --- builder: compiles anything without a prebuilt wheel into a venv ---
FROM python:3.11-slim AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app
COPY requirements.txt setup.py README.md ./
COPY EnterpriseCloudDiscovery ./EnterpriseCloudDiscovery
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir --no-deps -e .

COPY ui/backend/requirements-web.txt ./ui/backend/requirements-web.txt
RUN pip install --no-cache-dir -r ui/backend/requirements-web.txt

# --- runtime: no compiler toolchain, just the venv + source ---
FROM python:3.11-slim AS runtime

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app
COPY --from=builder /app/EnterpriseCloudDiscovery ./EnterpriseCloudDiscovery
COPY --from=builder /app/setup.py /app/README.md ./
COPY ui/backend/app ./ui/backend/app
RUN mkdir -p ./ui/backend/data/reports

RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app
USER appuser

WORKDIR /app/ui/backend
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
