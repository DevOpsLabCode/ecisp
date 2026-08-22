# Deliberately its own tiny image, not a stage bolted onto
# ui/backend/Dockerfile -- that image bundles a dozen SAST/DAST toolchains
# and, more importantly, is built to be deployed somewhere with
# Kubernetes access. This one must never have that: no kubectl, no
# cluster credentials, nothing beyond what boto3 and an HTTP client need.
FROM python:3.11-slim

RUN useradd --create-home --shell /usr/sbin/nologin appuser
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

USER appuser
CMD ["python", "-m", "app"]
