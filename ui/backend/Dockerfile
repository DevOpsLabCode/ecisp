# Build context is the REPO ROOT (not ui/backend) -- this image needs the
# engine source (EnterpriseCloudDiscovery/) alongside the FastAPI layer, and
# app/engine_runner.py locates the engine via a relative path from its own
# location, so the in-container layout mirrors the repo layout exactly:
# /app == repo root, /app/ui/backend/app == this package.
#
#   docker build -f ui/backend/Dockerfile -t golem-backend .
#
# This image also bundles the full toolchain for app/orgscan/'s eight SAST
# scanners (checkov, bandit, semgrep, gosec, spotbugs, eslint-plugin-security,
# brakeman, security code scan) -- five language runtimes (Python, Go, JVM,
# Ruby, .NET) plus Node, which makes this a genuinely large image. Each
# toolchain is built in its own stage so a change to one (e.g. bumping the Go
# version) doesn't invalidate every other stage's build cache. It also bundles
# Trivy (SCA + secrets, app/orgscan/scanners/trivy_sca_secrets.py) and OWASP
# ZAP (DAST, app/codescan/dast_scanner.py) for the code-scan feature.

# --- app: the FastAPI web layer's own venv ---
FROM python:3.11-slim AS app-builder

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

# --- scanners: checkov/bandit/semgrep in their OWN venv, deliberately kept
# separate from the app's venv above -- these are substantial applications
# in their own right with fast-moving dependency trees (pydantic, click,
# ...) that would otherwise fight the app's own pinned versions. ---
FROM python:3.11-slim AS scanner-venv-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/scanner-venv
ENV PATH="/opt/scanner-venv/bin:$PATH"

WORKDIR /build
COPY ui/backend/requirements-scanners.txt ./
RUN pip install --no-cache-dir -r requirements-scanners.txt

# --- gosec: built with the Go toolchain, itself a single static-ish binary
# at the end -- only that binary needs to survive into the final image. ---
FROM golang:1.23-bookworm AS go-builder
RUN go install github.com/securego/gosec/v2/cmd/gosec@v2.21.4

# --- spotbugs: downloaded release tarball; needs a JVM to *run* (installed
# in the runtime stage below), not to unpack here. ---
FROM debian:bookworm-slim AS spotbugs-builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /tmp/spotbugs.tgz \
      https://github.com/spotbugs/spotbugs/releases/download/4.8.6/spotbugs-4.8.6.tgz \
    && mkdir -p /opt/spotbugs \
    && tar -xzf /tmp/spotbugs.tgz -C /opt/spotbugs --strip-components=1 \
    && rm /tmp/spotbugs.tgz \
    && chmod +x /opt/spotbugs/bin/*

# --- trivy: single static binary, downloaded release tarball like spotbugs
# above -- provides both SCA (vuln) and secrets scanning in one pass. ---
FROM debian:bookworm-slim AS trivy-builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /tmp/trivy.tgz \
      https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz \
    && mkdir -p /opt/trivy \
    && tar -xzf /tmp/trivy.tgz -C /opt/trivy trivy \
    && rm /tmp/trivy.tgz \
    && chmod +x /opt/trivy/trivy

# --- zap: OWASP ZAP, downloaded release tarball -- needs a JVM to *run*
# (JDK already installed in the runtime stage below for spotbugs/brakeman),
# not to unpack here. Verified live (this exact tarball, this exact
# zap.sh -cmd -autorun invocation) against a real target during development. ---
FROM debian:bookworm-slim AS zap-builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /tmp/zap.tar.gz \
      https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz \
    && mkdir -p /opt/zap \
    && tar -xzf /tmp/zap.tar.gz -C /opt/zap --strip-components=1 \
    && rm /tmp/zap.tar.gz \
    && chmod +x /opt/zap/zap.sh

# --- node tools: ESLint pinned to 8.x + eslint-plugin-security, kept in a
# fixed location separate from the frontend's own node_modules or whatever
# a scanned repo ships -- see scanners/eslint_security.py's docstring for
# why 8.x specifically (the plugin's rules use a pre-ESLint-9 API). ---
FROM node:22-slim AS node-tools-builder
WORKDIR /opt/orgscan-node-tools
RUN npm init -y >/dev/null \
    && npm install --no-save eslint@8.57.1 eslint-plugin-security@3.0.1

# --- runtime: python:3.11-slim + every toolchain above, copied in rather
# than reinstalled, plus the language runtimes each toolchain still needs
# to actually execute (JDK for spotbugs, Ruby for brakeman, .NET SDK for
# security code scan, Go's runtime is statically linked into gosec so it
# does not need its own install here). ---
FROM python:3.11-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      git \
      curl \
      ca-certificates \
      default-jdk-headless \
      maven \
      ruby \
      ruby-dev \
      build-essential \
      libpango-1.0-0 \
      libpangocairo-1.0-0 \
      libgdk-pixbuf-2.0-0 \
      libffi-dev \
      shared-mime-info \
      fonts-dejavu-core \
      libicu76 \
    && gem install brakeman --no-document -v 7.0.2 \
    # Debian's default-jdk-headless doesn't pull build-essential's compiler
    # toolchain, which brakeman's native gem extensions (ffi, etc.) need at
    # install time -- build-essential is kept afterward too, since Maven
    # invokes it again for every repo spotbugs.py compiles.
    && curl -sSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
    && bash /tmp/dotnet-install.sh --channel 8.0 --install-dir /usr/share/dotnet \
    && rm /tmp/dotnet-install.sh \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/venv/bin:/usr/share/dotnet:/opt/gosec/bin:/opt/spotbugs/bin:/usr/local/go/bin:/opt/trivy:/opt/zap:$PATH"
ENV JAVA_HOME="/usr/lib/jvm/default-java"
ENV SCANNER_VENV="/opt/scanner-venv/bin"
ENV ORGSCAN_ESLINT_TOOLS_DIR="/opt/orgscan-node-tools"

COPY --from=app-builder /opt/venv /opt/venv
COPY --from=scanner-venv-builder /opt/scanner-venv /opt/scanner-venv
COPY --from=go-builder /go/bin/gosec /opt/gosec/bin/gosec
# gosec's own binary is only half of it -- it shells out to the `go`
# toolchain itself to load and type-check the target package (verified: it
# fails with "go command required, not found" against a repo with no `go`
# on PATH), so the full Go install has to come along too, not just the
# compiled gosec binary.
COPY --from=go-builder /usr/local/go /usr/local/go
COPY --from=spotbugs-builder /opt/spotbugs /opt/spotbugs
COPY --from=trivy-builder /opt/trivy /opt/trivy
COPY --from=zap-builder /opt/zap /opt/zap
COPY --from=node-tools-builder /opt/orgscan-node-tools /opt/orgscan-node-tools
# eslint's bin script itself needs a `node` binary on PATH to run -- this
# runtime stage is python:3.11-slim, which has no Node install at all, only
# the eslint-tools directory copied in above.
COPY --from=node-tools-builder /usr/local/bin/node /usr/local/bin/node

# checkov/bandit/semgrep live in a separate venv (not on the app's own
# PATH-activating /opt/venv) -- symlink them onto PATH individually rather
# than prepending the whole scanner venv's bin/, which would shadow the
# app venv's own uvicorn/python with the scanner venv's copies.
RUN for tool in checkov bandit semgrep; do \
      ln -s "/opt/scanner-venv/bin/$tool" "/usr/local/bin/$tool"; \
    done

WORKDIR /app
COPY --from=app-builder /app/EnterpriseCloudDiscovery ./EnterpriseCloudDiscovery
COPY --from=app-builder /app/setup.py /app/README.md ./
COPY ui/backend/app ./ui/backend/app
COPY ui/backend/alembic.ini ./ui/backend/alembic.ini
COPY ui/backend/alembic ./ui/backend/alembic
RUN mkdir -p ./ui/backend/data/reports ./ui/backend/data/orgscan-reports \
      ./ui/backend/data/codescan-reports ./ui/backend/data/codescan-uploads

RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app
USER appuser

WORKDIR /app/ui/backend
EXPOSE 8000
# Applies pending containment-table migrations (app/db.py, alembic/) before
# the app starts -- see docker-compose.yml's DATABASE_URL. Against the
# default SQLite DATABASE_URL (no DB service configured) this is a no-op
# past the first run.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
