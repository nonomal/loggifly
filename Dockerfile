ARG PYTHON_VERSION=3.11.4

# --- Build Stage ---
FROM python:${PYTHON_VERSION}-slim AS builder

WORKDIR /app

# Install build tools und systemd-dev libs
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libsystemd-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --prefix=/install --no-cache-dir -r requirements.txt

# --- Final Stage ---
FROM python:${PYTHON_VERSION}-slim AS final

WORKDIR /app

RUN apt-get update && apt-get install -y \
    systemd-journal-remote \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

COPY entrypoint.sh .
COPY app/ .


LABEL org.opencontainers.image.source="https://github.com/clemcer/loggifly"

RUN mkdir -p /tmp
RUN mkdir -p /var/log/journal/remote

ENTRYPOINT ["/bin/sh", "./entrypoint.sh"]
