ARG PYTHON_VERSION=3.11.4

# --- Build Stage ---
FROM python:${PYTHON_VERSION}-slim AS builder

WORKDIR /app

COPY requirements.txt .

# Install dependencies
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt

COPY app/line_processor.py .
COPY app/notifier.py .
COPY app/docker_monitor.py .
COPY app/app.py .
COPY app/utils.py .
COPY app/constants.py .
COPY app/config/ ./config/

# COPY app/systemd_monitor.py .

# --- Final Stage: distroless ---
FROM gcr.io/distroless/python3-debian12:nonroot

WORKDIR /app
USER nonroot

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

ENV PYTHONPATH=/usr/local/lib/python3.11/site-packages

COPY --from=builder /install /usr/local

COPY --from=builder /app /app

ENTRYPOINT ["python", "app.py"]
    