# Multi-stage build
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y gcc make && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir -e . && python src/qameleon/crypto_primitives/c_accel/build.py || true

FROM python:3.12-slim AS runtime

RUN apt-get update && apt-get install -y libgomp1 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /app /app

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "qameleon.dashboard.app:create_dashboard_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
