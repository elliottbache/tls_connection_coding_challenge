# docker/server.Dockerfile
FROM python:3.11-slim

# Install OS deps if you need them later (OpenSSL tools often helpful)
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY src/ src/
COPY certificates/ certificates/
COPY pyproject.toml ./

# Install Python deps (if none, keep the line; pip will no-op)
RUN pip install --no-cache-dir -r requirements.txt || true

# The server listens on this port (adjust to your actual server port)
EXPOSE 1234

# Run the server module
CMD ["python", "-m", "src.server"]
