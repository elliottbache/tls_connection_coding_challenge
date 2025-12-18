# docker/server.Dockerfile
FROM python:3.11-slim

# Install OS deps if you need them later (OpenSSL tools often helpful)
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Python package source
COPY . .

# Copy certs the client needs (client cert + key, trusted CA, etc.)
COPY certificates/ certificates/

# Optional deps
COPY pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt || true

# Install the project (creates tls-cc-client / tls-cc-server in PATH)
RUN pip install --no-cache-dir .

# The server listens on this port (adjust to your actual server port)
EXPOSE 3481

# Run the server module
CMD ["tlscc-server"]
