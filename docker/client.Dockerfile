# docker/client.Dockerfile
FROM python:3.11-slim

# For building or running the WORK helper:
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Python package source
COPY pyproject.toml README.md ./
COPY src/ src/
COPY certificates/ certificates/

# Copy certs the client needs (client cert + key, trusted CA, etc.)
COPY certificates/ certificates/

# Optional deps
COPY pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt || true

# If you ALREADY have the pow_challenge binary in ./build, copy it in:
COPY src/tlslp/_bin/pow_challenge src/tlslp/_bin/pow_challenge
RUN chmod +x src/tlslp/_bin/pow_challenge || true

# Install the project (creates tls-cc-client / tls-cc-server in PATH)
RUN pip install --no-cache-dir .

CMD ["tlslp-client"]
