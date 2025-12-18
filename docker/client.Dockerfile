# docker/client.Dockerfile
FROM python:3.11-slim

# For building or running the WORK helper:
# - If you already have a compiled binary in build/pow_challenge, we’ll just copy it.
# - If you need to compile, see the multi-stage example further below.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Python source
COPY src/ src/
# Copy certs the client needs (client cert + key, trusted CA, etc.)
COPY certificates/ certificates/
# Optional deps
COPY pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt || true

# If you ALREADY have the pow_challenge binary in ./build, copy it in:
COPY build/pow_challenge build/pow_challenge
RUN chmod +x build/pow_challenge || true

CMD ["python", "-m", "src.client"]
