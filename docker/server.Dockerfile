# docker/server.Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Copy Python package source
COPY . .

# Copy certs the client needs (client cert + key, trusted CA, etc.)
COPY certificates/ certificates/

# Optional deps
COPY pyproject.toml README.md ./

# Install the project (creates tls-cc-client / tls-cc-server in PATH)
RUN pip install --no-cache-dir .

# The server listens on this port
EXPOSE 1234

# Run the server module
CMD ["tlslp-server"]
