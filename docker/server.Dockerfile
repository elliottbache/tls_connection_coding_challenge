# docker/server.Dockerfile
FROM python:3.14-slim

WORKDIR /app

# copy Python package source
COPY . .

# Copy certs the client needs (client cert + key, trusted CA, etc.)
COPY certificates/ certificates/

# optional deps
COPY pyproject.toml README.md ./

# install the project (creates tls-cc-client / tls-cc-server in PATH)
RUN pip install --no-cache-dir .

# the server listens on this port
EXPOSE 3481

# run the server module
CMD ["tlscc-server"]
