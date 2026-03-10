# docker/client.Dockerfile
# build stage
# -----------
FROM python:3.14-slim AS builder

# For building or running the WORK helper:
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only what we need to build the C++ binary
COPY cpp/ cpp/

# Configure + build
RUN cmake -S cpp -B build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build --config Release

# runtime stage
# -----------
FROM python:3.14-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# copy Python package source
COPY pyproject.toml README.md ./
COPY src/ ./src/

# put the compiled binary where the code expects it
RUN mkdir -p /app/src/tlslp/_bin
COPY --from=builder /app/build/work_challenge /app/src/tlslp/_bin/work_challenge
RUN chmod +x /app/src/tlslp/_bin/pow_challenge

# copy certs the client needs (client cert + key, trusted CA, etc.)
COPY certificates/ certificates/

# install the project (creates tlslp-client / tlslp-server in PATH)
RUN pip install --no-cache-dir -e .

CMD ["tlslp-client"]
