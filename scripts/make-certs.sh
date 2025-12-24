set -euo pipefail

CERT_DIR="certificates"

# if certs already exist, don't regenerate (prevents server/client mismatch)
if [ -d "$CERT_DIR" ]; then
    echo "Certificates already exist in $CERT_DIR; skipping generation."
    echo "To force regeneration, delete $CERT_DIR/ manually."
    exit 0
fi

# create directory and change directory
mkdir -p certificates
cd certificates

# CA
openssl genrsa -out ca_key.pem 2048
openssl req -x509 -new -nodes -key ca_key.pem -sha256 -days 3650 -out ca_cert.pem -subj "/CN=My Test CA"

# client key and CSR
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec_private_key.pem
openssl req -new -key ec_private_key.pem -out client.csr -subj "/CN=client"

# client cert signed by CS
openssl x509 -req -in client.csr -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out client_cert.pem -days 365 -sha256

# server key and CSR
openssl genrsa -out server-key.pem 2048
openssl req -new -key server-key.pem -out server.csr -subj "/CN=localhost"

# server cert extensions file
cat > server.ext <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

# server cert signed by CA
openssl x509 -req -in server.csr -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial \
  -out server-cert.pem -days 365 -sha256 -extfile server.ext