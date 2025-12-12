mkdir certificates
cd certificates
openssl genrsa -out ca_key.pem 2048
openssl req -x509 -new -nodes -key ca_key.pem -sha256 -days 3650 -out ca_cert.pem -subj "/CN=My Test CA"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec_private_key.pem
openssl req -new -key ec_private_key.pem -out client.csr -subj "/CN=client"
openssl x509 -req -in client.csr -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out client_cert.pem -days 365 -sha256
openssl req -x509 -newkey rsa:2048 -nodes -keyout server-key.pem -out server-cert.pem -days 365 -subj "/CN=localhost"
