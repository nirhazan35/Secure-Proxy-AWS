#!/usr/bin/env bash
# Generate a root CA and a localhost server cert (demo purposes only).

set -euo pipefail

mkdir -p certs
cd certs

# Root CA
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -out ca.pem -subj "/CN=LocalProxyRoot"

# localhost leaf (used if you terminate TLS at the proxy)
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 825 -sha256

echo "✔  Certificates written to ./certs"
