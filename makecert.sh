#/bin/bash

CERT_DIR=~/.pyloncoin2/certs
PRIVATE=$CERT_DIR/private-pem
CERT=$CERT_DIR/cert.pem

mkdir -p $CERT_DIR

openssl ecparam -name secp256k1 -genkey -param_enc explicit -out $PRIVATE
openssl req -new -x509 -key $PRIVATE -out $CERT -days 730
openssl ec -in $PRIVATE -out $PRIVATE -aes256