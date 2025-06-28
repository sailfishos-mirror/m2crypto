#!/bin/sh
set -eu

SO_PIN=12345678
PIN=123456

OPENSSL_CONF="$(readlink -f provider-openssl.conf)"
SOFTHSM2_CONF="$(readlink -f provider-softhsm2.conf)"
export OPENSSL_CONF SOFTHSM2_CONF

# Create necessary file and folder
echo "${PIN}" > /path/to/pin.txt
mkdir -p /path/to/tokens

# Init SoftHSM token
softhsm2-util --init-token --slot 0 --label "SoftHSM2_Token" --so-pin "${SO_PIN}" --pin "${PIN}"

# Generate key pair
pkcs11-tool --module /lib*/libsofthsm2.so --login --pin "${PIN}" \
	--keypairgen --key-type RSA:2048 --id 1

# Display the generated public key
openssl rsa -in 'pkcs11:id=%01' -pubin
openssl rsa -in 'pkcs11:id=%01' -pubin -text -noout
openssl pkey -in "pkcs11:id=%01" -pubin
openssl pkey -in "pkcs11:id=%01" -pubin -text -noout

# Generate and import a certificate
openssl req -new -x509 -days 365 -key 'pkcs11:%01' -subj '/CN=01_cert/' -out 01_cert.der -outform der
pkcs11-tool --module /lib*/libsofthsm2.so --login --pin "${PIN}" \
	--write-object 01_cert.der --type cert --id 1

# # Run the test
# python3 -m venv venv
# source venv/bin/activate
# pip install /path/to/M2Crypto/
# python3 /path/to/M2Crypto/tests/test_provider.py
