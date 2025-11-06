import os
import subprocess
import shutil
import sys

OPENSSL = "openssl" if sys.platform != "win32" else "openssl.exe"
CERT_DIR = os.path.join(os.path.dirname(__file__), "certs")
VALID_KEY = os.path.join(CERT_DIR, "valid_key.pem")
VALID_CERT = os.path.join(CERT_DIR, "valid_cert.pem")
VALID_CSR = os.path.join(CERT_DIR, "valid_csr")
REVOKED_KEY = os.path.join(CERT_DIR, "revoked_key.pem")
REVOKED_CERT = os.path.join(CERT_DIR, "revoked_cert.pem")
REVOKED_CSR = os.path.join(CERT_DIR, "revoked_csr")
CA_CERT = os.path.join(CERT_DIR, "revoking_ca.pem")
CA_KEY = os.path.join(CERT_DIR, "revoking_ca_key.pem")
CA_SERIAL = os.path.join(CERT_DIR, "revoking_ca_serial")
CRL_FILE = os.path.join(CERT_DIR, "revoking_crl.pem")
CA_COMMON_NAME = "CA_SIGNER"
CLIENT_COMMON_NAME = "CLIENT"
INDEX = os.path.join(CERT_DIR, "index")
CRLNUMBER = os.path.join(CERT_DIR, "crlnumber")
CONF_FILE = os.path.join(os.path.dirname(__file__), "revoking_ssl.conf")


def run_command(command):
    subprocess.run(command, check=True, shell=True)


def main():
    if os.path.exists(CERT_DIR):
        shutil.rmtree(CERT_DIR)
    os.mkdir(CERT_DIR)

    with open(os.path.join(CERT_DIR, "index"), "w") as f:
        pass

    with open(os.path.join(CERT_DIR, "crlnumber"), "w") as f:
        f.write("01")

    # Create the CA
    print("Creating a test CA")
    run_command(f"{OPENSSL} genrsa -out {CA_KEY} 2048")
    run_command(
        f"{OPENSSL} req -new -x509 -days 1095 -key {CA_KEY} -out {CA_CERT} -subj '/CN={CA_COMMON_NAME}'"
    )

    with open(CA_SERIAL, "w") as f:
        f.write("01")

    # Create a valid cert that will _not_ be revoked
    print(f"Creating a test cert that will remain valid: {VALID_CERT}")
    run_command(f"{OPENSSL} genrsa -out {VALID_KEY} 2048")
    run_command(
        f"{OPENSSL} req -new -key {VALID_KEY} -out {VALID_CSR} -subj '/CN={CLIENT_COMMON_NAME}'"
    )
    run_command(
        f"{OPENSSL} x509 -req -days 1095 -CA {CA_CERT} -CAkey {CA_KEY} -in {VALID_CSR} -out {VALID_CERT} -CAserial {CA_SERIAL}"
    )

    # Create a test cert so we can revoke it later
    print(f"Creating a test cert to revoke in later step: {REVOKED_CERT}")
    run_command(f"{OPENSSL} genrsa -out {REVOKED_KEY} 2048")
    run_command(
        f"{OPENSSL} req -new -key {REVOKED_KEY} -out {REVOKED_CSR} -subj '/CN={CLIENT_COMMON_NAME}'"
    )
    run_command(
        f"{OPENSSL} x509 -req -days 1095 -CA {CA_CERT} -CAkey {CA_KEY} -in {REVOKED_CSR} -out {REVOKED_CERT} -CAserial {CA_SERIAL}"
    )

    # Setup CRL database info for CRL revoking
    with open(INDEX, "w") as f:
        pass

    with open(CRLNUMBER, "w") as f:
        f.write("01")

    # Revoke the cert, then generate a CRL with the newly revoked info
    print(f"Revoking the cert: {REVOKED_CERT}")
    original_cwd = os.getcwd()
    os.chdir(os.path.dirname(__file__))
    run_command(
        f"{OPENSSL} ca -revoke {REVOKED_CERT} -keyfile {CA_KEY} -cert {CA_CERT} -config {os.path.basename(CONF_FILE)} -md sha256"
    )
    run_command(
        f"{OPENSSL} ca -gencrl -keyfile {CA_KEY} -cert {CA_CERT} -out {CRL_FILE} -config {os.path.basename(CONF_FILE)} -crlexts crl_ext -md sha256"
    )
    os.chdir(original_cwd)


if __name__ == "__main__":
    main()
