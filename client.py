import requests
import ssl
import json
from base64 import b64decode
from configparser import ConfigParser
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat._oid import ObjectIdentifier
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def get_quote_from_ias_report(ias_report):
    return b64decode(json.loads(ias_report)['isvEnclaveQuoteBody'])

def verify_mr_enclave(ias_report):
    mr_enclave_offset = int(config["SGX_CONSTANTS"]["mr_enclave_offset"])
    mr_enclave_size = int(config["SGX_CONSTANTS"]["mr_enclave_size"])
    expected_mr_enclave = config["SERVER"]["mr_enclave"]
    quote_body = get_quote_from_ias_report(ias_report)
    mr_enclave = str(bytes.hex(quote_body[mr_enclave_offset:mr_enclave_offset+mr_enclave_size]))
    return expected_mr_enclave.lower().strip() == mr_enclave.lower().strip()

def verify_mr_signer(ias_report):
    mr_signer_offset = int(config["SGX_CONSTANTS"]["mr_signer_offset"])
    mr_signer_size = int(config["SGX_CONSTANTS"]["mr_signer_size"])
    expected_mr_signer = config["SERVER"]["mr_signer"]
    quote_body = get_quote_from_ias_report(ias_report)
    mr_signer = str(bytes.hex(quote_body[mr_signer_offset:mr_signer_offset+mr_signer_size]))
    return expected_mr_signer.lower().strip() == mr_signer.lower().strip()

def verify_certificate_pubkey(ias_report, pubkey):
    report_offset = int(config["SGX_CONSTANTS"]["report_offset"])
    pubkey_hash_size = int(config["SGX_CONSTANTS"]["pubkey_hash_size"])
    quote_body = get_quote_from_ias_report(ias_report)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(pubkey.public_bytes(Encoding.DER, PublicFormat.PKCS1))
    hash = digest.finalize()
    
    return quote_body[report_offset:report_offset+pubkey_hash_size] == hash

def verify_report_signature(ias_report, ias_report_signature, ias_report_signing_certificate):
    try:
        cert = x509.load_der_x509_certificate(ias_report_signing_certificate, default_backend())
        cert.public_key().verify(ias_report_signature,
                      ias_report,
                      padding.PKCS1v15(),
                      hashes.SHA256()
        )
        return True
    except:
        return False

def get_certificate_extensions(cert):
    ias_report = None
    ias_report_signature = None
    ias_report_signing_certificate = None

    for ext in cert.extensions:
        if ext.oid == ObjectIdentifier(config["SGX_CONSTANTS"]["ias_report_signature_oid"]):
            ias_report_signature = b64decode(ext.value.value)

        if ext.oid == ObjectIdentifier(config["SGX_CONSTANTS"]["ias_report_oid"]):
            ias_report = b64decode(ext.value.value)
        
        if ext.oid == ObjectIdentifier(config["SGX_CONSTANTS"]["ias_report_signing_certificate_oid"]):
            ias_report_signing_certificate = b64decode(ext.value.value)

    return (ias_report, ias_report_signature, ias_report_signing_certificate)

if __name__ == "__main__":

    CONFIGS_FILE = "configs.conf"
    config = ConfigParser()
    config.read(CONFIGS_FILE)

    try:
        cert_str = ssl.get_server_certificate((config["SERVER"]["host"], int(config["SERVER"]["port"])))
        cert = x509.load_pem_x509_certificate(str.encode(cert_str), default_backend())
    except:
        print("Unable to load server certificate! Aborting...")
        exit(-1)

    ias_report, ias_report_signature, ias_report_signing_certificate = get_certificate_extensions(cert)

    if ias_report is None or ias_report_signature is None or ias_report_signing_certificate is None:
        print("The certificate obtained from the server doesn't contain all expected extensions! Aborting...")
        exit(-2)

    if not verify_report_signature(ias_report, ias_report_signature, ias_report_signing_certificate):
        print("Server certificate signature is invalid! Aborting...")
        exit(-3)

    if not verify_mr_enclave(ias_report):
        print("Server MRENCLAVE is incorrect! Aborting...")
        exit(-4)

    if not verify_mr_signer(ias_report):
        print("Server MRSIGNER is incorrect! Aborting...")
        exit(-5)
    
    if not verify_certificate_pubkey(ias_report, cert.public_key()):
        print("Server certificate public key is incorrect! Aborting...")
        exit(-6)
    
    with open(config["SERVER"]["server_cert_path"], "w") as out_file:
        out_file.write(cert_str)
    
    try:
        url = "https://%s:%s%s" % (config["SERVER"]["host"], config["SERVER"]["port"], config["SERVER"]["URI"])
        resp = requests.get(url, verify=config["SERVER"]["server_cert_path"])
        print(resp)
        print("Successfully established a secure connection using the SGX-RA-TLS protocol.\nExiting now...")

    except:
        print("Unable to establish a secure connection using the SGX-RA-TLS protocol! Aborting...")
        exit(-7)