import ssl
import socket
import subprocess
import re
import pandas as pd
from urllib.parse import urlparse
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.exceptions import UnsupportedAlgorithm

# --- DICTIONARY OF KNOWN PQC OIDs ---
PQC_OIDS = {
    "1.3.6.1.4.1.2.267.7.4.4": "Dilithium2",
    "1.3.6.1.4.1.2.267.7.6.5": "Dilithium3",
    "1.3.6.1.4.1.2.267.7.8.7": "Dilithium5",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44", 
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65", 
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87", 
    "1.3.9999.3.1": "Falcon-512",
    "1.3.9999.3.4": "Falcon-1024",
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "1.3.9999.6.4.13": "SPHINCS+-SHA2-128f-simple"
}

def clean_hostname(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return urlparse(url).hostname or url

def get_public_key_details(cert):
    try:
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            return "RSA", public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return f"ECC ({public_key.curve.name})", public_key.key_size
        elif isinstance(public_key, dsa.DSAPublicKey):
            return "DSA", public_key.key_size
        return "Unknown Classical", getattr(public_key, "key_size", 0)
    except UnsupportedAlgorithm:
        oid = cert.signature_algorithm_oid.dotted_string
        if oid in PQC_OIDS:
            return f"PQC ({PQC_OIDS[oid]})", 0 
        return "Unsupported/Unknown", 0

def calculate_nist_score(is_pqc_success, tls_version, key_type, key_size):
    if is_pqc_success:
        return "A+ (Quantum-Resilient: Supports ML-KEM)"
    if tls_version not in ["TLSv1.2", "TLSv1.3"]:
        return "F (Non-Compliant: Deprecated TLS Version)"
    if "RSA" in key_type and key_size < 2048:
        return "C (Weak: RSA key size < 2048 bits)"
    if "ECC" in key_type and key_size < 256:
        return "C (Weak: ECC key size < 256 bits)"
    if tls_version == "TLSv1.3":
        return "B (Classical Strong: TLS 1.3)"
    return "B- (Classical Acceptable: TLS 1.2)"

def parse_cert_to_dict(cert, row_data, tls_version, cipher_suite, is_pqc_success=False):
    """Parses X509 cert and applies the exact CBOM Table 9 format."""
    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except IndexError:
        cn = row_data["Hostname"]

    key_type, key_size = get_public_key_details(cert)
    now = datetime.now(timezone.utc)
    key_state = "Active" if cert.not_valid_before_utc <= now <= cert.not_valid_after_utc else "Expired/Revoked"

    cert_oid = cert.signature_algorithm_oid.dotted_string
    pqc_algo = PQC_OIDS.get(cert_oid, None)
    alg_name = pqc_algo if pqc_algo else getattr(cert.signature_algorithm_oid, '_name', "Unknown")

    nist_score = calculate_nist_score(is_pqc_success, tls_version, key_type, key_size)

    row_data.update({
        "NIST_Security_Score": nist_score,
        "Alg_Name": alg_name,
        "Alg_Asset_Type": "algorithm",
        "Alg_Primitive": "signature" if "RSA" in alg_name.upper() or "ECDSA" in alg_name.upper() or pqc_algo else "key exchange",
        "Alg_Mode": "gcm" if cipher_suite and "GCM" in cipher_suite else "cbc" if cipher_suite and "CBC" in cipher_suite else "Unknown",
        "Alg_Crypto_Functions": "encryption, decryption, authentication" if cipher_suite else "signature verification",
        "Alg_Classical_Security_Level": f"{key_size} bits" if key_size else "N/A",
        "Alg_OID": cert_oid,
        "Key_Name": f"{cn} {key_type} Key",
        "Key_Asset_Type": "key",
        "Key_id": str(cert.serial_number),
        "Key_state": key_state,
        "Key_size": f"{key_size} bits",
        "Key_Creation_Date": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Key_Activation_Date": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Protocol_Name": "TLS",
        "Protocol_Asset_Type": "protocol",
        "Protocol_Version": tls_version,
        "Protocol_Cipher_Suites": cipher_suite,
        "Protocol_OID": "N/A", 
        "Cert_Name": cn,
        "Cert_Asset_Type": "certificate",
        "Cert_Subject_Name": cert.subject.rfc4514_string(),
        "Cert_Issuer_Name": cert.issuer.rfc4514_string(),
        "Cert_Not_Valid_Before": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Cert_Not_Valid_After": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Cert_Signature_Algorithm_Reference": alg_name,
        "Cert_Subject_Public_Key_Reference": f"{key_type} {key_size}-bit",
        "Cert_Format": "X.509",
        "Cert_Extension": ".crt"
    })
    return row_data

def scan_pqc(hostname, port=443):
    row_data = {"Hostname": hostname, "Scan_Type": "PQC Probe", "Scan_Status": "Success", "Error_Details": ""}
    cmd = [
        "/usr/bin/openssl", "s_client", 
        "-provider", "default", "-provider", "oqsprovider", 
        "-connect", f"{hostname}:{port}", "-groups", "X25519MLKEM768", "-showcerts"
    ]
    try:
        result = subprocess.run(cmd, input="Q\n", capture_output=True, text=True, timeout=15)
        output = result.stdout + result.stderr
        
        failure_triggers = ["handshake failure", "alert number 40", "invalid argument", "errno=104", "no peer certificate available", "Cipher is (NONE)"]
        if any(trigger in output for trigger in failure_triggers):
            row_data["Scan_Status"] = "Failed"
            row_data["Error_Details"] = "Server rejected PQC Key Exchange"
            return row_data

        tls_match = re.search(r"Protocol\s*:\s*(TLSv1\.[2-3])", output) or re.search(r"New,\s*(TLSv1\.[2-3])", output)
        tls_version = tls_match.group(1).strip() if tls_match else "Unknown"
        cipher_match = re.search(r"Cipher\s*:\s*([A-Za-z0-9_]+)", output) or re.search(r"Cipher is\s*([A-Za-z0-9_]+)", output)
        cipher_suite = cipher_match.group(1).strip() if cipher_match else "Unknown"

        cert_match = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", output, re.DOTALL)
        if not cert_match:
            row_data["Scan_Status"] = "Failed"
            row_data["Error_Details"] = "No certificate returned"
            return row_data
            
        cert = x509.load_pem_x509_certificate(cert_match.group(0).encode('utf-8'))
        return parse_cert_to_dict(cert, row_data, tls_version, cipher_suite, is_pqc_success=True)
    except Exception as e:
        row_data["Scan_Status"] = "Failed"
        row_data["Error_Details"] = str(e)
        return row_data

def scan_classical(hostname, port=443):
    row_data = {"Hostname": hostname, "Scan_Type": "Classical Fallback", "Scan_Status": "Success", "Error_Details": ""}
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version()
                cipher_suite = ssock.cipher()[0]
                der_cert = ssock.getpeercert(binary_form=True)
                
        cert = x509.load_der_x509_certificate(der_cert)
        return parse_cert_to_dict(cert, row_data, tls_version, cipher_suite, is_pqc_success=False)
    except Exception as e:
        row_data["Scan_Status"] = "Failed"
        row_data["Error_Details"] = str(e)
        return row_data

def generate_batch_cbom(url_list, output_filename="Batch_CBOM.csv"):
    all_cbom_data = []
    
    for url in url_list:
        hostname = clean_hostname(url)
        print(f"\nScanning {hostname}...")
        
        # 1. Try PQC First
        result = scan_pqc(hostname)
        
        # 2. If PQC fails, fallback to Classical
        if result["Scan_Status"] == "Failed":
            print(f"  -> PQC rejected ({result['Error_Details']}). Falling back to Classical...")
            result = scan_classical(hostname)
        else:
            print("  -> PQC Probe Successful!")
            
        all_cbom_data.append(result)
        
    df = pd.DataFrame(all_cbom_data)
    
    # Organize columns
    front_cols = ["Hostname", "Scan_Type", "Scan_Status", "NIST_Security_Score"]
    remaining_cols = [c for c in df.columns if c not in front_cols]
    df = df[front_cols + remaining_cols]
    
    df.to_csv(output_filename, index=False)
    print(f"\nSuccess! CBOM data exported to: {output_filename}")
    return df

if __name__ == "__main__":
    target_urls = ["google.com", "linkedin.com", "cloudflare.com"]
    df_result = generate_batch_cbom(target_urls)
    
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', 1000)
    print("\nPreview:")
    print(df_result[["Hostname", "Scan_Type", "Scan_Status", "NIST_Security_Score"]].head(6))