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
            return "RSA", str(public_key.key_size)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return f"ECC ({public_key.curve.name})", str(public_key.key_size)
        elif isinstance(public_key, dsa.DSAPublicKey):
            return "DSA", str(public_key.key_size)
        return "Unknown Classical", str(getattr(public_key, "key_size", "Unknown"))
    except UnsupportedAlgorithm:
        oid = cert.signature_algorithm_oid.dotted_string
        if oid in PQC_OIDS:
            return f"PQC ({PQC_OIDS[oid]})", "N/A"
        return "Unsupported/Unknown", "N/A"

def scan_classical(url, hostname, port=443):
    """Standard Python SSL Scan (Classical Defaults)"""
    row_data = {"Domain (URL)": url, "Hostname": hostname, "Scan_Type": "Classical", "Scan_Status": "Success", "Error_Details": ""}
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version()
                cipher_suite = ssock.cipher()[0]
                der_cert = ssock.getpeercert(binary_form=True)
                
        cert = x509.load_der_x509_certificate(der_cert)
        return parse_cert_to_dict(cert, row_data, tls_version, cipher_suite, "Classical (Standard)")
    except Exception as e:
        row_data["Scan_Status"] = "Failed"
        row_data["Error_Details"] = str(e)
        return row_data

def parse_cert_to_dict(cert, row_data, tls_version, cipher_suite, kem_alg):
    """Parses X509 cert and applies the CBOM dictionary format."""
    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except IndexError:
        cn = row_data["Hostname"]

    key_type, key_size = get_public_key_details(cert)
    now = datetime.now(timezone.utc)
    key_state = "Active" if cert.not_valid_before_utc <= now <= cert.not_valid_after_utc else "Expired/Inactive"

    cert_oid = cert.signature_algorithm_oid.dotted_string
    pqc_algo = PQC_OIDS.get(cert_oid, None)
    
    # If the certificate is PQC (like Dilithium), use that name. Otherwise, use the classical name (like RSA/ECDSA)
    alg_name = pqc_algo if pqc_algo else cert.signature_algorithm_oid._name

    # --- CBOM FORMAT ---
    row_data.update({
        # --- PROTOCOLS ---
        "Protocol_Name": "TLS",
        "Protocol_Version": tls_version,
        "Protocol_Cipher_Suite": cipher_suite,
        "Key_Exchange_Algorithm": kem_alg, 
        
        # --- CERTIFICATES ---
        "Cert_Name": cn,
        "Cert_Subject_Name": cert.subject.rfc4514_string(),
        "Cert_Issuer_Name": cert.issuer.rfc4514_string(),
        "Cert_Not_Valid_Before": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Cert_Not_Valid_After": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Cert_Signature_Algorithm": alg_name,
        "Cert_Public_Key_Ref": f"{key_type} {key_size}-bit",
        "Cert_Format": "X.509",
        
        # --- KEYS ---
        "Key_ID_Serial": str(cert.serial_number),
        "Key_State": key_state,
        "Key_Size": f"{key_size} bits",
        "Key_Activation_Date": cert.not_valid_before_utc.strftime("%Y-%m-%d"),
        
        # --- ALGORITHMS ---
        "Alg_Name": alg_name,
        "Alg_Primitive": "signature",
        "Alg_Classical_Security_Level": f"Matches {key_size}-bit {key_type} strength",
        "Alg_OID": cert_oid,
    })
    
    return row_data

def scan_pqc(url, hostname, port=443):
    """OQS Subprocess Scan (Forcing PQC ML-KEM Key Exchange)"""
    row_data = {"Domain (URL)": url, "Hostname": hostname, "Scan_Type": "PQC Probe", "Scan_Status": "Success", "Error_Details": ""}
    
    cmd = [
        "/usr/bin/openssl", "s_client", 
        "-provider", "default", 
        "-provider", "oqsprovider", 
        "-connect", f"{hostname}:{port}", 
        "-groups", "X25519MLKEM768", 
        "-showcerts"
    ]
    
    try:
        # Pass "Q\n" to mimic typing Q to quit, preventing hangs
        result = subprocess.run(cmd, input="Q\n", capture_output=True, text=True, timeout=15)
        output = result.stdout + result.stderr
        
        # 1. Check for specific handshake failures (like meta.com)
        if "handshake failure" in output or "alert number 40" in output or "invalid argument" in output:
            row_data["Scan_Status"] = "Failed"
            row_data["Error_Details"] = "Server rejected PQC Key Exchange (Classical Only)"
            return row_data

        # 2. Extract TLS Version & Cipher (like google.com)
        tls_match = re.search(r"Protocol\s*:\s*(TLSv1\.[2-3])", output) or re.search(r"New,\s*(TLSv1\.[2-3])", output)
        tls_version = tls_match.group(1).strip() if tls_match else "Unknown"

        cipher_match = re.search(r"Cipher\s*:\s*([A-Za-z0-9_]+)", output) or re.search(r"Cipher is\s*([A-Za-z0-9_]+)", output)
        cipher_suite = cipher_match.group(1).strip() if cipher_match else "Unknown"

        # 3. Extract the Certificate Block
        cert_match = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", output, re.DOTALL)
        if not cert_match:
            row_data["Scan_Status"] = "Failed"
            row_data["Error_Details"] = "No certificate returned by server"
            return row_data
            
        pem_cert = cert_match.group(0).encode('utf-8')
        cert = x509.load_pem_x509_certificate(pem_cert)
        
        # If we got here, the PQC Key Exchange was successful. 
        # The Certificate itself might still be Classical (RSA/ECDSA), which parse_cert_to_dict will detect.
        return parse_cert_to_dict(cert, row_data, tls_version, cipher_suite, "X25519MLKEM768")

    except Exception as e:
        row_data["Scan_Status"] = "Failed"
        row_data["Error_Details"] = str(e)
        return row_data

def generate_batch_cbom(url_list, output_filename="Batch_CBOM.csv"):
    all_cbom_data = []
    
    for url in url_list:
        hostname = clean_hostname(url)
        print(f"\nScanning {hostname}...")
        
        print("  -> Running Classical Probe...")
        all_cbom_data.append(scan_classical(url, hostname))
        
        print("  -> Running PQC Probe...")
        all_cbom_data.append(scan_pqc(url, hostname))
        
    df = pd.DataFrame(all_cbom_data)
    
    # Reorder columns slightly to put key info at the front
    front_cols = ["Hostname", "Scan_Type", "Scan_Status", "Key_Exchange_Algorithm", "Alg_Name", "Protocol_Cipher_Suite"]
    remaining_cols = [c for c in df.columns if c not in front_cols]
    df = df[front_cols + remaining_cols]
    
    df.to_csv(output_filename, index=False)
    print(f"\nSuccess! CBOM data exported to: {output_filename}")
    return df

if __name__ == "__main__":
    target_urls = [
        # IIT / academic
        "iitk.ac.in",
        "iitgn.ac.in",
        "iitb.ac.in",
        "iitd.ac.in",
        "iisc.ac.in",
        "mit.edu",
        "stanford.edu",
        "cmu.edu",

        # PQC / crypto research
        "test.openquantumsafe.org",
        "openquantumsafe.org",
        "pq.cloudflareresearch.com",
        "pq.cloudflareresearch.net",
        "cryptrec.go.jp",

        # Big tech
        "google.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "meta.com",
        "openai.com",
        "groq.com",

        # CDN / security
        "cloudflare.com",
        "fastly.com",
        "akamai.com",
        "imperva.com",
        "sucuri.net",

        # TLS testing sites
        "badssl.com",
        "tls-v1-0.badssl.com",
        "tls-v1-1.badssl.com",
        "sha256.badssl.com",
        "expired.badssl.com",

        # developer / infra
        "github.com",
        "gitlab.com",
        "docker.com",
        "kubernetes.io",
        "nginx.org",

        # misc high-traffic
        "wikipedia.org",
        "reddit.com",
        "stackoverflow.com",
        "twitter.com",
        "linkedin.com"
    ]
    
    df_result = generate_batch_cbom(target_urls)
    
    print("\nPreview of DataFrame:")
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', 1000)
    print(df_result[["Hostname", "Scan_Type", "Scan_Status", "Key_Exchange_Algorithm", "Alg_Name"]].head(8))