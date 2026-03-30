# How to setup openssl with PQC algos
OQS - Open Quantumn Safe 
By doing this you are effectively upgrading your computers native OpenSSL to understand Post-Quantumn algorithms

Step 01 INstall build dependencies
sudo apt update
sudo apt install git cmake gcc ninja-build libssl-dev

Step 02 Biuld and install liboqs

git clone -b main https://github.com/open-quantum-safe/liboqs.git
cd liboqs

mkdir build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON ..

ninja
sudo ninja install

cd ../..


Step 03 Build and install oqs provider

git clone -b main https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider

cmake -S . -B _build -GNinja
cmake --build _build

sudo cmake --install _build

Step 04 Configure Open SSL to use provider

find where is the computer's openssl to load this new plugin
openssl version -d

open the openssl.cnf file and add the following lines to respective sectors
```conf
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
```

sudo ldconfig to ensure system recognizes new libraries. it is like refresing the linker


Step 05 Verification
openssl list -providers  should show oqs provider along with default ones

open-ssl list -kem-algorithms  check for available ciphers



# Keywords related to above setup

## ninja 
Ninja is a small, fast build system used to compile software projects.
In simple terms

Ninja executes build steps (compile, link, etc.).

Another tool like CMake usually generates the Ninja build files.

Ninja then runs those steps efficiently.

Why developers use Ninja

⚡ Very fast – optimized for speed
🧩 Simple – minimal features, only build execution
🔁 Incremental builds – rebuilds only what changed

Ninja mainly works with a build file called build.ninja. This file contains the instructions Ninja needs to compile a project.

## oqsprovider and liboqs


Liboqs : This is the core library.

It implements post-quantum cryptographic algorithms such as:
CRYSTALS-Kyber
CRYSTALS-Dilithium
Falcon
SPHINCS+
It provides C implementations and APIs to use these algorithms.

oqs-provider: This integrates liboqs with OpenSSL. It is a provider module for OpenSSL. Meaning it lets OpenSSL use post-quantum algorithms from liboqs.




# understanding how the code works
most part will be commented in the code itself

Okay so we are just running openssl with standard group provided by nist
'''bash
echo "Q" | openssl s_client  -provider oqsprovider -connect meta.com:443 -groups mlkem768 
CONNECTED(00000003)
40E738CD5F750000:error:0A000410:SSL routines:ssl3_read_bytes:sslv3 alert handshake failure:../ssl/record/rec_layer_s3.c:1599:SSL alert number 40
no peer certificate available
No client certificate CA names sent
SSL handshake has read 7 bytes and written 1436 bytes
Verification: OK
New, (NONE), Cipher is (NONE)
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
'''


if the algorithm is not supported then it will not ocnnect and giev output like above

---
You have just discovered a fundamental truth about how the internet is migrating to Post-Quantum Cryptography!

The reason your script is filling up the signature fields with RSA and SHA is because Google's certificate actually IS an RSA-SHA256 certificate. Your Python script is not broken; it is accurately reporting exactly what the server sent. If you look closely at the terminal output you just pasted for google.com, the server explicitly tells you it is using classical math for its identity:

    sigalg: RSA-SHA256

    Peer signature type: ECDSA

Why is this happening if it's "PQC Safe"?
Because the internet is currently using a Hybrid Approach.
There are two completely different cryptographic tasks happening here:    
1. The Key Exchange (The Tunnel): How you and Google securely agree on a secret password to encrypt your traffic. Google has upgraded this to PQC (X25519MLKEM768).

2. The Certificate (The ID Badge): How Google proves it is actually Google and not a hacker. Google has NOT upgraded this yet. They still use Classical RSA/ECDSA.

This is why we added the Key_Exchange_Algorithm column to your CBOM. For modern websites like Google and Cloudflare, your CBOM will show X25519MLKEM768 for the connection, but RSA/ECDSA for the certificate. This is currently the highest standard of security implemented by major tech companies.
---


So certs are still in rsa.
For public websites, true end-to-end PQC does not yet exist because while the key exchange is quantum-safe, public Certificate Authorities have not yet upgraded to issuing Post-Quantum certificates.



# openssl commands
echo "Q" | openssl s_client  -provider oqsprovider -connect google.com:443 -groups X25519MLKEM768
echo "Q" | openssl s_client  -provider oqsprovider -connect google.com:443 -groups X25519MLKEM768

echo "Q" | openssl s_client  -provider oqsprovider -connect linkedin.com:443 -groups X25519MLKEM768



openssl list -kem-algorithms -provider oqsprovider



# Scoring of algorithms

The calculate_nist_score() function categorizes domains based on cryptographic agility and strength:

    A+ (Quantum-Resilient): The domain successfully negotiates a connection using X25519MLKEM768 (or similar PQC KEMs). This aligns with NIST FIPS 203.

    B (Classical Strong): The domain rejects PQC but successfully negotiates TLS 1.3 with strong keys (RSA ≥ 2048 or ECC ≥ 256). This adheres strictly to NIST SP 800-52 Rev 2 guidelines for current classical setups.

    B- (Classical Acceptable): Falls back to TLS 1.2 with strong keys. Still compliant, but less optimal than TLS 1.3.

    C (Weak): Uses compliant TLS versions but weak key parameters (e.g., RSA 1024-bit).

    F (Non-Compliant): Uses deprecated TLS versions (TLS 1.1 or SSLv3).