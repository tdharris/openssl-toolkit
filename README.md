# openssl-toolkit
This is an OpenSSL certificate toolkit utility leveraging OpenSSL's CLI for Linux. This is a simple wrapper utility for OpenSSL CLI to help automate certificate tasks.

Download <a href="https://github.com/tdharris/openssl-toolkit/releases/download/1.1.0/openssl-toolkit-1.1.0.zip">openssl-toolkit-1.1.0.zip</a> or see below for one-liner download, extract, launch:
```bash
echo https://github.com/tdharris/openssl-toolkit/releases/download/1.1.0/openssl-toolkit-1.1.0.zip \
| xargs wget -qO- -O tmp.zip && unzip -o tmp.zip && rm tmp.zip && ./openssl-toolkit/openssl-toolkit.sh
```

The following tasks are supported:

1. Create certificates:
   - Self-Signed SSL Certificate (key, csr, crt)
   - Private Key & Certificate Signing Request (key, csr)
   - PEM from previous certificates (key, crt, intermediate crts) 

2. Convert certificates:
   - PEM -> DER
   - PEM -> P7B
   - PEM -> PFX
   - DER -> PEM
   - P7B -> PEM
   - P7B -> PFX
   - PFX -> PEM

3. Verify certificates:
   - CSR is signed by private key
   - Public certificate and private key are a keypair
   - 3rd party intermediate chain file and signed public certificate are a keypair
   - Check date validity of certificates

4. Test ssl server:
   - SSL Certificate handshake
   - SSL Server date validity
   - Permitted Protocols

5. Output certificate information:
   - Output the details from a certifticate sign request
   - Output the details from a signed certificate
