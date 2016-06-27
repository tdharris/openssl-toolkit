# openssl-toolkit
This is an OpenSSL certificate toolkit utility leveraging OpenSSL's CLI for Linux. The following tasks are supported:

1. Create certificates:
  - Self-Signed SSL Certificate (key, csr, crt)
  - Private Key & Certificate Signing Request (key, csr)
  - PEM with key and entire trust chain

2. Convert certificates:
  - PEM -> DER
  - PEM -> P7B
  - PEM -> PFX
  - DER -> PEM
  - P7B -> PEM
  - P7B -> PFX
  - PFX -> PEM

3. Verify certificates:
  - CSR is a public key from the private key
  - Signed certificate is the public key from the private key
  - Chain file applies to the signed certificate (complete ssl chain)
  - Check date validity of certificates

4. Test ssl server:
  - SSL Certificate handshake
  - SSL Server date validity
  - Permitted Protocols

5. Output certificate information:
  - Output the details from a certifticate sign request
  - Output the details from a signed certificate
