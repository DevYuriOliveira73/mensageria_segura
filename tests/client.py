from cryptography import x509

with open('certificado.crt', 'rb') as f:
    cert_data = f.read()

cert = x509.load_pem_x509_certificate(cert_data)
pkey = cert.public_key()

print(pkey)