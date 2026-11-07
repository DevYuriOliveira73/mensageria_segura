import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s : %(message)s'
)


from src.core import Server

server: Server = Server('0.0.0.0', 9000, rsa_skey_path='src/keys/server.key', rsa_cert_path='src/keys/certificado.crt')

