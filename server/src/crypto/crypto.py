import base64
import secrets
import uuid
from socket import socket

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from Crypto.Cipher import AES
from Crypto.Hash import SHA256 as cryptoSHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss


def sign(sk_S: bytes, pk_S: bytes, pk_C: bytes, client_id: str, salt_srv: bytes) -> bytes:
    client_id_bytes: bytes = client_id.encode('utf-8')
    pre_digest: bytes = pk_S + pk_C + client_id_bytes + salt_srv

    digest = cryptoSHA256.new(pre_digest)
    signature = pss.new(sk_S).sign(digest)
    return signature

from src.crypto.rwriter import StreamRW

class Crypto:
    def __init__(self, conn: socket, rsa_skey_path: str, rsa_cert_path: str):
        self.conn: socket = conn
        self.salt_srv: bytes = secrets.token_bytes(16)

        with open(rsa_skey_path, 'rb') as f:
            self.rsa_skey = RSA.import_key(f.read())

        with open(rsa_cert_path, 'rb') as f:
            self.rsa_cert = base64.b64encode(f.read()).decode('utf-8')

    def handshake(self) -> dict | None:
        if not self.rsa_skey:
            raise Exception('Impossível prosseguir com a troca de chaves sem a chave privada RSA')

        srw = StreamRW(self.conn, self.rsa_skey, self.rsa_cert, self.salt_srv)

        secret: bytes | None = self.get_ecdhe_x25519_secret(srw)
        if not secret:
            return None

        c2s, s2c = self.derive_key(secret)

        session_data: dict = {
            "client_id": srw.client_id,
            "meta": {
                "pk_C": srw.pk_C,
                "c2s": c2s,
                "s2c": s2c,
                "salt_srv": self.salt_srv,
                "iv": secrets.token_bytes(4)
            }
        }
        return session_data

    def derive_key(self, secret: bytes) -> tuple[bytes, bytes]:
        c2s: bytes = HKDF(
            algorithm=SHA256(),
            length=16,
            salt=self.salt_srv,
            info=b'c2s'
        ).derive(secret)

        s2c: bytes = HKDF(
            algorithm=SHA256(),
            length=16,
            salt=self.salt_srv,
            info=b's2c'
        ).derive(secret)

        return c2s, s2c


    def get_ecdhe_x25519_secret(self, srw: StreamRW) -> bytes | None:
        c_packet: dict[str, str] | None = srw.read()
        if not c_packet:
            return None

        client_id: str = c_packet.get('client_id')
        raw_client_pkey_x25519: str = c_packet.get('pkey')

        if not raw_client_pkey_x25519 or not client_id:
            srw.write(500, 'server_error', 'Invalid JSON')
            self.conn.close()
            return None

        client_key_bytes: bytes = base64.b64decode(raw_client_pkey_x25519)

        srw.set_client_id(client_id)
        srw.set_pk_c(client_key_bytes)

        client_pkey_x25519: X25519PublicKey = X25519PublicKey.from_public_bytes(client_key_bytes)
        server_skey_x25519: X25519PrivateKey = X25519PrivateKey.generate()
        server_pkey_x25519: X25519PublicKey = server_skey_x25519.public_key()

        server_pkey_x2_bytes: bytes = server_pkey_x25519.public_bytes_raw()
        srw.write(server_pkey_x2_bytes)

        common_x25519_secret: bytes = server_skey_x25519.exchange(client_pkey_x25519)
        return common_x25519_secret


class Cipher:
    def __init__(self, client_id: str, c2s: bytes, s2c: bytes):
        self.client_id: str = client_id
        # Converte o UUID em string de 36 caracteres para seus 16 bytes binários
        self.client_id_bytes: bytes = uuid.UUID(client_id).bytes
        self.c2s_key: bytes = c2s
        self.s2c_key: bytes = s2c

    def encrypt(self, plaintext: str, seq_send: bytes | int, iv: bytes) -> bytes:
        if isinstance(seq_send, int):
            seq_send = seq_send.to_bytes(8, 'big')

        nonce = iv + seq_send
        cipher = AES.new(
            key=self.s2c_key, 
            mode=AES.MODE_GCM, 
            nonce=nonce
        )

        aad = b'server' + seq_send
        cipher.update(aad)

        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        return ciphertext + tag

    def decrypt(self, ciphertext: bytes, nonce: bytes, seq_no: bytes | int) -> bytes:
        if isinstance(seq_no, int):
            seq_no = seq_no.to_bytes(8, 'big')

        tag: bytes = ciphertext[-16:]
        encrypted_data: bytes = ciphertext[:-16]

        cipher = AES.new(
            key=self.c2s_key,
            mode=AES.MODE_GCM,
            nonce=nonce
        )

        # AAD do Transporte C2S: UUID binário (16B) + seq_no (8B)
        aad = self.client_id_bytes + seq_no
        cipher.update(aad)

        data: bytes = cipher.decrypt_and_verify(encrypted_data, tag)
        return data