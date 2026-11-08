import socket
import json
import base64
import uuid
import secrets
import threading

from pathlib import Path

from Crypto.Cipher import AES

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    x25519, padding, rsa
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ==================================================
# CONFIGURAÇÃO
# ==================================================

HOST = "127.0.0.1"
PORT = 9000

CERT_PATH = "./certificado.crt"

MAX_FRAME_SIZE = 10 * 1024 * 1024


# ==================================================
# RECEBIMENTO EXATO
# ==================================================

def recv_exact(sock, size):

    data = bytearray()

    while len(data) < size:

        chunk = sock.recv(size - len(data))

        if not chunk:
            return None

        data.extend(chunk)

    return bytes(data)


# ==================================================
# HANDSHAKE JSON
# ==================================================

def recv_handshake_json(sock):

    decoder = json.JSONDecoder()
    response = bytearray()

    while len(response) < 1024 * 1024:

        chunk = sock.recv(1)

        if not chunk:
            raise ConnectionError("Servidor encerrou o handshake.")

        response.extend(chunk)

        try:
            text = response.decode("utf-8")
            obj, end = decoder.raw_decode(text)

            if text[end:].strip() == "":
                return obj

        except (UnicodeDecodeError, json.JSONDecodeError):
            continue

    raise ValueError("Resposta de handshake muito grande.")


# ==================================================
# CERTIFICADO E ASSINATURA
# ==================================================

def load_certificate(data):

    try:
        return x509.load_pem_x509_certificate(data)

    except ValueError:
        return x509.load_der_x509_certificate(data)


def validate_server(response, pk_C, client_id):

    cert_data = base64.b64decode(
        response["server_crt"],
        validate=True
    )

    pk_S = base64.b64decode(
        response["pk_S"],
        validate=True
    )

    signature = base64.b64decode(
        response["signature"],
        validate=True
    )

    salt_srv = base64.b64decode(
        response["salt_srv"],
        validate=True
    )

    received_cert = load_certificate(cert_data)
    pinned_cert = load_certificate(
        Path(CERT_PATH).read_bytes()
    )

    received_fp = received_cert.fingerprint(hashes.SHA256())
    pinned_fp = pinned_cert.fingerprint(hashes.SHA256())

    if received_fp != pinned_fp:
        raise RuntimeError("Certificado não corresponde ao pin!")

    public_key = received_cert.public_key()

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise RuntimeError("Certificado não contém chave RSA.")

    signed_data = (
        pk_S
        + pk_C
        + client_id.encode("utf-8")
        + salt_srv
    )

    public_key.verify(
        signature,
        signed_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=hashes.SHA256().digest_size
        ),
        hashes.SHA256()
    )

    print("[+] Certificado pinado validado.")
    print("[+] Assinatura RSA-PSS validada.")

    return pk_S, salt_srv


# ==================================================
# DERIVAÇÃO DAS CHAVES
# ==================================================

def derive_keys(secret, salt_srv):

    c2s = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt_srv,
        info=b"c2s"
    ).derive(secret)

    s2c = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt_srv,
        info=b"s2c"
    ).derive(secret)

    return c2s, s2c


# ==================================================
# HANDSHAKE COMPLETO
# ==================================================

def handshake(sock, client_id):

    private_key = x25519.X25519PrivateKey.generate()

    pk_C = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    request = {
        "client_id": client_id,
        "pkey": base64.b64encode(pk_C).decode("ascii")
    }

    sock.sendall(json.dumps(request).encode("utf-8"))

    print("[+] Chave pública enviada.")

    response = recv_handshake_json(sock)

    pk_S, salt_srv = validate_server(
        response,
        pk_C,
        client_id
    )

    server_public = x25519.X25519PublicKey.from_public_bytes(pk_S)

    secret = private_key.exchange(server_public)

    c2s, s2c = derive_keys(secret, salt_srv)

    print("[+] X25519 estabelecido.")
    print("[+] HKDF concluído.")

    return c2s, s2c


# ==================================================
# GERAÇÃO DE UM FRAME GCM LEGÍTIMO
# ==================================================

def build_valid_frame(c2s_key, client_id, recipient_id):

    seq_no = 0
    seq_bytes = seq_no.to_bytes(8, "big")

    # O servidor não valida o IV_base recebido.
    # Ele utiliza o nonce recebido na operação GCM.
    iv_base = secrets.token_bytes(4)

    nonce = iv_base + seq_bytes

    packet = {
        "sender_id": client_id,
        "recipient_id": recipient_id,
        "seq_no": seq_no,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "control": False,
        "ciphertext": ""
    }

    plaintext = json.dumps(packet).encode("utf-8")

    cipher = AES.new(
        c2s_key,
        AES.MODE_GCM,
        nonce=nonce
    )

    aad = uuid.UUID(client_id).bytes + seq_bytes
    cipher.update(aad)

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    body = nonce + seq_bytes + ciphertext + tag

    frame = (
        len(body).to_bytes(4, "big")
        + body
    )

    return frame


# ==================================================
# RECEBIMENTO DO SERVIDOR
# ==================================================

def receive_loop(sock):

    while True:

        try:
            header = recv_exact(sock, 4)

            if header is None:
                print("\n[!] Servidor encerrou a conexão.")
                return

            size = int.from_bytes(header, "big")

            if size < 20 or size > MAX_FRAME_SIZE:
                print("\n[!] Frame recebido com tamanho inválido.")
                return

            body = recv_exact(sock, size)

            if body is None:
                print("\n[!] Frame recebido incompleto.")
                return

            print(f"\n[<] Frame recebido: {size + 4} bytes")
            print("[<] HEX:", (header + body).hex())

        except OSError:
            return


# ==================================================
# EXECUÇÃO DO TESTE
# ==================================================

def run_test(test_number, recipient_id):

    client_id = str(uuid.uuid4())

    print("\n[*] Nova sessão:", client_id)

    sock = socket.create_connection((HOST, PORT))

    try:
        c2s_key, _ = handshake(sock, client_id)

        frame = build_valid_frame(
            c2s_key,
            client_id,
            recipient_id
        )

        print(f"[+] Frame válido gerado: {len(frame)} bytes.")

        receiver = threading.Thread(
            target=receive_loop,
            args=(sock,),
            daemon=True
        )

        receiver.start()

        # ------------------------------------------
        # TESTE 1 - BITFLIP
        # ------------------------------------------

        if test_number == 1:

            print("\n=== BITFLIP ===")
            print("Frame original:")
            print(frame.hex())

            value = input(
                "\nByte a adulterar (Enter = último byte da tag): "
            ).strip()

            offset = len(frame) - 1 if not value else int(value)

            # O cabeçalho ocupa 4 bytes.
            # Nonce + seq_no ocupam mais 20 bytes.
            if not 24 <= offset < len(frame):
                raise ValueError(
                    "Offset deve apontar para ciphertext ou tag."
                )

            modified = bytearray(frame)

            # Inverte exatamente um bit.
            modified[offset] ^= 0x01

            print(f"\n[+] Bitflip no byte {offset}.")
            print("[+] Pacote adulterado:")
            print(bytes(modified).hex())

            sock.sendall(modified)

            print("\n[+] Pacote adulterado enviado.")
            print("[*] Esperado: falha de autenticação GCM no servidor.")

        # ------------------------------------------
        # TESTE 2 - REPLAY
        # ------------------------------------------

        elif test_number == 2:

            print("\n=== REPLAY ===")

            print("[+] Enviando frame legítimo...")
            sock.sendall(frame)

            print("[+] Primeiro envio realizado.")

            print("\n[+] Reenviando exatamente o mesmo frame...")
            sock.sendall(frame)

            print("[+] Replay enviado.")
            print("[*] Esperado: rejeição do segundo envio por seq_no.")

        # ------------------------------------------
        # TESTE 3 - FRAMING INVÁLIDO
        # ------------------------------------------

        elif test_number == 3:

            print("\n=== FRAMING INVÁLIDO ===")

            body = frame[4:]

            actual_size = len(body)
            declared_size = actual_size + 1

            print(f"[+] Tamanho real: {actual_size}")
            print(f"[+] Tamanho declarado: {declared_size}")

            malformed = (
                declared_size.to_bytes(4, "big")
                + body
            )

            sock.sendall(malformed)

            # Informa ao servidor que não haverá mais bytes.
            # Ele continuará esperando o byte que falta
            # até detectar EOF.
            sock.shutdown(socket.SHUT_WR)

            print("\n[+] Frame truncado enviado.")
            print("[*] Esperado: detecção de frame incompleto e desconexão.")

        print("\n[*] Pressione ENTER para encerrar esta sessão.")
        input()

    finally:
        sock.close()


# ==================================================
# MENU
# ==================================================

def main():

    print("""
========================================
       MENSAGERIA - SECURITY TESTS
========================================

1 - Mensagem adulterada (Bitflip)
2 - Replay de frame
3 - Framing inválido
0 - Sair

========================================
""")

    try:
        recipient_id = str(
            uuid.UUID(input("UUID do destinatário: ").strip())
        )
    except ValueError:
        print("[!] UUID inválido.")
        return

    while True:

        option = input("\nSelecione o teste: ").strip()

        if option == "0":
            break

        if option not in ("1", "2", "3"):
            print("[!] Opção inválida.")
            continue

        try:
            run_test(int(option), recipient_id)

        except Exception as exc:
            print(f"\n[!] Erro: {exc}")

    print("\n[*] Testes encerrados.")


if __name__ == "__main__":
    main()