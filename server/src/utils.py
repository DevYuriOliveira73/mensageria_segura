from socket import socket
import json

def craft_packet(recipient_id: str, seq_no: int, nonce: str) -> dict[str, str]:
    '''Monta um dicionario'''
    obj_response: dict = {
        "sender_id": "server",
        "recipient_id": recipient_id,
        "seq_no": seq_no,
        "nonce": nonce,
        "control": False,
        "ciphertext": ""
    }

    return obj_response


def get_nonce(seq_no: int, iv: bytes) -> bytes:
    seq_no: bytes = seq_no.to_bytes(8, 'big')
    nonce: bytes = iv + seq_no

    return nonce

def process_data(data: bytes) -> dict[str, str] | None:
    raw_data = data.decode('utf-8')

    try:
        obj_data = json.loads(raw_data)
    except json.JSONDecodeError:
        return None
    return obj_data


