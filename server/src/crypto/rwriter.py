import json
import base64
from socket import socket

from src.crypto.crypto import sign


'''
text possíveis:

{
    "client_pkey": [
        "client_id", "key_in_base64"
    ]
}

{
    "server_auth": [
        "pk_S (b64)", "server.crt (b64)", "rsa_sign (b64)", "salt_srv (b64)" 
    ]
}

{
    "server_error": [
        "Invalid JSON"
    ]
}

'''


class StreamRW:
    '''Reader e Writer usado apenas no handshake'''
    def __init__(self, client: socket, rsa_skey: bytes, rsa_cert: bytes, salt_srv: bytes):
        self.client: socket = client
        self.rsa_skey: bytes = rsa_skey
        self.salt_srv: bytes = salt_srv
        self.rsa_cert: bytes = rsa_cert

        self.pk_C: bytes = b''
        self.client_id: str = ''

    def read(self) -> dict[str, str] | None:
        raw_data: bytes = self.client.recv(1024)
        if not raw_data:
            return None

        data: str = raw_data.decode('utf-8')

        try:
            dict_data: dict[str, str] = json.loads(data)
            return dict_data
        except json.JSONDecodeError:
            return None


    def write(self, pk_S: bytes) -> None:
        signature: bytes = sign(self.rsa_skey, pk_S, self.pk_C, self.client_id, self.salt_srv)
        packet: dict = {
            'pk_S': base64.b64encode(pk_S).decode('utf-8'),
            'server_crt': self.rsa_cert,
            'signature': base64.b64encode(signature).decode('utf-8'),
            'salt_srv': base64.b64encode(self.salt_srv).decode('utf-8')
        }   

        json_packet: str = json.dumps(packet)

        self.client.send(json_packet.encode('utf-8'))

    def set_pk_c(self, pk_C) -> None:
        self.pk_C = pk_C

    def set_client_id(self, client_id: str) -> None:
        self.client_id = client_id
