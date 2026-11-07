from __future__ import annotations

from socket import socket
from threading import Lock
import struct
import json

from src.crypto.crypto import Cipher


class Stream:
    def __init__(self, conn: socket, client_id: str, session: dict):
        self.client_id: str = client_id
        self.conn: socket = conn
        self.session: dict = session
        self.cipher: Cipher = Cipher(client_id, session['c2s_key'], session['s2c_key'])
        self.lock: Lock = Lock()


class StreamWriter(Stream):
    def __init__(self, conn: socket, client_id: str, session: dict):
        super().__init__(conn, client_id, session)

    def __call__(self, str_data: str) -> bool:
        '''tcp_frame_len(4B) + nonce(12B) + seq_no(8B) + ciphertext(+tag)(N Bytes)'''
        seq_no: bytes = self.session['seq_send'].to_bytes(8, 'big')
        iv: bytes = self.session['iv_base']
        nonce: bytes = iv + seq_no

        ciphertext: bytes = self.cipher.encrypt(str_data, seq_no, iv)

        raw_packet: bytes = nonce + seq_no + ciphertext
        tcp_frame_len: int = len(raw_packet)

        packet: bytes = tcp_frame_len.to_bytes(4, 'big') + raw_packet

        self.conn.sendall(packet)

        with self.lock:
            self.session['seq_send'] += 1
        return True


class StreamReader(Stream):
    def __init__(self, conn: socket, client_id: str, session: dict):
        super().__init__(conn, client_id, session)

    def parse_json(self, json_string: str) -> dict:
        return json.loads(json_string)

    def _recv_exact(self, size: int) -> bytes | None:
        """Lê exatamente `size` bytes do socket TCP."""
        received = bytearray()
        while len(received) < size:
            block = self.conn.recv(size - len(received))
            if not block:
                return None
            received.extend(block)
        return bytes(received)

    def __call__(self) -> dict | None:
        '''
        Estrutura do frame TCP:
        tcp_frame_len(4B) + nonce(12B) + seq_no(8B) + ciphertext(N Bytes)
        '''
        # 1. Lê os 4 bytes do tamanho do frame
        length_bytes = self._recv_exact(4)
        if not length_bytes:
            return None

        tcp_frame_len = struct.unpack('!I', length_bytes)[0]

        # 2. Lê o corpo do frame
        frame_body = self._recv_exact(tcp_frame_len)
        if not frame_body or len(frame_body) < 20:
            return None

        # 3. Extrai nonce (12B) e seq_no inteiro (8B)
        nonce, seq_no = struct.unpack('!12sQ', frame_body[:20])

        if seq_no != self.session['seq_recv']:
            return None

        with self.lock:
            self.session['seq_recv'] += 1

        ciphertext = frame_body[20:]
        
        # Converte o seq_no inteiro para 8 bytes binários antes de decifrar
        seq_no_bytes = seq_no.to_bytes(8, 'big')

        decdata = self.cipher.decrypt(ciphertext, nonce, seq_no_bytes)

        return self.parse_json(decdata.decode('utf-8'))