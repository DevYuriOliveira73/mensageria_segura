'''
Estrutura de dados:

session = {
    client: {
        "writer": StreamWriter, 
        "public_key": pk_C (32B),
        "seq_recv": último seq_no recebido do cliente,
        "seq_send": próximo seq_no para mensagens de controle enviadas pelo servidor, 
        "salt": salt_srv (16B)
    }

}

'''

import socket
import threading

class Server:
    def __init__(self):
        self.sessions: dict[str, str] = {}

    def setup_sock(self, h: str, p: int) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(1)
        s.bind((h, p))
        s.listen(5)
        return s

    def run(self, host: str = '127.0.0.1', port: int = 5000) -> None:
        sock = self.setup_sock(host, port)
        while True:
            try:
                con, client = sock.accept()
                t = threading.Thread(target=self.handle_session, args=(con, client))
                t.start()

            except TimeoutError:
                continue

    def handle_session(self, con, client) -> None:
        while True:
            ...