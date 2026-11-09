import socket
import threading
import select
import json
import base64
from threading import Lock
from typing import Any

from src import logging as logger
from src.crypto.crypto import Crypto
from src.utils import get_nonce
from src.stream import StreamWriter, StreamReader


class Server:
    def __init__(self, host: str, port: int, rsa_skey_path: str | None = None, rsa_cert_path: str | None = None):
        self.sock = self.setup_sock(host, port)
        self.sessions: dict[str, dict[str, Any]] = {}
        self.readers: dict[socket.socket, StreamReader] = {}

        self.lock = Lock()
        self.rsa_skey_path = rsa_skey_path
        self.rsa_cert_path = rsa_cert_path

    def setup_sock(self, h: str, p: int) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(1)
        s.bind((h, p))
        s.listen(5)

        logger.info('Servidor configurado')
        logger.info(f'Host: {h}, Port: {p}')
        return s

    def run(self) -> None:
        logger.info('Servidor e handler iniciados')
        handler = threading.Thread(target=self.handle_sessions, daemon=True)
        handler.start()

        while True:
            try:
                con, client = self.sock.accept()
                logger.info(f'Chegada de conexão de {client[0]}')
                t = threading.Thread(target=self.create_session, args=(con,), daemon=True)
                t.start()
            except TimeoutError:
                continue

    def create_session(self, conn: socket.socket) -> str | None:
        with self.lock:
            num_clients: int = len(self.sessions.keys())
            if num_clients >= 5000:
                return
            
        raw_session_obj = self.keys_exchange(conn)
        if not raw_session_obj:
            conn.close()
            return None

        client_id: str = raw_session_obj['client_id']

        with self.lock:
            if client_id in self.sessions:
                conn.close()
                return None

            meta: dict = raw_session_obj['meta']
            pre_session: dict[str, Any] = {
                'writer': None,
                'public_key': meta['pk_C'],  # bytes (32B X25519)
                'iv_base': meta['iv'],
                'seq_recv': 0,
                'seq_send': 0,
                'salt': meta['salt_srv'],
                's2c_key': meta['s2c'],
                'c2s_key': meta['c2s']
            }

            try:
                reader = StreamReader(conn, client_id, pre_session)
                writer = StreamWriter(conn, client_id, pre_session)
                pre_session['writer'] = writer
            except ValueError:
                logger.error('Cliente enviou UUID inválido.')
                return

            self.readers[conn] = reader
            self.sessions[client_id] = pre_session

        self.broadcast('new_user', client_id)
        logger.info(f'Cliente {client_id} conectado')
        return client_id

    def broadcast(self, info: str, client_id: str) -> None:
        with self.lock:
            if info == 'new_user':
                if client_id not in self.sessions:
                    return
                raw_client_pk: bytes = self.sessions[client_id]['public_key']
                client_pk_b64: str = base64.b64encode(raw_client_pk).decode('ascii')
            active_clients = list(self.sessions.items())

        for target_id, session_data in active_clients:
            if info == 'new_user':
                if target_id == client_id:
                    continue
                
                # Notifica o cliente novo sobre os existentes
                existing_pk_b64 = base64.b64encode(session_data['public_key']).decode('ascii')
                self.send_control_message(client_id, info, [target_id, existing_pk_b64])
                
                # Notifica os clientes existentes sobre o novo
                self.send_control_message(target_id, info, [client_id, client_pk_b64])

            elif info == 'user_exit':
                if target_id != client_id:
                    self.send_control_message(target_id, info, [client_id])

    def craft_packet(self, recipient_id: str) -> dict[str, Any]:
        with self.lock:
            session = self.sessions[recipient_id]
            seq_no: int = session['seq_send']
            iv: bytes = session['iv_base']

        nonce: str = base64.b64encode(get_nonce(seq_no, iv)).decode('ascii')

        return {
            "sender_id": "server",
            "recipient_id": recipient_id,
            "seq_no": seq_no,
            "nonce": nonce,
            "control": True,
            "ciphertext": ""
        }

    def send_control_message(self, target_id: str, info: str, data: list) -> None:
        with self.lock:
            if target_id not in self.sessions:
                return
            writer: StreamWriter = self.sessions[target_id]['writer']

        packet = self.craft_packet(target_id)
        packet['ciphertext'] = {
            'info': info,
            'data': data
        }

        try:
            with self.lock:
                writer(json.dumps(packet))
        except Exception as exc:
            logger.error(f"Erro ao enviar mensagem de controle para {target_id}: {exc}")

    def keys_exchange(self, conn: socket.socket) -> dict[str, Any] | None:
        try:
            crypto = Crypto(
                conn=conn, 
                rsa_skey_path=self.rsa_skey_path,
                rsa_cert_path=self.rsa_cert_path
            )
            return crypto.handshake()
        except Exception as exc:
            logger.error(f"Falha no handshake: {exc}")
            return None

    def close_conn(self, client_id: str) -> None:
        with self.lock:
            if client_id not in self.sessions:
                return
            
            session = self.sessions.pop(client_id)
            writer: StreamWriter = session['writer']
            sock = writer.conn
            
            if sock in self.readers:
                del self.readers[sock]
                
            try:
                sock.close()
            except OSError:
                pass

    def handle_sessions(self) -> None:
        while True:
            try:
                with self.lock:
                    sockets_to_watch = list(self.readers.keys())

                if not sockets_to_watch:
                    select.select([], [], [], 0.5)
                    continue

                try:
                    readable, _, _ = select.select(sockets_to_watch, [], [], 0.5)
                except (OSError, ValueError):
                    continue

                for reader_sock in readable:
                    with self.lock:
                        reader: StreamReader | None = self.readers.get(reader_sock)
                    
                    if reader is None:
                        continue

                    try:
                        obj_data: dict | None = reader()
                    except Exception as exc:
                        logger.error(f"Erro na leitura do socket de {getattr(reader, 'client_id', 'desconhecido')}: {exc}")
                        client_id = getattr(reader, 'client_id', None)
                        if client_id:
                            self.close_conn(client_id)
                            self.broadcast('user_exit', client_id)
                        continue

                    if not obj_data:
                        logger.warning(f'Cliente {reader.client_id} desconectado')
                        self.close_conn(reader.client_id)
                        self.broadcast('user_exit', reader.client_id)
                        continue

                    sender_id: str = obj_data.get('sender_id', '')

                    # Prevenção de falsificação de identidade (spoofing)
                    if sender_id != reader.client_id:
                        logger.warning(f'Tentativa de spoofing pelo cliente {reader.client_id}')
                        self.close_conn(reader.client_id)
                        self.broadcast('user_exit', reader.client_id)
                        continue

                    recipient_id: str = obj_data.get('recipient_id', '')
                    
                    with self.lock:
                        recipient_session = self.sessions.get(recipient_id)

                    if recipient_session:
                        obj_data['control'] = False
                        try:
                            with self.lock:
                                recipient_session['writer'](json.dumps(obj_data))
                        except Exception as exc:
                            logger.error(f"Erro ao repassar mensagem para {recipient_id}: {exc}")
                            self.close_conn(recipient_id)
                            self.broadcast('user_exit', recipient_id)
                    else:
                        logger.warning(f'Destinatário {recipient_id} não encontrado/offline')
                        self.send_control_message(sender_id, 'server_alert', ['cliente offline'])

            except Exception as loop_exc:
                logger.error(f"Erro na thread handle_sessions: {loop_exc}")