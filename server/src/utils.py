from socket import socket, gaierror
import json

def write(writer: socket, data: bytes) -> bool:
    try:
        writer.send(data) # Nada por enquanto
        return True
    except ConnectionResetError:
        return False