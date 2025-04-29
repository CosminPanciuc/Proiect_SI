import socket
import threading
from aes import encrypt_ecb, decrypt_ecb
from dh_utils import generate_private_key, generate_public_key, compute_shared_secret, derive_aes_key

class Client:
    def __init__(self, chunk_size: int = 1024):
        self.chunk_size = chunk_size
        self.conn = None
        self.aes_key = None

    def listen(self, host: str, port: int):
        def accept_conn():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((host, port))
            s.listen(1)
            self.conn, addr = s.accept()
            self.perform_key_exchange(is_initiator=False)

        thread = threading.Thread(target=accept_conn)
        thread.start()

    def connect(self, host: str, port: int):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        self.conn = s
        self.perform_key_exchange(is_initiator=True)

    def perform_key_exchange(self, is_initiator: bool):
        private_key = generate_private_key()
        public_key = generate_public_key(private_key)

        if is_initiator:
            self.conn.sendall(public_key.to_bytes(256, 'big'))
            peer_public_key = int.from_bytes(self.conn.recv(256), 'big')
        else:
            peer_public_key = int.from_bytes(self.conn.recv(256), 'big')
            self.conn.sendall(public_key.to_bytes(256, 'big'))

        shared_secret = compute_shared_secret(peer_public_key, private_key)
        self.aes_key = derive_aes_key(shared_secret)

    def send_file(self, file_path: str):
        if not self.conn or not self.aes_key:
            raise RuntimeError("Error")
        with open(file_path, 'rb') as f:
            data = f.read()
            encrypted = encrypt_ecb(data, self.aes_key)
            self.conn.sendall(encrypted)

    def receive_file(self, save_path: str):
        if not self.conn or not self.aes_key:
            raise RuntimeError("Error")
        buffer = b''
        while chunk := self.conn.recv(self.chunk_size):
            buffer += chunk
            if len(chunk) < self.chunk_size:
                break
        decrypted = decrypt_ecb(buffer, self.aes_key)
        with open(save_path, 'wb') as f:
            f.write(decrypted)

    def close(self):
        if self.conn:
            self.conn.close()