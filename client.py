import socket
import threading
from aes import encrypt_ecb, decrypt_ecb
from dh_utils import generate_private_key, generate_public_key, compute_shared_secret, derive_aes_key
import struct
import os

class Client:
    def __init__(self, chunk_size: int = 1024):
        self.chunk_size = chunk_size
        self.conn = None
        self.aes_key = None

    def listen(self, host: str, port: int):
        self.ready = threading.Event()

        def accept_conn():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((host, port))
            s.listen(1)
            self.conn, addr = s.accept()
            self.perform_key_exchange(is_initiator=False)
            self.ready.set()

        thread = threading.Thread(target=accept_conn)
        thread.start()
        self.ready.wait()


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
            file_data = f.read()
        encrypted_file = encrypt_ecb(file_data, self.aes_key)

        filename = os.path.basename(file_path).encode()
        encrypted_filename = encrypt_ecb(filename, self.aes_key)

        # header for file
        self.conn.send(b'\x02')  

        # file name length + name + content 
        self.conn.send(struct.pack("!I", len(encrypted_filename)))
        self.conn.send(encrypted_filename)

        for i in range(0, len(encrypted_file), self.chunk_size):
            self.conn.send(encrypted_file[i:i+self.chunk_size])


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
            
    def send_message(self, msg: str):
        if not self.conn or not self.aes_key:
            raise RuntimeError("Error")
        encrypted = encrypt_ecb(msg, self.aes_key)
        # header for msg
        self.conn.send(b'\x01' + encrypted)


    def receive_msg(self) -> str:
        if not self.conn or not self.aes_key:
            raise RuntimeError("Error")
        buffer = b''
        while chunk := self.conn.recv(self.chunk_size):
            buffer += chunk
            if len(chunk) < self.chunk_size:
                break
        return decrypt_ecb(buffer, self.aes_key)

    def close(self):
        if self.conn:
            self.conn.close()