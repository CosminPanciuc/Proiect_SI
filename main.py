from client import Client
import struct
import tkinter as tk
from tkinter import filedialog, scrolledtext
import threading
import os
from aes import decrypt_ecb

class SecurePeerGUI:
    def __init__(self, peer:Client):
        self.peer = peer
        self.root = tk.Tk()
        self.root.title("P2P Messenger")

        frame_conn = tk.Frame(self.root)
        frame_conn.pack(pady=5)
        tk.Label(frame_conn, text="Peer IP:").pack(side=tk.LEFT)
        self.ip_entry = tk.Entry(frame_conn, width=15)
        self.ip_entry.pack(side=tk.LEFT)
        self.ip_entry.insert(0, "localhost")
        tk.Label(frame_conn, text="Port:").pack(side=tk.LEFT)
        self.port_entry = tk.Entry(frame_conn, width=5)
        self.port_entry.pack(side=tk.LEFT)
        self.port_entry.insert(0, "5001")
        tk.Button(frame_conn, text="Connect", command=self.connect).pack(side=tk.LEFT)
        tk.Button(frame_conn, text="Listen", command=self.listen).pack(side=tk.LEFT)

        self.log = scrolledtext.ScrolledText(self.root, height=15, width=60, state='disabled')
        self.log.pack(padx=10, pady=5)

        frame_msg = tk.Frame(self.root)
        frame_msg.pack(pady=5)
        self.msg_entry = tk.Entry(frame_msg, width=40)
        self.msg_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(frame_msg, text="Send Message", command=self.send_message).pack(side=tk.LEFT)

        tk.Button(self.root, text="Send File", command=self.send_file).pack(pady=5)

        threading.Thread(target=self.receive_loop, daemon=True).start()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

    def log_message(self, message):
        self.log.configure(state='normal')
        self.log.insert(tk.END, message + "\n")
        self.log.configure(state='disabled')
        self.log.see(tk.END)

    def connect(self):
        host = self.ip_entry.get()
        port = int(self.port_entry.get())
        try:
            self.peer.connect(host, port)
            self.log_message(f"Connected to {host}:{port}")
        except Exception as e:
            self.log_message(f"Connection failed: {e}")

    def listen(self):
        host = self.ip_entry.get()
        port = int(self.port_entry.get())
        try:
            self.peer.listen(host, port)
            self.log_message(f"Listening on {host}:{port}")
        except Exception as e:
            self.log_message(f"Listen failed: {e}")

    def send_message(self):
        msg = self.msg_entry.get()
        if not msg:
            return
        self.peer.send_message(msg.encode())
        self.log_message(f"[Me] {msg}")
        self.msg_entry.delete(0, tk.END)

    def send_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.peer.send_file(file_path)
            self.log_message(f"[Me] Sent file: {os.path.basename(file_path)}")

    def receive_loop(self):
        while True:
            try:
                if self.peer.conn:
                    header = self.peer.conn.recv(1)
                    if not header:
                        continue

                    if header == b'\x01':
                        buffer = b''
                        while True:
                            chunk = self.peer.conn.recv(self.peer.chunk_size)
                            buffer += chunk
                            if len(chunk) < self.peer.chunk_size:
                                break
                        try:
                            msg = decrypt_ecb(buffer, self.peer.aes_key).decode()
                            self.log_message(f"[Peer] {msg}")
                        except Exception as e:
                            self.log_message(f"Failed to decode message: {e}")

                    elif header == b'\x02':
                        # Receive file
                        raw_len = self.peer.conn.recv(4)
                        if not raw_len:
                            continue
                        name_len = struct.unpack("!I", raw_len)[0]

                        encrypted_name = b''
                        while len(encrypted_name) < name_len:
                            encrypted_name += self.peer.conn.recv(name_len - len(encrypted_name))
                        filename = decrypt_ecb(encrypted_name, self.peer.aes_key).decode()

                        buffer = b''
                        while True:
                            chunk = self.peer.conn.recv(self.peer.chunk_size)
                            if not chunk:
                                break
                            buffer += chunk
                            if len(chunk) < self.peer.chunk_size:
                                break

                        decrypted = decrypt_ecb(buffer, self.peer.aes_key)
                        with open(filename, 'wb') as f:
                            f.write(decrypted)
                        self.log_message(f"[Peer] Sent a file {filename}")

            except Exception as e:
                pass


    def on_close(self):
        self.peer.close()
        self.root.destroy()

if __name__ == "__main__":
    
    peer = Client()
    gui = SecurePeerGUI(peer)
