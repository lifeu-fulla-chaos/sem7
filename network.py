import socket


class NetworkManager:
    def __init__(self, host, port, mode, peer_addr=None):
        self.host = host
        self.port = port
        self.mode = mode
        self.peer_addr = peer_addr
        if self.mode == "udp":
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((self.host, self.port))
        else:
            self.socket = None
        self.conn = None

    def start_server(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        print(f"Server listening on {self.host}:{self.port}")
        print("Waiting for a connection...")
        self.conn, addr = self.socket.accept()  # Blocks until a client connects
        print(f"Connection accepted from {addr}")

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))

    def send_data(self, data):
        if isinstance(data, str):
            data = data.encode()
        if self.mode == "tcp":
            if self.conn:
                self.conn.sendall(data)
            elif self.socket:
                self.socket.sendall(data)
            else:
                raise RuntimeError("No connection available to send data.")
        elif self.mode == "udp":
            if self.socket:
                self.socket.sendto(data, self.peer_addr)  # type: ignore
            else:
                raise RuntimeError("No connection available to send data.")

    def receive_data(self):
        buffer = ""
        if self.mode == "tcp":
            while True:
                if self.conn:
                    chunk = self.conn.recv(4096).decode()
                elif self.socket:
                    chunk = self.socket.recv(4096).decode()
                else:
                    raise RuntimeError("No connection available to receive data.")
                if not chunk:
                    return None
                buffer += chunk
                if "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    return line
        elif self.mode == "udp":
            while True:
                data = self.socket.recv(4096)  # type: ignore
                if not data:
                    return None
                chunk = data.decode()
                buffer += chunk
                if "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    return line

    def close_connection(self):
        if self.conn:
            self.conn.close()
            self.conn = None
        if self.socket:
            self.socket.close()
            self.socket = None
