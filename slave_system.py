import logging
import threading
import numpy as np  # type: ignore
from lorenz_system import LorenzSystem, LorenzParameters
from encryption import *
from master_system import RECV_UDP
from rsa_sharing import generate_rsa_keys, decrypt_master_key, derive_keys
from network import NetworkManager

HOST, PORT = "0.0.0.0", 3000
RECV_HOST = "192.168.0.113"
UDP_PORT, RECV_UDP = 4001, 4000
logging.basicConfig(level=logging.INFO)


class SlaveSystem:
    def __init__(self):
        self.sys = LorenzSystem(LorenzParameters(sigma=10.0, rho=28.0, beta=8 / 3))
        self.tcpManager = NetworkManager(RECV_HOST, PORT, "tcp")
        self.udpManager = NetworkManager(HOST, UDP_PORT, "udp", (RECV_HOST, RECV_UDP))
        try:
            self.tcpManager.connect()
            logging.info("Slave: connected")
        except Exception as e:
            logging.error(f"Slave: cannot connect -> {e}")
            raise
        self.secret_idx = None
        self.buff = ""
        self.ref_state = None
        self.steps = 10000

        # RSA key generation and exchange
        self.private_key, self.public_key = generate_rsa_keys()
        self.tcpManager.send({"type": "rsa_pubkey", "pubkey": self.public_key.decode()})
        # Wait for master key
        while True:
            msg = self.tcpManager.recv()
            if msg and msg.get("type") == "master_key":
                encrypted_master = bytes.fromhex(msg["encrypted_master"])
                self.master_key = decrypt_master_key(self.private_key, encrypted_master)
                self.aes_inner, self.aes_outer, self.hmac_key = derive_keys(
                    self.master_key
                )
                logging.info("Slave: received and decrypted master key")
                self.tcpManager.send({"ack": "decoded"})
                break

    def run_system(self):
        while True:
            msg = self.tcpManager.recv()
            if msg and msg.get("type") == "sync":
                self.sys.run_steps(self.steps)
                if (msg.get("state") == self.sys.state_history[-1]).all():
                    print("nice")
                else:
                    print("not nice")
                    print(msg.get("state"))
                    print(self.sys.state_history[-1])
                self.tcpManager.send({"ack": "ok"})

    def decrypt_message(self):
        while True:
            msg = self.udpManager.recv()
            if msg and msg.get("type") == "message":
                enc_hex = msg["enc"]
                logging.info(f"{self.sys.state_history[-1]}")  # type: ignore
                dec, _ = xor_decrypt(enc_hex, self.sys.state_history[-1])  # type: ignore
                logging.info(f"Slave: decrypted message = {dec}")

    def run(self):
        # Step 1: receive & decode packet
        while True:
            msg = self.tcpManager.recv()
            if not msg:
                continue
            if msg.get("type") == "packet":
                try:
                    # Outer AES/HMAC layer
                    iv = bytes.fromhex(msg["iv"])
                    ct = bytes.fromhex(msg["ct"])
                    tag = bytes.fromhex(msg["tag"])

                    packet = decrypt_packet(iv, ct, tag, self.aes_outer, self.hmac_key)

                    # Inner AES layer for parts
                    enc_parts = packet[0, -1]  # assuming all rows have same enc_parts
                    parts = decrypt_parts(enc_parts, self.aes_inner)

                    # Now you can use 'parts' to reconstruct secret_idx
                    self.secret_idx = int(np.sum(parts))
                except Exception as e:
                    logging.error(f"Slave: packet decrypt failed -> {e}")
                    continue

                logging.info(f"Slave: decoded index = {self.secret_idx}")
                self.ref_state = packet[self.secret_idx][:3] # type: ignore
                print(self.ref_state)
                self.tcpManager.send({"ack": "decoded"})
                break

        # Step 2: wait for restart
        while True:
            msg = self.tcpManager.recv()
            if msg and msg.get("type") == "restart":
                self.sys = LorenzSystem(
                    LorenzParameters(sigma=10.0, rho=28.0, beta=8 / 3),
                    initial_state=self.ref_state,
                )
                self.sys.run_steps(self.steps)
                logging.info("Slave: restart acknowledged")
                break
    
    def receive_audio(self, output_path="received_audio.mp3"):
        # Receive the file length as a line of text
        file_len_data = self.udpManager.receive_data()
        if file_len_data is None:
            print("No file length received.")
            return
        if isinstance(file_len_data, bytes):
            file_len_data = file_len_data.decode()
        file_len = int(file_len_data.strip()) # type: ignore
        print(f"Expecting {file_len} bytes.")
        chunk_size = 16384
        expected_num_chunks = (file_len + chunk_size - 1) // chunk_size
        print(f"Expecting {expected_num_chunks} chunks.")
        received = {}
        total_received = 0
        while total_received < file_len:
            data = self.udpManager.receive_data()
            if data is None:
                break
            # data is bytes, first 6 bytes are header (sequence number), rest is chunk
            header = data[:6]
            chunk = data[6:]
            chunk = xor_decrypt(chunk, self.sys.state_history[-1])[0]  # type: ignore
            seq = int(header.decode())  # type: ignore
            received[seq] = chunk
            total_received += len(chunk)
            print(f"Received chunk {seq}, size {len(chunk)}")
            print(f"Total received: {total_received}/{file_len} bytes")
            if len(received) == expected_num_chunks:
                break
        # Reassemble in order
        audio_bytes = b''.join(received[i] for i in sorted(received))
        with open(output_path, "wb") as f:
            f.write(audio_bytes)
        print(f"Audio file written to {output_path}")

    def receive_audio_realtime(self, output_path="received_audio.raw"):
        print("Receiving audio stream...")
        received = {}
        while True:
            data = self.udpManager.receive_data()
            if data is None:
                continue
            if data == b"EOF":
                break

            header = data[:6]
            chunk = data[6:]

            # Decrypt
            dec_chunk, mask = xor_decrypt(chunk, self.sys.state_history[-1]) # type: ignore
            seq = int(header.decode()) # type: ignore
            received[seq] = dec_chunk
            print(f"Received chunk {seq}, size {len(dec_chunk)}, mask {mask}")

        # Reassemble
        audio_bytes = b''.join(received[i] for i in sorted(received))
        with open(output_path, "wb") as f:
            f.write(audio_bytes)
        print(f"Audio stream written to {output_path}")

if __name__ == "__main__":
    try:
        slave = SlaveSystem()
        slave.run()
        slave_system_thread = threading.Thread(target=slave.run_system)
        # decrypt_thread = threading.Thread(target=slave.decrypt_message)
        # audio_thread = threading.Thread(target=slave.receive_audio_realtime)
        slave_system_thread.start()
        # audio_thread.start()
        # decrypt_thread.start()
        slave_system_thread.join()
        # decrypt_thread.join()
        # audio_thread.join()
    except Exception as e:
        logging.error(f"Slave: fatal error -> {e}")
