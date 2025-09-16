import logging
import threading
import numpy as np  # type: ignore
from lorenz_system import LorenzSystem, LorenzParameters
from encryption import *
from rsa_sharing import generate_rsa_keys, decrypt_master_key, derive_keys
from network import NetworkManager
from audio import AudioHandler
import gc

HOST, PORT = "0.0.0.0", 3000
RECV_HOST = "192.168.0.102"
logging.basicConfig(level=logging.INFO)


class SlaveSystem(AudioHandler):
    def __init__(self):
        self.params = LorenzParameters(sigma=10.0, rho=28.0, beta=8 / 3)
        self.sys = None
        self.tcpManager = NetworkManager(RECV_HOST, PORT, "tcp")
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
        super().__init__(self.sys, RECV_HOST)
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
                self.sys.run_steps1(self.steps)
                self.tcpManager.send({"ack": "ok"})

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
                self.ref_state = packet[self.secret_idx][:3]  # type: ignore
                self.tcpManager.send({"ack": "decoded"})
                break

        # Step 2: wait for restart
        while True:
            msg = self.tcpManager.recv()
            if msg and msg.get("type") == "restart":
                del self.sys
                gc.collect()
                self.sys = LorenzSystem(
                    self.params,
                    initial_state=self.ref_state,
                )
                self.sys.state_history = None
                print("initial state", self.ref_state)
                self.sys.run_steps1(self.steps)
                logging.info("Slave: restart acknowledged")
                print("final state", self.sys.state_history[-1])
                break


if __name__ == "__main__":
    try:
        slave = SlaveSystem()
        slave.run()
        slave_system_thread = threading.Thread(target=slave.run_system, daemon=True)
        audio_thread1 = threading.Thread(
            target=slave.send_audio_from_mic_realtime, daemon=True
        )
        audio_thread = threading.Thread(
            target=slave.receive_audio_realtime, daemon=True
        )
        slave_system_thread.start()
        audio_thread.start()
        audio_thread1.start()
        slave_system_thread.join()
        audio_thread.join()
        audio_thread1.join()
    except Exception as e:
        logging.error(f"Slave: fatal error -> {e}")
