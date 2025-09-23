import os
import logging
import threading
from lorenz_system import LorenzSystem, LorenzParameters
from encryption import *
from network import NetworkManager
from rsa_sharing import encrypt_master_key, derive_keys
import random
import time
from audio import AudioHandler

HOST, PORT = "0.0.0.0", 3000
RECV_HOST = "192.168.0.104"
logging.basicConfig(level=logging.INFO)


class MasterSystem(AudioHandler):
    def __init__(self):
        self.params = LorenzParameters(sigma=10.0, rho=28.0, beta=8 / 3)
        self.sys = LorenzSystem(self.params)
        self.steps = 10000
        self.tcpManager = NetworkManager(HOST, PORT, "tcp")

        self.master_key = None
        self.aes_inner = None
        self.aes_outer = None
        self.hmac_key = None
        super().__init__(self.sys, RECV_HOST)

    def start(self):
        self.tcpManager.start_server()

    def run_system(self):
        while True:
            self.sys.run_steps1(self.steps)
            self.tcpManager.send({"type": "sync"})  # type: ignore }
            msg = self.tcpManager.recv()
            if msg and msg.get("ack") == "ok":
                logging.info("Master: slave in sync")
                time.sleep(random.uniform(0.5, 3.0))  # simulate variable delay

    def run(self):
        # Step 0: RSA key exchange
        while True:
            msg = self.tcpManager.recv()
            if msg and msg.get("type") == "rsa_pubkey":
                pubkey = msg["pubkey"].encode()
                self.master_key = os.urandom(32)
                encrypted_master = encrypt_master_key(pubkey, self.master_key)
                self.tcpManager.send(
                    {"type": "master_key", "encrypted_master": encrypted_master.hex()}
                )
                self.aes_inner, self.aes_outer, self.hmac_key = derive_keys(
                    self.master_key
                )
                logging.info("Master: sent encrypted master key")
                break
        while True:
            msg = self.tcpManager.recv()
            if msg and msg.get("ack") == "decoded":
                logging.info("received ack")
                break

        # Step 1: compute 10k trajectory
        traj = self.sys.run_steps1(self.steps, True)
        packet, secret_idx = make_packet(traj, aes_key=self.aes_inner)  # type: ignore
        iv, ct, tag = encrypt_packet(
            packet, aes_key=self.aes_outer, hmac_key=self.hmac_key
        )

        self.tcpManager.send(
            {"type": "packet", "iv": iv.hex(), "ct": ct.hex(), "tag": tag.hex()}
        )

        # Step 3: wait for ack
        while True:
            msg = self.tcpManager.recv()
            if msg and msg.get("ack") == "decoded":
                logging.info("Master: slave decoded index, restarting...")
                break

        # Step 4: restart sync
        self.tcpManager.send({"type": "restart"})
        logging.info("Master: restarting trajectory sync...")
        self.sys = LorenzSystem(self.params, initial_state=packet[secret_idx][:3])  # type: ignore
        self.sys.run_steps1(self.steps)


if __name__ == "__main__":
    master = MasterSystem()
    try:
        master.start()
        master.run()
        system_thread = threading.Thread(target=master.run_system, daemon=True)
        audio_thread = threading.Thread(
            target=master.send_audio_from_mic_realtime, daemon=True
        )
        audio_thread1 = threading.Thread(
            target=master.receive_audio_realtime, daemon=True
        )
        system_thread.start()
        audio_thread.start()
        audio_thread1.start()  
        audio_thread.join()
        system_thread.join()
        audio_thread1.join()
    except Exception as e:
        logging.error(f"Master: fatal error -> {e}")
    finally:
        master.tcpManager.close_connection()
