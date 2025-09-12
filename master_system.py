import os
import logging
import threading
from lorenz_system import LorenzSystem, LorenzParameters
from encryption import *
from network import NetworkManager
from rsa_sharing import encrypt_master_key, derive_keys
import random
import time
import sounddevice as sd  # type: ignore
import numpy as np  # type: ignore

HOST, PORT = "0.0.0.0", 3000
RECV_HOST = "192.168.0.117"
PORT_UDP, RECV_UDP = 4000, 4001
logging.basicConfig(level=logging.INFO)


class MasterSystem:
    def __init__(self):
        self.params = LorenzParameters(sigma=10.0, rho=28.0, beta=8 / 3)
        self.sys = LorenzSystem(self.params)
        self.steps = 10000
        self.tcpManager = NetworkManager(HOST, PORT, "tcp")
        self.udpManager = NetworkManager(HOST, PORT_UDP, "udp", (RECV_HOST, RECV_UDP))
        self.master_key = None
        self.aes_inner = None
        self.aes_outer = None
        self.hmac_key = None

    def start(self):
        self.tcpManager.start_server()

    def run_system(self):
        while True:
            self.sys.run_steps(self.steps)
            self.tcpManager.send({"type": "sync"})
            msg = self.tcpManager.recv()
            if msg and msg.get("ack") == "ok":
                logging.info("Master: slave in sync")
                time.sleep(random.uniform(0.5, 3.0))  # simulate variable delay

    def user_input(self):
        while True:
            msg = input("Enter message to send: ")
            logging.info(f"{self.sys.state_history[-1]}")  # type: ignore
            enc_hex, mask = xor_encrypt(msg, self.sys.state_history[-1])  # type: ignore
            logging.info(f"Master: original msg = {msg}")
            logging.info(f"Master: mask = {mask[: len(msg)]}")
            logging.info(f"Master: encrypted msg = {enc_hex}")
            self.udpManager.send({"type": "message", "enc": enc_hex})

    def send_audio(self, audio_bytes: bytes):
        chunk_size = 16378
        chunks = [
            audio_bytes[i : i + chunk_size]
            for i in range(0, len(audio_bytes), chunk_size)
        ]

        chunks = [xor_encrypt(chunk, self.sys.state_history[-1])[0] for chunk in chunks]  # type: ignore
        file_len = len(audio_bytes)
        self.udpManager.send_data(str(file_len).encode() + b"\n")
        for i, chunk in enumerate(chunks):
            header = f"{i:06d}".encode()
            print(f"Master: sending chunk {i+1}/{len(chunks)}")
            self.udpManager.send_data(header + bytes.fromhex(chunk))
            time.sleep(0.1)  # simulate network delay
        logging.info("Master: finished sending audio")

    def send_audio_from_mic_realtime(
        self, duration=10, samplerate=44100, channels=1, chunk_size=16384
    ):
        print("Streaming mic audio for", duration, "seconds...")
        start_time = time.time()
        stream = sd.InputStream(
            samplerate=samplerate,
            channels=channels,
            dtype="int16",
            blocksize=chunk_size,
        )
        stream.start()

        chunk_index = 0
        while time.time() - start_time < duration:
            audio, _ = stream.read(chunk_size)
            audio_bytes = audio.tobytes()

            # Encrypt
            enc_chunk = xor_encrypt(audio_bytes, self.sys.state_history[-1])[0]  # type: ignore
            header = f"{chunk_index:06d}".encode()

            # Send
            print(f"Master: sending chunk {chunk_index}")
            self.udpManager.send_data(header + bytes.fromhex(enc_chunk))
            chunk_index += 1

        stream.stop()
        stream.close()
        self.udpManager.send_data(b"EOF")
        print("Master: finished streaming audio")

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
        traj = self.sys.run_steps(self.steps, True)
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
        self.sys = LorenzSystem(self.params, initial_state=traj[secret_idx]) # type: ignore
        self.sys.run_steps(self.steps)


if __name__ == "__main__":
    master = MasterSystem()
    try:
        master.start()
        master.run()
        system_thread = threading.Thread(target=master.run_system, daemon=True)
        # input_thread = threading.Thread(target=master.user_input, daemon=True)
        audio_thread = threading.Thread(
            target=master.send_audio_from_mic_realtime, daemon=True
        )
        system_thread.start()
        audio_thread.start()
        # input_thread.start()
        audio_thread.join()
        system_thread.join()
        # input_thread.join()
    except Exception as e:
        logging.error(f"Master: fatal error -> {e}")
    finally:
        master.tcpManager.close_connection()
        master.udpManager.close_connection()
