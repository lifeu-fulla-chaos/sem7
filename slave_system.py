# import socket, json
# import numpy as np
# from lorenz_system import LorenzSystem
# from Cryptodome.Cipher import AES
# from Cryptodome.Util.Padding import pad, unpad

# HOST, PORT = "127.0.0.1", 3000

# class SlaveSystem:
#     def __init__(self):
#         self.sys = LorenzSystem()
#         self.buf = ""
#         self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         try:
#             self.sock.connect((HOST, PORT))
#             print("Slave: connected")
#         except Exception as e:
#             print(f"Slave: cannot connect -> {e}")
#             raise
#         self.secret_idx = None
#         self.traj = None
#         self.ref_state = None

#     def send(self, obj):
#         try:
#             data = json.dumps(obj).encode() + b"\n"
#             self.sock.sendall(data)
#         except Exception as e:
#             print(f"Slave: send error -> {e}")

#     def recv(self):
#         try:
#             while "\n" not in self.buf:
#                 chunk = self.sock.recv(4096)
#                 if not chunk:
#                     return None
#                 self.buf += chunk.decode()
#             line, self.buf = self.buf.split("\n", 1)
#             return json.loads(line)
#         except json.JSONDecodeError:
#             print("Slave: got invalid JSON line, skipping")
#             return None
#         except Exception as e:
#             print(f"Slave: recv error -> {e}")
#             return None


#     def run(self):
#         # Step 1: receive packet
#         while True:
#             msg = self.recv()
#             if not msg:
#                 continue
#             if msg.get("type") == "packet":
#                 try:
#                     iv = bytes.fromhex(msg["iv"])
#                     ct = bytes.fromhex(msg["ct"])
#                     key = bytes.fromhex(msg["key"])
#                 except Exception as e:
#                     print(f"Slave: bad packet fields -> {e}")
#                     continue

#                 try:
#                     packet = LorenzSystem.aes_decrypt_packet(iv, ct, key)
#                 except Exception as e:
#                     print(f"Slave: AES decrypt failed -> {e}")
#                     continue

#                 print("Slave: packet after decryption ->", packet[:5], "...")
#                 self.secret_idx = int(np.sum(packet[:, 3]))
#                 print("Slave: decoded index =", self.secret_idx)

#                 self.traj = self.sys.simulate_master([1, 1, 1], 10000)
#                 self.ref_state = self.traj[self.secret_idx]
#                 self.send({"ack": "decoded"})
#                 break

#         # Step 2: wait for restart
#         while True:
#             msg = self.recv()
#             if msg and msg.get("type") == "restart":
#                 print("Slave: restarted")
#                 break

#         # Step 3: sync + acks
#         while True:
#             msg = self.recv()
#             if not msg:
#                 continue
#             if msg.get("type") == "sync":
#                 if msg["step"] % 50 == 0:
#                     self.send({"ack": "ok"})
#             elif msg.get("type") == "message":
#                 enc_hex = msg["enc"]
#                 dec, mask = self.sys.xor_decrypt(enc_hex, self.ref_state)
#                 print("Slave: mask =", mask[:len(dec)])
#                 print("Slave: decrypted msg =", dec)
#                 break


# if __name__ == "__main__":
#     try:

#         SlaveSystem().run()
#     except Exception as e:
#         print(f"Slave: fatal error -> {e}")

# slave_system.py
# import socket, json
# import numpy as np
# from lorenz_system import LorenzSystem

# HOST, PORT = "127.0.0.1", 3000

# class SlaveSystem:
#     def __init__(self):
#         self.sys = LorenzSystem()
#         self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         try:
#             self.sock.connect((HOST, PORT))
#             print("Slave: connected")
#         except Exception as e:
#             print(f"Slave: cannot connect -> {e}")
#             raise
#         self.buf = ""
#         self.secret_idx = None
#         self.traj = None
#         self.ref_state = None

#     def send(self, obj):
#         try:
#             data = json.dumps(obj).encode() + b"\n"
#             self.sock.sendall(data)
#         except Exception as e:
#             print(f"Slave: send error -> {e}")

#     def recv(self):
#         try:
#             while "\n" not in self.buf:
#                 chunk = self.sock.recv(4096)
#                 if not chunk:
#                     return None
#                 self.buf += chunk.decode()
#             line, self.buf = self.buf.split("\n", 1)
#             return json.loads(line)
#         except json.JSONDecodeError:
#             print("Slave: got invalid JSON line, skipping")
#             return None
#         except Exception as e:
#             print(f"Slave: recv error -> {e}")
#             return None

#     def run(self):
#         # Step 1: receive & decode packet
#         while True:
#             msg = self.recv()
#             if not msg:
#                 continue
#             if msg.get("type") == "packet":
#                 try:
#                     iv = bytes.fromhex(msg["iv"])
#                     ct = bytes.fromhex(msg["ct"])
#                     key = bytes.fromhex(msg["key"])
#                     packet = LorenzSystem.aes_decrypt_packet(iv, ct, key)
#                 except Exception as e:
#                     print(f"Slave: AES decrypt failed -> {e}")
#                     continue

#                 print("Slave: packet after decryption ->", packet[:5], "...")
#                 self.secret_idx = int(np.sum(packet[:, 3]))
#                 print("Slave: decoded index =", self.secret_idx)
#                 self.traj = self.sys.simulate_master([1, 1, 1], 10000)
#                 self.ref_state = self.traj[self.secret_idx]
#                 self.send({"ack": "decoded"})
#                 break

#         # Step 2: wait for restart
#         while True:
#             msg = self.recv()
#             if msg and msg.get("type") == "restart":
#                 print("Slave: restart acknowledged")
#                 break

#         # Step 3: sync with ack every 50 steps
#         y = np.array([5.0, 5.0, 5.0], dtype=float)
#         while True:
#             msg = self.recv()
#             if not msg:
#                 continue
#             if msg.get("type") == "sync":
#                 step = msg["step"]
#                 x = np.array(msg["state"], dtype=float)
#                 y, _ = self.sys.simulate_slave_step(y, x)
#                 if step % 50 == 0:
#                     self.send({"ack": "ok"})
#             elif msg.get("type") == "message":
#                 enc_hex = msg["enc"]
#                 dec, mask = self.sys.xor_decrypt(enc_hex, self.ref_state)
#                 print("Slave: mask =", mask[:len(dec)])
#                 print("Slave: decrypted msg =", dec)
#                 break

# if __name__ == "__main__":
#     try:
#         SlaveSystem().run()
#     except Exception as e:
#         print(f"Slave: fatal error -> {e}")


import socket, json
import numpy as np  # type: ignore
from lorenz_system import LorenzSystem, LorenzParameters
from encryption import *
from rsa_sharing import generate_rsa_keys, decrypt_master_key, derive_keys

HOST, PORT = "127.0.0.1", 3000


class SlaveSystem:
    def __init__(self):
        self.sys = LorenzSystem(LorenzParameters(sigma=10.0, rho=28.0, beta=8 / 3))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((HOST, PORT))
            print("Slave: connected")
        except Exception as e:
            print(f"Slave: cannot connect -> {e}")
            raise
        self.buf = ""
        self.secret_idx = None
        self.traj = None
        self.ref_state = None

        # RSA key generation and exchange
        self.private_key, self.public_key = generate_rsa_keys()
        self.send({"type": "rsa_pubkey", "pubkey": self.public_key.decode()})
        # Wait for master key
        while True:
            msg = self.recv()
            if msg and msg.get("type") == "master_key":
                encrypted_master = bytes.fromhex(msg["encrypted_master"])
                self.master_key = decrypt_master_key(self.private_key, encrypted_master)
                self.aes_inner, self.aes_outer, self.hmac_key = derive_keys(
                    self.master_key
                )
                print("Slave: received and decrypted master key")
                break

    # ...existing code...
    def send(self, obj):
        try:
            data = json.dumps(obj).encode() + b"\n"
            self.sock.sendall(data)
        except Exception as e:
            print(f"Slave: send error -> {e}")

    def recv(self):
        try:
            while "\n" not in self.buf:
                chunk = self.sock.recv(4096)
                if not chunk:
                    return None
                self.buf += chunk.decode()
            line, self.buf = self.buf.split("\n", 1)
            return json.loads(line)
        except json.JSONDecodeError:
            print("Slave: got invalid JSON line, skipping")
            return None
        except Exception as e:
            print(f"Slave: recv error -> {e}")
            return None

    def run(self):
        # Step 1: receive & decode packet
        while True:
            msg = self.recv()
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
                    print(f"Slave: packet decrypt failed -> {e}")
                    continue

                print("Slave: packet after decryption ->", packet[:5], "...")
                print("Slave: decoded index =", self.secret_idx)
                self.traj = self.sys.run_steps(10000)
                self.ref_state = self.traj[self.secret_idx]
                self.send({"ack": "decoded"})
                break

        # Step 2: wait for restart
        while True:
            msg = self.recv()
            if msg and msg.get("type") == "restart":
                self.sys = LorenzSystem(
                    LorenzParameters(sigma=10.0, rho=28.0, beta=8 / 3), initial_state=self.ref_state
                )
                print("Slave: restart acknowledged")
                break

        while True:
            msg = self.recv()
            if msg and msg.get("type") == "message":
                enc_hex = msg["enc"]
                dec, _ = xor_decrypt(enc_hex, self.ref_state)
                print("Slave: decrypted message =", dec)
                break


if __name__ == "__main__":
    try:
        SlaveSystem().run()
    except Exception as e:
        print(f"Slave: fatal error -> {e}")
