# import socket, json
# import numpy as np
# from lorenz_system import LorenzSystem
# from Cryptodome.Random import get_random_bytes

# HOST, PORT = "127.0.0.1", 3000

# class MasterSystem:
#     def __init__(self):
#         self.sys = LorenzSystem()
#         self.sock = None
#         self.conn = None
#         self.key = get_random_bytes(16)  # AES-128 key

#     def start(self):
#         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         s.bind((HOST, PORT))
#         s.listen(1)
#         print("Master: waiting...")
#         self.conn, _ = s.accept()
#         print("Master: slave connected")

#     def send(self, obj):
#         try:
#             data = json.dumps(obj).encode() + b"\n"
#             self.conn.sendall(data)
#         except Exception as e:
#             print(f"Master: send failed -> {e}")
#             self.conn = None


#     def recv(self):
#         return json.loads(self.conn.recv(8192).decode())

#     def run(self):
#         # Step 1: compute 10k trajectory
#         traj = self.sys.simulate_master([1, 1, 1], 10000)

#         # Step 2: pick packet
#         secret_idx = int(np.random.randint(0, 10000))
#         packet = self.sys.make_packet(traj, secret_idx)
#         print("Master: packet before encryption ->", packet[:5], "...")

#         # Step 3: AES encrypt
#         iv, ct = self.sys.aes_encrypt_packet(packet, self.key)
#         print("Master: packet after encryption ->", ct[:32], "...")

#         self.send({"type": "packet", "iv": iv.hex(), "ct": ct.hex(), "key": self.key.hex()})

#         # Step 4: wait for ack
#         msg = self.recv()
#         if msg.get("ack") == "decoded":
#             print("Master: slave decoded index, restarting...")

#         # Restart both
#         self.send({"type": "restart"})

#         # Step 5: comms with ack every 50
#         for i in range(1, 201):  # shorter run just for demo
#             state = traj[i].tolist()
#             self.send({"type": "sync", "step": i, "state": state})
#             if i % 50 == 0:
#                 ack = self.recv()
#                 print(f"Master: step {i} ack from slave")

#         # Step 6: send encrypted message
#         msg = "Hello World!"
#         enc_hex, mask = self.sys.xor_encrypt(msg, traj[secret_idx])
#         print("Master: original msg =", msg)
#         print("Master: mask =", mask[:len(msg)])
#         print("Master: encrypted msg =", enc_hex)
#         self.send({"type": "message", "enc": enc_hex})

# if __name__ == "__main__":
#     master = MasterSystem()
#     try:
#         master.start()
#         master.run()
#     except Exception as e:
#         print(f"Master: fatal error -> {e}")
#     finally:
#         if master.conn:
#             try: master.conn.close()
#             except: pass


# master_system.py
# import socket, json
# import numpy as np
# from lorenz_system import LorenzSystem
# from Cryptodome.Random import get_random_bytes

# HOST, PORT = "127.0.0.1", 3000

# class MasterSystem:
#     def __init__(self):
#         self.sys = LorenzSystem()
#         self.sock = None
#         self.conn = None
#         self.key = get_random_bytes(16)  # AES-128 key

#     def start(self):
#         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#         s.bind((HOST, PORT))
#         s.listen(1)
#         print("Master: waiting...")
#         self.conn, _ = s.accept()
#         print("Master: slave connected")

#     def send(self, obj):
#         try:
#             data = json.dumps(obj).encode() + b"\n"
#             self.conn.sendall(data)
#         except Exception as e:
#             print(f"Master: send error -> {e}")

#     def recv(self):
#         try:
#             data = self.conn.recv(4096)
#             if not data:
#                 return None
#             return json.loads(data.decode().strip())
#         except Exception as e:
#             print(f"Master: recv error -> {e}")
#             return None

#     def run(self):
#         # Step 1: compute 10k trajectory
#         traj = self.sys.simulate_master([1, 1, 1], 10000)

#         # Step 2: pick packet
#         secret_idx = int(np.random.randint(0, 10000))
#         packet = self.sys.make_packet(traj, secret_idx)
#         print("Master: packet before encryption ->", packet[:5], "...")
#         iv, ct = self.sys.aes_encrypt_packet(packet, self.key)
#         print("Master: packet after encryption ->", ct[:32], "...")

#         self.send({"type": "packet", "iv": iv.hex(), "ct": ct.hex(), "key": self.key.hex()})

#         # Step 3: wait for ack
#         while True:
#             msg = self.recv()
#             if msg and msg.get("ack") == "decoded":
#                 print("Master: slave decoded index, restarting...")
#                 break

#         # Step 4: restart sync
#         self.send({"type": "restart"})
#         print("Master: restarting trajectory sync...")
#         x = np.array([1.0, 1.0, 1.0], dtype=float)
#         for step in range(1, 501):  # demo: 500 steps, can extend to 10k
#             x = x + self.sys.f_master(x) * self.sys.dt
#             self.send({"type": "sync", "step": step, "state": x.tolist()})
#             if step % 50 == 0:
#                 ack = self.recv()
#                 if ack and ack.get("ack") == "ok":
#                     print(f"Master: got ack at step {step}")
#                 else:
#                     print(f"Master: no ack at step {step}, stopping sync")
#                     break

#         # Step 5: send encrypted message
#         msg = "Hello World!"
#         enc_hex, mask = self.sys.xor_encrypt(msg, traj[secret_idx])
#         print("Master: original msg =", msg)
#         print("Master: mask =", mask[:len(msg)])
#         print("Master: encrypted msg =", enc_hex)
#         self.send({"type": "message", "enc": enc_hex})

# if __name__ == "__main__":
#     master = MasterSystem()
#     try:
#         master.start()
#         master.run()
#     except Exception as e:
#         print(f"Master: fatal error -> {e}")
#     finally:
#         if master.conn:
#             try: master.conn.close()
#             except: pass

import os
import socket, json
import numpy as np  # type: ignore
from lorenz_system import LorenzSystem, LorenzParameters
from encryption import *
from network import NetworkManager
from rsa_sharing import encrypt_master_key, derive_keys

HOST, PORT = "127.0.0.1", 3000
PORT_UDP, RECV_UDP = 4000, 4001


class MasterSystem:
    def __init__(self):
        self.params = LorenzParameters(sigma=10.0, rho=28.0, beta=8 / 3)
        self.sys = LorenzSystem(self.params)
        self.steps = 10000
        self.tcpManager = NetworkManager(HOST, PORT, "tcp")
        self.udpManager = NetworkManager(HOST, PORT_UDP, "udp", (HOST, RECV_UDP))
        self.master_key = None
        self.aes_inner = None
        self.aes_outer = None
        self.hmac_key = None

    def start(self):
        self.tcpManager.start_server()

    def send(self, obj, netManager):
        try:
            data = json.dumps(obj).encode() + b"\n"
            netManager.send_data(data)
        except Exception as e:
            print(f"Master: send error -> {e}")

    def recv(self, netManager):
        try:
            data = netManager.receive_data()
            if not data:
                return None
            return json.loads(data)
        except Exception as e:
            print(f"Master: recv error -> {e}")
            return None

    def run(self):
        # Step 0: RSA key exchange
        while True:
            msg = self.recv(self.tcpManager)
            if msg and msg.get("type") == "rsa_pubkey":
                pubkey = msg["pubkey"].encode()
                self.master_key = os.urandom(32)
                encrypted_master = encrypt_master_key(pubkey, self.master_key)
                self.send(
                    {"type": "master_key", "encrypted_master": encrypted_master.hex()},
                    self.tcpManager,
                )
                self.aes_inner, self.aes_outer, self.hmac_key = derive_keys(
                    self.master_key
                )
                print("Master: sent encrypted master key")
                break
        while True:
            msg = self.recv(self.tcpManager)
            if msg and msg.get("ack") == "decoded":
                print("received ack")
                break

        # Step 1: compute 10k trajectory
        traj = self.sys.run_steps(self.steps)
        packet, secret_idx = make_packet(traj, aes_key=self.aes_inner)
        iv, ct, tag = encrypt_packet(
            packet, aes_key=self.aes_outer, hmac_key=self.hmac_key
        )

        self.send(
            {"type": "packet", "iv": iv.hex(), "ct": ct.hex(), "tag": tag.hex()},
            self.tcpManager,
        )

        # Step 3: wait for ack
        while True:
            msg = self.recv(self.tcpManager)
            if msg and msg.get("ack") == "decoded":
                print("Master: slave decoded index, restarting...")
                break

        # Step 4: restart sync
        self.send({"type": "restart"}, self.tcpManager)
        print("Master: restarting trajectory sync...")
        self.sys = LorenzSystem(self.params, initial_state=traj[secret_idx])
        self.sys.run_steps(self.steps)
        # Step 5: send encrypted message
        msg = "Hello World!"
        print(self.sys.state_history[-1])  # type: ignore
        enc_hex, mask = xor_encrypt(msg, self.sys.state_history[-1])  # type: ignore
        print("Master: original msg =", msg)
        print("Master: mask =", mask[: len(msg)])
        print("Master: encrypted msg =", enc_hex)
        self.send({"type": "message", "enc": enc_hex}, self.udpManager)


if __name__ == "__main__":
    master = MasterSystem()
    try:
        master.start()
        master.run()
    except Exception as e:
        print(f"Master: fatal error -> {e}")
    finally:
        master.tcpManager.close_connection()
        master.udpManager.close_connection()
