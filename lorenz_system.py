# import numpy as np
# import json, hashlib
# from Cryptodome.Cipher import AES
# from Cryptodome.Util.Padding import pad, unpad

# class LorenzSystem:
#     def __init__(self, sigma=10.0, rho=28.0, beta=8/3, dt=0.01):
#         self.sigma = sigma
#         self.rho = rho
#         self.beta = beta
#         self.dt = dt

#     def f_master(self, x):
#         dx = np.zeros(3)
#         dx[0] = self.sigma * (x[1] - x[0])
#         dx[1] = x[0] * (self.rho - x[2]) - x[1]
#         dx[2] = x[0] * x[1] - self.beta * x[2]
#         return dx

#     def simulate_master(self, x0, steps):
#         X = np.zeros((steps, 3))
#         x = np.array(x0, dtype=float)
#         for i in range(steps):
#             x = x + self.f_master(x) * self.dt
#             X[i] = x
#         return X

#     @staticmethod
#     def make_packet(traj, secret_idx, bundle_size=500):
#         rng = np.random.default_rng()
#         states = traj[rng.choice(traj.shape[0], size=bundle_size, replace=False)]
#         # break secret_idx into 500 integers
#         cuts = np.sort(rng.integers(0, secret_idx+1, size=bundle_size-1))
#         parts = np.diff(np.concatenate(([0], cuts, [secret_idx])))
#         packet = np.column_stack([states, parts])
#         return packet

#     # === AES encryption ===
#     @staticmethod
#     def aes_encrypt_packet(packet, key):
#         cipher = AES.new(key, AES.MODE_CBC)
#         blob = json.dumps(packet.tolist(), separators=(",", ":")).encode()
#         ct = cipher.encrypt(pad(blob, AES.block_size))
#         return cipher.iv, ct

#     @staticmethod
#     def aes_decrypt_packet(iv, ct, key):
#         cipher = AES.new(key, AES.MODE_CBC, iv=iv)
#         pt = unpad(cipher.decrypt(ct), AES.block_size)
#         return np.array(json.loads(pt.decode()))

#     # === XOR message encryption with Lorenz state ===
#     @staticmethod
#     def derive_mask(state, length):
#         s = json.dumps(state.tolist()).encode()
#         h = hashlib.sha256(s).digest()
#         mask = (h * ((length // len(h)) + 1))[:length]
#         return mask

#     @staticmethod
#     def xor_encrypt(msg, state):
#         msg_b = msg.encode()
#         mask = LorenzSystem.derive_mask(np.array(state), len(msg_b))
#         enc = bytes([b ^ m for b, m in zip(msg_b, mask)])
#         return enc.hex(), mask

#     @staticmethod
#     def xor_decrypt(enc_hex, state):
#         enc_b = bytes.fromhex(enc_hex)
#         mask = LorenzSystem.derive_mask(np.array(state), len(enc_b))
#         dec = bytes([b ^ m for b, m in zip(enc_b, mask)])
#         return dec.decode(), mask

# lorenz_system.py
# import numpy as np
# import json, hashlib
# from Cryptodome.Cipher import AES
# from Cryptodome.Util.Padding import pad, unpad


# class LorenzSystem:
#     def __init__(self, sigma=10.0, rho=28.0, beta=8/3, dt=0.01):
#         self.sigma = float(sigma)
#         self.rho = float(rho)
#         self.beta = float(beta)
#         self.dt = float(dt)

#     # -------- Master dynamics --------
#     def f_master(self, x: np.ndarray) -> np.ndarray:
#         x = np.asarray(x, dtype=float)
#         dx = np.zeros(3, dtype=float)
#         dx[0] = self.sigma * (x[1] - x[0])
#         dx[1] = x[0] * (self.rho - x[2]) - x[1]
#         dx[2] = x[0] * x[1] - self.beta * x[2]
#         return dx

#     def simulate_master(self, x0, steps: int) -> np.ndarray:
#         X = np.zeros((steps, 3), dtype=float)
#         x = np.array(x0, dtype=float)
#         for i in range(steps):
#             x = x + self.f_master(x) * self.dt
#             X[i] = x
#         return X

#     # -------- Slave dyn + backstepping --------
#     def backstepping_control(self, x_master: np.ndarray, y_slave: np.ndarray, k: float = 5.0):
#         """
#         x_master: master state (reference)
#         y_slave:  current slave state
#         returns: (u control vector, error vector e = y - x)
#         """
#         x = np.asarray(x_master, dtype=float)
#         y = np.asarray(y_slave, dtype=float)
#         e = y - x  # e1,e2,e3

#         # simple backstepping law (same as we used earlier)
#         u1 = -self.sigma * ((y[1] - y[0]) - (x[1] - x[0])) + e[1]
#         u2 = -self.rho * (y[0] - x[0]) + (y[1] - x[1]) + (y[0] * y[2]) - (x[0] * x[2]) + e[2]
#         u3 = (-y[0] * y[1]) + (x[0] * x[1]) + self.beta * (y[2] - x[2]) \
#              - ((3 + 2 * k) * e[0]) - ((5 + 2 * k) * e[1]) - ((3 + k) * e[2])

#         return np.array([u1, u2, u3], dtype=float), e

#     def f_slave(self, y: np.ndarray, u: np.ndarray) -> np.ndarray:
#         y = np.asarray(y, dtype=float)
#         u = np.asarray(u, dtype=float)
#         dy = np.zeros(3, dtype=float)
#         dy[0] = self.sigma * (y[1] - y[0]) + u[0]
#         dy[1] = y[0] * (self.rho - y[2]) - y[1] + u[1]
#         dy[2] = y[0] * y[1] - self.beta * y[2] + u[2]
#         return dy

#     def simulate_slave_step(self, y: np.ndarray, x_master: np.ndarray):
#         """
#         One controlled Euler step for slave using backstepping towards x_master.
#         Returns: (y_next, error_vector)
#         """
#         u, e = self.backstepping_control(x_master, y)
#         y_next = y + self.f_slave(y, u) * self.dt
#         return y_next.astype(float), e.astype(float)

#     # -------- Bundle creation --------
#     @staticmethod
#     def make_packet(traj: np.ndarray, secret_idx: int, bundle_size: int = 500) -> np.ndarray:
#         rng = np.random.default_rng()
#         states = traj[rng.choice(traj.shape[0], size=bundle_size, replace=False)]
#         # break secret_idx into 500 nonnegative integers that sum to secret_idx
#         cuts = np.sort(rng.integers(0, secret_idx + 1, size=bundle_size - 1)) if secret_idx > 0 else np.zeros(bundle_size - 1, dtype=int)
#         parts = np.diff(np.concatenate(([0], cuts, [secret_idx]))).astype(float)
#         packet = np.column_stack([states, parts])
#         return packet

#     # -------- AES for packet --------
#     @staticmethod
#     def aes_encrypt_packet(packet: np.ndarray, key: bytes):
#         cipher = AES.new(key, AES.MODE_CBC)
#         blob = json.dumps(packet.tolist(), separators=(",", ":")).encode()
#         ct = cipher.encrypt(pad(blob, AES.block_size))
#         return cipher.iv, ct

#     @staticmethod
#     def aes_decrypt_packet(iv: bytes, ct: bytes, key: bytes) -> np.ndarray:
#         cipher = AES.new(key, AES.MODE_CBC, iv=iv)
#         pt = unpad(cipher.decrypt(ct), AES.block_size)
#         return np.array(json.loads(pt.decode()), dtype=float)

#     # -------- XOR message using Lorenz state --------
#     @staticmethod
#     def derive_mask(state: np.ndarray, length: int) -> bytes:
#         s = json.dumps(np.asarray(state, dtype=float).tolist(), separators=(",", ":")).encode()
#         h = hashlib.sha256(s).digest()
#         return (h * ((length // len(h)) + 1))[:length]

#     @staticmethod
#     def xor_encrypt(msg: str, state: np.ndarray):
#         msg_b = msg.encode()
#         mask = LorenzSystem.derive_mask(np.array(state, dtype=float), len(msg_b))
#         enc = bytes([b ^ m for b, m in zip(msg_b, mask)])
#         return enc.hex(), mask

#     @staticmethod
#     def xor_decrypt(enc_hex: str, state: np.ndarray):
#         enc_b = bytes.fromhex(enc_hex)
#         mask = LorenzSystem.derive_mask(np.array(state, dtype=float), len(enc_b))
#         dec = bytes([b ^ m for b, m in zip(enc_b, mask)])
#         return dec.decode(errors="strict"), mask


# lorenz_system.py
import numpy as np # type: ignore
from scipy.integrate import solve_ivp # type: ignore


class LorenzParameters:
    def __init__(self, sigma, rho, beta):
        self.sigma = sigma
        self.rho = rho
        self.beta = beta


class LorenzSystem:
    def __init__(self, params: LorenzParameters, dt=0.01, initial_state=[1.0, 1.0, 1.0]):
        self.params = params
        self.dt = float(dt)
        self.initial_state = np.array(initial_state, dtype=float)
        self.state_history = None
        self.t = 0.0

    def lorenz_equations(self, t, state):
        x, y, z = state
        dx = self.params.sigma * (y - x)
        dy = x * (self.params.rho - z) - y
        dz = x * y - self.params.beta * z
        return [dx, dy, dz]

    def run_steps(self, steps: int):
        t_span = (self.t, self.t + self.dt * steps)
        t_eval = np.linspace(*t_span, steps)

        solution = solve_ivp(
            fun=self.lorenz_equations,
            t_span=t_span,
            y0=self.initial_state,
            t_eval=t_eval,
            method="RK45",
            rtol=1e-9,
            atol=1e-9,
        )
        self.state_history = solution.y.T
        self.initial_state = self.state_history[-1]
        self.t += (steps * self.dt)
        return self.state_history

    # -------- Slave dyn + backstepping --------
    def backstepping_control(self, x_master: np.ndarray, y_slave: np.ndarray, k: float = 5.0):
        x = np.asarray(x_master, dtype=float)
        y = np.asarray(y_slave, dtype=float)
        e = y - x

        u1 = -self.params.sigma * ((y[1] - y[0]) - (x[1] - x[0])) + e[1]
        u2 = -self.params.rho * (y[0] - x[0]) + (y[1] - x[1]) + (y[0] * y[2]) - (x[0] * x[2]) + e[2]
        u3 = (-y[0] * y[1]) + (x[0] * x[1]) + self.params.beta * (y[2] - x[2]) \
             - ((3 + 2 * k) * e[0]) - ((5 + 2 * k) * e[1]) - ((3 + k) * e[2])

        return np.array([u1, u2, u3], dtype=float), e


    