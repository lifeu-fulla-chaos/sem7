from Cryptodome.Cipher import AES  # type: ignore
from Cryptodome.Util.Padding import pad, unpad  # type: ignore
import json, hashlib, hmac
import numpy as np  # type: ignore


import hashlib


def derive_keys(master_key: bytes):
    aes_inner = hashlib.sha256(master_key + b"INNER").digest()[:16]  # 128-bit
    aes_outer = hashlib.sha256(master_key + b"OUTER").digest()[:16]  # 128-bit
    hmac_key = hashlib.sha256(master_key + b"HMAC").digest()  # 256-bit
    return aes_inner, aes_outer, hmac_key


def make_packet(traj: np.ndarray, bundle_size: int = 500, aes_key: bytes = None): # pyright: ignore[reportArgumentType]
    rng = np.random.default_rng()
    states = traj[rng.choice(traj.shape[0], size=bundle_size, replace=False)]
    secret_idx = np.random.randint(0, bundle_size)

    cuts = (
        np.sort(rng.integers(0, secret_idx + 1, size=bundle_size - 1))
        if secret_idx > 0
        else np.zeros(bundle_size - 1, dtype=int)
    )
    parts = np.diff(np.concatenate(([0], cuts, [secret_idx]))).astype(float)

    # Generate AES key if not provided
    if aes_key is None:
        aes_key = rng.bytes(16)  # AES-128 key

    # AES-CBC encrypt "parts"
    cipher = AES.new(aes_key, AES.MODE_CBC)
    parts_bytes = pad(
        json.dumps(parts.tolist(), separators=(",", ":")).encode(),
        AES.block_size,
    )
    ct = cipher.encrypt(parts_bytes)
    iv = cipher.iv

    # Encode IV + ciphertext as hex
    enc_parts = iv.hex() + ct.hex()

    # Store encrypted parts in packet
    packet = np.column_stack([states, np.full((bundle_size, 1), enc_parts)])
    return packet, secret_idx


def decrypt_parts(enc_parts: str, aes_key: bytes) -> np.ndarray:
    # Extract IV and ciphertext from hex string
    enc_parts_bytes = bytes.fromhex(enc_parts)
    iv = enc_parts_bytes[: AES.block_size]
    ct = enc_parts_bytes[AES.block_size :]

    # AES-CBC decrypt
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    parts_bytes = unpad(cipher.decrypt(ct), AES.block_size)

    # Convert back to numpy array
    parts = np.array(json.loads(parts_bytes.decode()))
    return parts


def encrypt_packet(
    packet: np.ndarray, aes_key: bytes, hmac_key: bytes
) -> tuple[bytes, bytes, bytes]:
    # Serialize packet
    blob = json.dumps(packet.tolist(), separators=(",", ":")).encode()

    # AES-CBC encryption
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(blob, AES.block_size))

    # IV + ciphertext
    data = cipher.iv + ct

    # HMAC for integrity/authentication
    tag = hmac.new(hmac_key, data, hashlib.sha256).digest()

    return cipher.iv, ct, tag


def decrypt_packet(
    iv: bytes, ct: bytes, tag: bytes, aes_key: bytes, hmac_key: bytes
) -> np.ndarray:
    data = iv + ct

    # Verify HMAC
    expected_tag = hmac.new(hmac_key, data, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("Integrity check failed!")

    # AES decryption
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    blob = unpad(cipher.decrypt(ct), AES.block_size)

    # Convert back to numpy array
    return np.array(json.loads(blob.decode()))


# -------- XOR message using Lorenz state --------


def derive_mask(state: np.ndarray, length: int) -> bytes:
    s = json.dumps(
        np.asarray(state, dtype=float).tolist(), separators=(",", ":")
    ).encode()
    h = hashlib.sha256(s).digest()
    return (h * ((length // len(h)) + 1))[:length]


def xor_encrypt(msg: str, state: np.ndarray):
    msg_b = msg.encode()
    mask = derive_mask(np.array(state, dtype=float), len(msg_b))
    enc = bytes([b ^ m for b, m in zip(msg_b, mask)])
    return enc.hex(), mask


def xor_decrypt(enc_hex: str, state: np.ndarray):
    enc_b = bytes.fromhex(enc_hex)
    mask = derive_mask(np.array(state, dtype=float), len(enc_b))
    dec = bytes([b ^ m for b, m in zip(enc_b, mask)])
    return dec.decode(errors="strict"), mask
