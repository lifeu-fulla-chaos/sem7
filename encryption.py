from Crypto.Cipher import AES  # type: ignore
from Crypto.Util.Padding import pad, unpad  # type: ignore
import json, hashlib, hmac
import numpy as np  # type: ignore
import hashlib
import hmac
import struct
import random
import hashlib


def derive_keys(master_key: bytes):
    aes_inner = hashlib.sha256(master_key + b"INNER").digest()[:16]  # 128-bit
    aes_outer = hashlib.sha256(master_key + b"OUTER").digest()[:16]  # 128-bit
    hmac_key = hashlib.sha256(master_key + b"HMAC").digest()  # 256-bit
    return aes_inner, aes_outer, hmac_key


def make_packet(
    traj: np.ndarray, bundle_size: int = 500, aes_key: bytes = None  # type: ignore
):  # pyright: ignore[reportArgumentType]
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
    data = cipher.iv + ct  # type: ignore

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


def xor_encrypt(msg: str | bytes, state: np.ndarray) -> tuple[str, bytes]:
    msg_b = msg.encode() if isinstance(msg, str) else msg
    mask = derive_mask(np.array(state, dtype=float), len(msg_b))
    enc = bytes([b ^ m for b, m in zip(msg_b, mask)])
    return enc.hex(), mask


def xor_decrypt(enc_hex: bytes | str, state: np.ndarray):
    if isinstance(enc_hex, str):
        enc_b = bytes.fromhex(enc_hex)
    else:
        enc_b = enc_hex
    mask = derive_mask(np.array(state, dtype=float), len(enc_b))
    dec = bytes([b ^ m for b, m in zip(enc_b, mask)])
    return dec, mask


def fisher_yates_sbox(seed):
    """Generate S-box using Fisher-Yates shuffle with given seed"""
    random.seed(seed)
    sbox = list(range(256))
    for i in range(255, 0, -1):
        j = random.randint(0, i)
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox


def sha256_counter_keystream(key, counter, length):
    """Generate keystream using SHA256 in counter mode"""
    keystream = b""
    block_size = 32  # SHA256 output size
    blocks_needed = (length + block_size - 1) // block_size

    for i in range(blocks_needed):
        counter_bytes = struct.pack(">Q", counter + i)
        hash_input = key + counter_bytes
        block = hashlib.sha256(hash_input).digest()
        keystream += block

    return keystream[:length]


def encrypt_audio(audio_counter, audio_data, lorenz_states):
    lorenz_state = lorenz_states[audio_counter % len(lorenz_states)]

    mixed_data = audio_data + lorenz_state[0] * 0.1  # Small mixing factor

    lorenz_bytes = struct.pack(
        ">ddd", lorenz_state[0], lorenz_state[1], lorenz_state[2]
    )
    seed_input = lorenz_bytes + struct.pack(">I", audio_counter)  # Different key slice
    audio_seed = struct.unpack(">I", hashlib.sha256(seed_input).digest()[:4])[0]

    # Step 5: Generate S-box
    sbox = fisher_yates_sbox(audio_seed)

    # Step 6: Convert mixed data to bytes for encryption
    audio_nonce = struct.pack(">Q", audio_counter)
    keystream = sha256_counter_keystream(audio_nonce, 0, len(mixed_data))

    # Step 7: Encrypt with different pipeline for audio: XOR -> S-box -> Feedback
    encrypted = bytearray()
    prev_byte = 0xA5  # Different IV for audio

    for i, byte in enumerate(mixed_data):
        # XOR with keystream first (different order than video)
        xor_byte = byte ^ keystream[i % len(keystream)]
        # S-box substitution
        sub_byte = sbox[xor_byte]
        # Feedback chain
        chain_byte = sub_byte ^ prev_byte
        encrypted.append(chain_byte)
        prev_byte = chain_byte

    # Step 8: Generate HMAC
    auth_data = struct.pack(">I", audio_counter) + audio_nonce + bytes(encrypted)
    auth_tag = hmac.new(lorenz_bytes, auth_data, hashlib.sha256).digest()
    return encrypted, audio_nonce, auth_tag


def inverse_sbox(sbox):
    """Generate inverse S-box"""
    inv_sbox = [0] * 256
    for i in range(256):
        inv_sbox[sbox[i]] = i
    return inv_sbox


def decrypt_audio(encrypted_packet, frame_no, lorenz_states):
    ciphertext = encrypted_packet["ciphertext"]
    frame_nonce = encrypted_packet["frame_nonce"]
    auth_tag = encrypted_packet["auth_tag"]

    # Step 2: Get same Lorenz state as encryption
    lorenz_state = lorenz_states[frame_no % len(lorenz_states)]

    # Step 3: Generate same audio seed (different from video)
    lorenz_bytes = struct.pack(
        ">ddd", lorenz_state[0], lorenz_state[1], lorenz_state[2]
    )
    # Step 1: Verify HMAC first
    auth_data = struct.pack(">I", frame_no) + frame_nonce + ciphertext
    expected_tag = hmac.new(lorenz_bytes, auth_data, hashlib.sha256).digest()

    if not hmac.compare_digest(auth_tag, expected_tag):
        raise ValueError("Audio authentication failed")

    seed_input = lorenz_bytes + struct.pack(">I", frame_no)
    audio_seed = struct.unpack(">I", hashlib.sha256(seed_input).digest()[:4])[0]

    # Step 4: Generate same S-box and inverse
    sbox = fisher_yates_sbox(audio_seed)
    inv_sbox = inverse_sbox(sbox)

    # Step 5: Generate same keystream
    keystream = sha256_counter_keystream(frame_nonce, 0, len(ciphertext))

    # Step 6: Decrypt by reversing: Feedback -> Inverse S-box -> XOR
    decrypted = bytearray()
    prev_byte = 0xA5  # Same IV as audio encryption

    for i, byte in enumerate(ciphertext):
        # Reverse feedback chain
        chain_byte = byte ^ prev_byte
        # Reverse S-box substitution
        xor_byte = inv_sbox[chain_byte]
        # Reverse XOR with keystream
        original_byte = xor_byte ^ keystream[i % len(keystream)]
        decrypted.append(original_byte)
        prev_byte = byte  # Use original ciphertext byte for next iteration

    # Step 7: Convert back to float64 and reverse Lorenz mixing
    try:
        mixed_data = np.frombuffer(bytes(decrypted), dtype=np.float32).astype(
            np.float64
        )
        audio_float = mixed_data - lorenz_state[0] * 0.1  # Reverse the mixing
        audio_int16 = np.clip(audio_float, -32768, 32767).astype(np.int16)

        print(f"Audio {frame_no}: Decrypted successfully")
        return audio_int16.tobytes()
    except Exception as e:
        raise ValueError(f"Audio reconstruction failed for block {frame_no}: {e}")
