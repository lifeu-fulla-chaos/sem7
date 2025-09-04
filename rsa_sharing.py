from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os, hashlib


# ---------------- Receiver: Generate RSA keys ----------------
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


# ---------------- Sender: Encrypt master key ----------------
def encrypt_master_key(public_key: bytes, master_key: bytes) -> bytes:
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(master_key)


# ---------------- Receiver: Decrypt master key ----------------
def decrypt_master_key(private_key: bytes, encrypted_master: bytes) -> bytes:
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(encrypted_master)


# ---------------- Derive AES/HMAC subkeys ----------------
def derive_keys(master_key: bytes):
    aes_inner = hashlib.sha256(master_key + b"INNER").digest()[:16]  # AES-128
    aes_outer = hashlib.sha256(master_key + b"OUTER").digest()[:16]  # AES-128
    hmac_key = hashlib.sha256(master_key + b"HMAC").digest()  # 256-bit
    return aes_inner, aes_outer, hmac_key
