# crypto_utils.py
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
from typing import Tuple

DES_KEY = b'8bytekey'  # must be exactly 8 bytes

def encrypt_des(data: bytes, key: bytes = DES_KEY) -> Tuple[bytes, bytes]:
    cipher = DES.new(key, DES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, DES.block_size))
    return cipher.iv, ciphertext

def decrypt_des(ciphertext: bytes, iv: bytes, key: bytes = DES_KEY) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), DES.block_size)

def encode_for_json(iv: bytes, ciphertext: bytes) -> str:
    combined = iv + ciphertext
    return base64.b64encode(combined).decode()

def decode_from_json(encoded_str: str) -> Tuple[bytes, bytes]:
    raw = base64.b64decode(encoded_str)
    iv = raw[:8]
    ciphertext = raw[8:]
    return iv, ciphertext
