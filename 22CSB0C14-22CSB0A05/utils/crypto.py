
from Crypto.Cipher import DES
from typing import Dict, Any
import hashlib
import json
import base64
import socket
import struct
import time

def _des_key_from_password(password: str) -> bytes:
    # Derive a valid 8-byte DES key from password
    return hashlib.md5(password.encode()).digest()[:8]

def encrypt_obj(obj: Dict[str, Any], key: str) -> str:
    data = json.dumps(obj, separators=(',', ':')).encode('utf-8')
    des_key = _des_key_from_password(key)

    cipher = DES.new(des_key, DES.MODE_ECB)

    # Pad to 8 bytes (PKCS#7)
    pad_len = 8 - (len(data) % 8)
    data += bytes([pad_len]) * pad_len

    ct = cipher.encrypt(data)
    return base64.b64encode(ct).decode('ascii')

def decrypt_obj(token: str, key: str) -> Dict[str, Any]:
    ct = base64.b64decode(token)
    des_key = _des_key_from_password(key)

    cipher = DES.new(des_key, DES.MODE_ECB)
    pt = cipher.decrypt(ct)

    # Unpad
    pad_len = pt[-1]
    pt = pt[:-pad_len]

    return json.loads(pt.decode('utf-8'))


# ---------- Framed JSON over TCP ----------
def send_json(sock: socket.socket, obj: Dict[str, Any]) -> None:
    data = json.dumps(obj).encode('utf-8')
    hdr = struct.pack('!I', len(data))
    sock.sendall(hdr + data)

def recv_json(sock: socket.socket) -> Dict[str, Any]:
    hdr = _recvall(sock, 4)
    if not hdr:
        raise ConnectionError("Connection closed")
    (n,) = struct.unpack('!I', hdr)
    data = _recvall(sock, n)
    return json.loads(data.decode('utf-8'))

def _recvall(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed during recv")
        buf.extend(chunk)
    return bytes(buf)

# ---------- Time helpers ----------
def now_minutes(initial_epoch: int) -> int:
    """Return current timestamp in minutes since the shared initial_wall_clock epoch."""
    return int((time.time() - initial_epoch) // 60)

def within_lifetime(start_ts: int, lifetime_min: int, now_min: int) -> bool:
    return now_min >= start_ts and now_min <= start_ts + lifetime_min

# ---------- Convenience ----------
def log(*args):
    print(*args, flush=True)


# ---------- Framed JSON over TCP ----------
def send_json(sock: socket.socket, obj: Dict[str, Any]) -> None:
    data = json.dumps(obj).encode('utf-8')
    hdr = struct.pack('!I', len(data))
    sock.sendall(hdr + data)

def recv_json(sock: socket.socket) -> Dict[str, Any]:
    hdr = _recvall(sock, 4)
    if not hdr:
        raise ConnectionError("Connection closed")
    (n,) = struct.unpack('!I', hdr)
    data = _recvall(sock, n)
    return json.loads(data.decode('utf-8'))

def _recvall(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed during recv")
        buf.extend(chunk)
    return bytes(buf)

# ---------- Time helpers ----------
def now_minutes(initial_epoch: int) -> int:
    """Return current timestamp in minutes since the shared initial_wall_clock epoch."""
    return int((time.time() - initial_epoch) // 60)

def within_lifetime(start_ts: int, lifetime_min: int, now_min: int) -> bool:
    return now_min >= start_ts and now_min <= start_ts + lifetime_min

# ---------- Convenience ----------
def log(*args):
    print(*args, flush=True)
