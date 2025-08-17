
import json
import base64
import hashlib
import socket
import struct
import time
from typing import Dict, Any

# ---------- Simple symmetric "encryption" (XOR with SHA256-derived keystream) ----------
def _keystream(key: bytes, n: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        h = hashlib.sha256(key + counter.to_bytes(8, 'big')).digest()
        out.extend(h)
        counter += 1
    return bytes(out[:n])

def encrypt_obj(obj: Dict[str, Any], key: str) -> str:
    data = json.dumps(obj, separators=(',', ':')).encode('utf-8')
    ks = _keystream(key.encode('utf-8'), len(data))
    ct = bytes([a ^ b for a, b in zip(data, ks)])
    return base64.b64encode(ct).decode('ascii')

def decrypt_obj(token: str, key: str) -> Dict[str, Any]:
    ct = base64.b64decode(token)
    ks = _keystream(key.encode('utf-8'), len(ct))
    data = bytes([a ^ b for a, b in zip(ct, ks)])
    return json.loads(data.decode('utf-8'))

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
