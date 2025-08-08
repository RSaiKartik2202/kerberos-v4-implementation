# client.py
import socket
import json
from datetime import datetime
from utils.des import encrypt_des, encode_for_json

HOST = '127.0.0.1'
PORT = 65432

client_id = "client123"
server_id = "server1"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("[CLIENT] Connected. Type 'exit' to quit.")

    while True:
        msg = input("Message: ")
        if msg.lower() == "exit":
            break

        inner_json = {
            "command": "message",
            "content": msg,
            "timestamp": datetime.now().isoformat()
        }

        iv, encrypted_payload = encrypt_des(json.dumps(inner_json).encode())
        payload_b64 = encode_for_json(iv, encrypted_payload)

        outer_json = {
            "client_id": client_id,
            "server_id": server_id,
            "timestamp": datetime.now().isoformat(),
            "payload": payload_b64
        }

        s.sendall(json.dumps(outer_json).encode())
