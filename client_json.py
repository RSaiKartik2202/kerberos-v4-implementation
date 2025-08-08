# client.py
import socket
import json
from datetime import datetime

HOST = '127.0.0.1'
PORT = 6000

CLIENT_ID = "client123"
SERVER_ID = "server1"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("[CLIENT] Connected to server. Type 'exit' to quit.")

    while True:
        msg = input("Message (or 'exit'): ")
        if msg.lower() == 'exit':
            break

        payload = {
            "client_id": CLIENT_ID,
            "server_id": SERVER_ID,
            "timestamp": datetime.now().isoformat(),
            "message": msg
        }
        s.sendall(json.dumps(payload).encode())

        data = s.recv(1024)
        try:
            response = json.loads(data.decode())
            print("[SERVER REPLY]", response)

            
        except json.JSONDecodeError:
            print("[SERVER ERROR]", data.decode())
