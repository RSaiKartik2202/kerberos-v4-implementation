import socket
import json
from datetime import datetime
# from utils.des import encrypt_des, encode_for_json

HOST = '127.0.0.1'
PORT = 6000

client_id = "client123"
server_id = "server1"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    while True:
        msg = input("Message (or 'exit'): ")
        if msg.lower() == 'exit':
            break
        tgt_req = {
            "client_id": client_id,
            "tgs_id": server_id,
            "timestamp": datetime.now().isoformat()
        }
        s.sendall(json.dumps(tgt_req).encode())

        data = s.recv(1024)
        try:
            response = json.loads(data.decode())
            print("Authenitcation Server reply:", response)

            
        except json.JSONDecodeError:
            print("Authenitcation Server error:", data.decode())