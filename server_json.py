# server.py
import socket
import threading
import json
from datetime import datetime

HOST = '127.0.0.1'
PORT = 6000

def handle_client(conn, addr):
    print(f"[+] Connected by {addr}")
    with conn:
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                try:
                    message = json.loads(data.decode())
                    client_id = message.get("client_id")
                    server_id = message.get("server_id")
                    timestamp = message.get("timestamp")
                    print(f"[RECEIVED] Client: {client_id} | Server: {server_id} | Time: {timestamp}")
                    response = {"status": "ok", "echo": message}
                    conn.sendall(json.dumps(response).encode())
                except json.JSONDecodeError:
                    print("[!] Received non-JSON data:", data.decode())
                    conn.sendall(b"Invalid message format")
            except ConnectionResetError:
                break
    print(f"[-] {addr} disconnected.")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[SERVER] Listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
