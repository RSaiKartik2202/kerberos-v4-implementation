import socket
import threading
import json
from utils.des import decode_from_json, decrypt_des

HOST = '127.0.0.1'
PORT = 6000

def handle_client(conn, addr):
    print(f"{addr} connected.")
    with conn:
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                try:
                    message = json.loads(data.decode())
                    client_id = message.get("client_id")
                    tgs_id = message.get("tgs_id")
                    timestamp = message.get("timestamp")
                    print(f"Received tgt request: client: {client_id} | tgs: {tgs_id} | Time: {timestamp}")
                    response = {"status": "ok", "echo": message}
                    conn.sendall(json.dumps(response).encode())
                except json.JSONDecodeError:
                    print("Received non-JSON data:", data.decode())
                    conn.sendall(b"Invalid message format")
            except ConnectionResetError:
                break
    print(f"{addr} disconnected.")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"Authentication Server: Listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()