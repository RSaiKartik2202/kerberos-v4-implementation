# server.py
import socket
import threading
import json
from utils.des import decode_from_json, decrypt_des

HOST = '127.0.0.1'
PORT = 65432

def handle_client(conn, addr):
    print(f"[+] Connected: {addr}")
    with conn:
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break

                outer_json = json.loads(data.decode())
                print(f"\n[Metadata] Client: {outer_json['client_id']} | Server: {outer_json['server_id']}")

                payload_b64 = outer_json["payload"]
                iv, ciphertext = decode_from_json(payload_b64)
                decrypted_data = decrypt_des(ciphertext, iv)

                inner_json = json.loads(decrypted_data.decode())
                print(f"[Decrypted Payload] Command: {inner_json['command']} | Content: {inner_json['content']} | Time: {inner_json['timestamp']}")

            except Exception as e:
                print("[!] Error:", str(e))
                break

    print(f"[-] Disconnected: {addr}")

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
