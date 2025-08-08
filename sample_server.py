# server.py
import socket
import threading

HOST = '127.0.0.1'
PORT = 65432

def handle_client(conn, addr):
    print(f"[+] New connection from {addr}")
    with conn:
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                message = data.decode()
                print(f"[{addr}] {message}")
                if message.lower() == 'exit':
                    print(f"[-] {addr} disconnected.")
                    break
                conn.sendall(f"Server received: {message}".encode())
            except ConnectionResetError:
                print(f"[!] {addr} forcefully closed the connection.")
                break
    print(f"[THREAD END] Handler for {addr} exited.")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[SERVER] Listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()

if __name__ == "__main__":
    main()

