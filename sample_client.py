# client.py
import socket

HOST = '127.0.0.1'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("[CLIENT] Connected to server. Type 'exit' to disconnect.")
    while True:
        message = input("You: ")
        s.sendall(message.encode())

        if message.lower() == 'exit':
            print("[CLIENT] Disconnected from server.")
            break

        data = s.recv(1024)
        print("Server:", data.decode())

