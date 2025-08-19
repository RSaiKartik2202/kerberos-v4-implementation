import socket
import threading
import os
from dotenv import load_dotenv
from utils.crypto import encrypt_obj, decrypt_obj, send_json, recv_json, now_minutes, within_lifetime, log

load_dotenv()  # Load .env variables

def handle_client(conn: socket.socket, addr, server_name: str, server_pass: str, initial_epoch: int):
    try:
        req = recv_json(conn)
        if req.get("type") != "APP_REQ":
            send_json(conn, {"type": "ERR", "reason": "bad type"})
            return

        # Expect fields from client.py
        Ticketv = req["Ticketv"]
        Authenticatorc = req["Authenticatorc"]
        enc_msg = req["Message"]

        # Decrypt service ticket with server's secret
        ticket_data = decrypt_obj(Ticketv, server_pass)
        Kc_v = ticket_data["Kc_v"]
        client_id = ticket_data["IDc"]
        ts_ticket = ticket_data["TS4"]
        lifetime = ticket_data["Lifetime4"]

        nowm = now_minutes(initial_epoch)
        if not within_lifetime(ts_ticket, lifetime, nowm):
            send_json(conn, {"type": "ERR", "reason": "service ticket expired"})
            return

        # Decrypt authenticator with session key
        auth_data = decrypt_obj(Authenticatorc, Kc_v)
        if auth_data.get("IDc") != client_id:
            send_json(conn, {"type": "ERR", "reason": "client mismatch"})
            return
        if auth_data.get("ADc") != addr[0]:
            send_json(conn, {"type": "ERR", "reason": "client IP mismatch"})
            return

        # Decrypt message
        msgobj = decrypt_obj(enc_msg, Kc_v)
        message = msgobj.get("msg", "")
        log(f"[{server_name}] Received secure message from {client_id}: {message}")

        # Respond encrypted with session key
        resp = encrypt_obj({"ack": f"Hello {client_id}, message received by {server_name}.",
                            "TS5+1": nowm + 1}, Kc_v)
        send_json(conn, {"type": "APP_REP", "data": resp})

    except Exception as e:
        try:
            send_json(conn, {"type": "ERR", "reason": str(e)})
        except:
            pass
    finally:
        conn.close()


def run_server(server_name: str, server_pass: str, port: int, initial_epoch: int, host: str = "127.0.0.1"):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)
    log(f"[{server_name}] Listening on {host}:{port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client,
                         args=(conn, addr, server_name, server_pass, initial_epoch), daemon=True).start()


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True,
                    help="Server name (e.g., fileServer or mailServer)")
    ap.add_argument("--initial-wall-clock", type=int, required=False)
    args = ap.parse_args()

    if args.initial_wall_clock is None:
        try:
            with open("epoch.txt", "r") as f:
                args.initial_wall_clock = int(f.read().strip())
            log(f"[INFO] Loaded initial wall clock from epoch.txt: {args.initial_wall_clock}")
        except FileNotFoundError:
            raise FileNotFoundError("epoch.txt not found. Please run time_synchronize.py first")
        except ValueError:
            raise ValueError("Invalid value in epoch.txt")

    server_name = args.server
    server_pass = os.getenv(f"{server_name.upper()}_PASSWORD")
    port = int(os.getenv(f"{server_name.upper()}_PORT"))

    if not server_pass or not port:
        raise SystemExit(f"Server password or port not defined for {server_name} in .env")

    run_server(server_name, server_pass, port, args.initial_wall_clock)


if __name__ == "__main__":
    main()
