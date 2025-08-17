
import argparse
import socket
import threading
from typing import Dict, Any
from common import encrypt_obj, decrypt_obj, send_json, recv_json, now_minutes, within_lifetime, log


def handle_client(conn: socket.socket, addr, server_name: str, server_pass: str, initial_epoch: int):
    try:
        req = recv_json(conn)
        # Expect {"type":"APP_REQ","ticket":ticket_s,"authenticator":enc_kcs({client,ts}),"message":enc_kcs({msg,ts})}
        if req.get("type") != "APP_REQ":
            send_json(conn, {"type": "ERR", "reason": "bad type"})
            return
        ticket = req["ticket"]
        auth = req["authenticator"]
        # Decrypt ticket with K_s
        t = decrypt_obj(ticket, server_pass)
        c = t["client"]
        k_c_s = t["k_c_s"]
        ts_ticket = t["ts"]
        lifetime = t["lifetime"]
        nowm = now_minutes(initial_epoch)
        if not within_lifetime(ts_ticket, lifetime, nowm):
            send_json(
                conn, {"type": "ERR", "reason": "service ticket expired"})
            return
        # Check authenticator
        a = decrypt_obj(auth, k_c_s)
        if a.get("client") != c:
            send_json(conn, {"type": "ERR", "reason": "client mismatch"})
            return
        # Decrypt message
        msgobj = decrypt_obj(req.get("message"), k_c_s)
        message = msgobj.get("msg", "")
        log(f"[{server_name}] Received secure message from {c}: {message}")
        # Respond
        resp = encrypt_obj(
            {"ack": f"Hello {c}, message received by {server_name}.", "ts": nowm}, k_c_s)
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
        threading.Thread(target=handle_client, args=(
            conn, addr, server_name, server_pass, initial_epoch), daemon=True).start()


def main():
    import json
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="auth_db.json")
    ap.add_argument("--name", required=True,
                    help="Server name as in DB (e.g., filesvc or chatsvc)")
    ap.add_argument("--initial-wall-clock", type=int, required=False)
    args = ap.parse_args()

    if args.initial_wall_clock is None:
        try:
            with open("epoch.txt", "r") as f:
                args.initial_wall_clock = int(f.read().strip())
            print(
                f"[INFO] Loaded initial wall clock from epoch.txt: {args.initial_wall_clock}")
        except FileNotFoundError:
            raise FileNotFoundError(
                "epoch.txt not found. Please run time_synchronize.py first")
        except ValueError:
            raise ValueError("Invalid value in epoch.txt")

    with open(args.db, 'r') as f:
        db = json.load(f)
    server = db["servers"][args.name]
    run_server(args.name, server["password"],
               server["port"], args.initial_wall_clock)


if __name__ == "__main__":
    main()
