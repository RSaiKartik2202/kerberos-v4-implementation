
import argparse
import socket
import json
import time
from common import encrypt_obj, decrypt_obj, send_json, recv_json, now_minutes, log


def as_req(as_host, as_port, client_name, client_pass, initial_epoch):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((as_host, as_port))
    nonce = int(time.time()) & 0xffff
    send_json(s, {"type": "AS_REQ", "client": client_name, "nonce": nonce})
    rep = recv_json(s)
    s.close()
    if rep.get("type") != "AS_REP":
        raise RuntimeError(f"AS error: {rep}")
    data = decrypt_obj(rep["data"], client_pass)
    # returns k_c_tgs, tgt
    return data["k_c_tgs"], data["tgt"], data["lifetime"]


def tgs_req(tgs_host, tgs_port, service, tgt, k_c_tgs, client_name, initial_epoch):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((tgs_host, tgs_port))
    ts = now_minutes(initial_epoch)
    authenticator = encrypt_obj({"client": client_name, "ts": ts}, k_c_tgs)
    send_json(s, {"type": "TGS_REQ", "service": service,
              "tgt": tgt, "authenticator": authenticator})
    rep = recv_json(s)
    s.close()
    if rep.get("type") != "TGS_REP":
        raise RuntimeError(f"TGS error: {rep}")
    data = decrypt_obj(rep["data"], k_c_tgs)
    return data["k_c_s"], data["ticket_s"], data["lifetime"]


def app_req(server_host, server_port, ticket_s, k_c_s, client_name, message, initial_epoch):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server_host, server_port))
    ts = now_minutes(initial_epoch)
    authenticator = encrypt_obj({"client": client_name, "ts": ts}, k_c_s)
    enc_msg = encrypt_obj({"msg": message, "ts": ts}, k_c_s)
    send_json(s, {"type": "APP_REQ", "ticket": ticket_s,
              "authenticator": authenticator, "message": enc_msg})
    rep = recv_json(s)
    s.close()
    if rep.get("type") != "APP_REP":
        raise RuntimeError(f"APP error: {rep}")
    data = decrypt_obj(rep["data"], k_c_s)
    return data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="auth_db.json")
    ap.add_argument("--client", required=True,
                    help="Client principal")
    ap.add_argument("--service", required=True,
                    help="Service principal (e.g., filesvc or chatsvc)")
    ap.add_argument("--message", default="Hello from client!")
    ap.add_argument("--as-host", default="127.0.0.1")
    ap.add_argument("--as-port", type=int, default=6000)
    ap.add_argument("--tgs-host", default="127.0.0.1")
    ap.add_argument("--tgs-port", type=int, default=6001)
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
    if args.client not in db["clients"]:
        raise SystemExit("Unknown client in DB")
    if args.service not in db["servers"]:
        raise SystemExit("Unknown service in DB")
    client_pass = db["clients"][args.client]
    # 1) AS exchange
    k_c_tgs, tgt, tgt_life = as_req(
        args.as_host, args.as_port, args.client, client_pass, args.initial_wall_clock)
    log(f"[Client:{args.client}] Got TGT (life={tgt_life}m)")
    # 2) TGS exchange
    k_c_s, ticket_s, st_life = tgs_req(
        args.tgs_host, args.tgs_port, args.service, tgt, k_c_tgs, args.client, args.initial_wall_clock)
    log(f"[Client:{args.client}] Got ServiceTicket for {args.service} (life={st_life}m)")
    # 3) App request
    srv = db["servers"][args.service]
    rep = app_req("127.0.0.1", srv["port"], ticket_s, k_c_s,
                  args.client, args.message, args.initial_wall_clock)
    log(f"[Client:{args.client}] Server reply: {rep['ack']}")
    # 4) Reuse ticket within lifetime
    log(f"[Client:{args.client}] Reusing ServiceTicket within lifetime...")
    rep2 = app_req("127.0.0.1", srv["port"], ticket_s, k_c_s, args.client,
                   args.message + " (second call)", args.initial_wall_clock)
    log(f"[Client:{args.client}] Second reply: {rep2['ack']}")


if __name__ == "__main__":
    main()
