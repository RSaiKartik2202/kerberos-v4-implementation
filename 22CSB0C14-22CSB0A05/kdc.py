
import argparse
import json
import socket
import threading
import time
from typing import Dict, Any
from common import encrypt_obj, decrypt_obj, send_json, recv_json, now_minutes, log

# In-memory DB loaded from JSON file


class AuthDB:
    def __init__(self, path: str):
        with open(path, 'r') as f:
            db = json.load(f)
        self.clients = db["clients"]           # { name: password }
        # { name: {"port": int, "password": str} }
        self.servers = db["servers"]
        self.ktgs = db["ktgs"]                 # secret shared by AS and TGS
        self.default_lifetime_tgt = db.get(
            "default_lifetime_tgt", 10)  # minutes
        self.default_lifetime_st = db.get(
            "default_lifetime_st", 5)     # minutes

# AS: handles TGT requests on port 6000


def run_as(db: AuthDB, host: str, port: int, initial_epoch: int):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)
    log(f"[AS] Listening on {host}:{port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_as_conn, args=(
            db, conn, addr, initial_epoch), daemon=True).start()


def handle_as_conn(db: AuthDB, conn: socket.socket, addr, initial_epoch: int):
    try:
        req = recv_json(conn)
        # Expect: {"type": "AS_REQ", "client": C, "nonce": n}
        if req.get("type") != "AS_REQ":
            send_json(conn, {"type": "ERR", "reason": "bad type"})
            return
        c = req["client"]
        nonce = req.get("nonce", 0)
        if c not in db.clients:
            send_json(conn, {"type": "ERR", "reason": "unknown client"})
            return
        nowm = now_minutes(initial_epoch)
        # Create session key for C<->TGS
        k_c_tgs = f"KC_TGS_{c}_{nowm}_{nonce}"
        # TGT: encrypted with K_tgs
        tgt = encrypt_obj({
            "client": c,
            "k_c_tgs": k_c_tgs,
            "ts": nowm,
            "lifetime": db.default_lifetime_tgt
        }, db.ktgs)
        # Reply to client, encrypted with K_c (client password)
        enc_for_c = encrypt_obj({
            "k_c_tgs": k_c_tgs,
            "tgt": tgt,
            "ts": nowm,
            "lifetime": db.default_lifetime_tgt,
            "nonce": nonce
        }, db.clients[c])
        send_json(conn, {"type": "AS_REP", "data": enc_for_c})
        log(f"[AS] Issued TGT to {c} at t={nowm} (lifetime={db.default_lifetime_tgt}m)")
    except Exception as e:
        try:
            send_json(conn, {"type": "ERR", "reason": str(e)})
        except:
            pass
    finally:
        conn.close()

# TGS: handles service ticket requests on port 6001


def run_tgs(db: AuthDB, host: str, port: int, initial_epoch: int):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)
    log(f"[TGS] Listening on {host}:{port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_tgs_conn, args=(
            db, conn, addr, initial_epoch), daemon=True).start()


def handle_tgs_conn(db: AuthDB, conn: socket.socket, addr, initial_epoch: int):
    try:
        req = recv_json(conn)
        # Expect: {"type": "TGS_REQ", "service": S, "tgt": TGT, "authenticator": ENC_{k_c_tgs}({client, ts})}
        if req.get("type") != "TGS_REQ":
            send_json(conn, {"type": "ERR", "reason": "bad type"})
            return
        service = req["service"]
        tgt = req["tgt"]
        auth = req["authenticator"]
        # Decrypt TGT with K_tgs
        tgt_plain = decrypt_obj(tgt, db.ktgs)
        c = tgt_plain["client"]
        k_c_tgs = tgt_plain["k_c_tgs"]
        ts_tgt = tgt_plain["ts"]
        lifetime_tgt = tgt_plain["lifetime"]
        nowm = now_minutes(initial_epoch)
        # Validate TGT lifetime
        if not (nowm >= ts_tgt and nowm <= ts_tgt + lifetime_tgt):
            send_json(conn, {"type": "ERR", "reason": "TGT expired"})
            return
        # Decrypt authenticator
        auth_plain = decrypt_obj(auth, k_c_tgs)
        if auth_plain.get("client") != c:
            send_json(
                conn, {"type": "ERR", "reason": "authenticator mismatch"})
            return
        # Check replay (freshness): authenticator ts must be close (within TGT lifetime)
        if not (nowm >= auth_plain.get("ts", -10) and nowm <= ts_tgt + lifetime_tgt):
            send_json(conn, {"type": "ERR", "reason": "stale authenticator"})
            return
        # Service exists?
        if service not in db.servers:
            send_json(conn, {"type": "ERR", "reason": "unknown service"})
            return
        ks = db.servers[service]["password"]
        # New session key C<->S
        k_c_s = f"KC_S_{c}_{service}_{nowm}"
        ticket_s = encrypt_obj({
            "client": c,
            "k_c_s": k_c_s,
            "ts": nowm,
            "lifetime": db.default_lifetime_st,
            "service": service
        }, ks)
        # Enc for client with k_c_tgs
        enc_for_c = encrypt_obj({
            "k_c_s": k_c_s,
            "ticket_s": ticket_s,
            "ts": nowm,
            "lifetime": db.default_lifetime_st,
            "service": service
        }, k_c_tgs)
        send_json(conn, {"type": "TGS_REP", "data": enc_for_c})
        log(f"[TGS] Issued ServiceTicket to {c} for {service} at t={nowm} (life={db.default_lifetime_st}m)")
    except Exception as e:
        try:
            send_json(conn, {"type": "ERR", "reason": str(e)})
        except:
            pass
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="auth_db.json")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--as-port", type=int, default=6000)
    ap.add_argument("--tgs-port", type=int, default=6001)
    ap.add_argument("--initial-wall-clock", type=int, required=False,
                    help="Shared initial epoch (UNIX seconds). Will read from epoch.txt.")
    args = ap.parse_args()

    # if not passed in command, read from epoch.txt
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

    db = AuthDB(args.db)
    threading.Thread(target=run_as, args=(
        db, args.host, args.as_port, args.initial_wall_clock), daemon=True).start()
    run_tgs(db, args.host, args.tgs_port, args.initial_wall_clock)


if __name__ == "__main__":
    main()
