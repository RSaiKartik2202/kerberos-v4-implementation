import argparse
import socket
import threading
from utils.crypto import encrypt_obj, decrypt_obj, send_json, recv_json, now_minutes, log
from utils.kerberos_db import get_client, get_server, get_tgs, get_tgs_by_id

# --- AS: Handles TGT requests ---
def run_as(host: str, port: int, initial_epoch: int):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)
    log(f"[AS] Listening on {host}:{port}")
    
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_as_conn, args=(conn, addr, initial_epoch), daemon=True).start()


def handle_as_conn(conn, addr, initial_epoch: int):
    try:
        req = recv_json(conn)
        if req.get("type") != "AS_REQ":
            return send_json(conn, {"type": "ERR", "reason": "bad type"})

        IDc, IDtgs, TS1 = req["IDc"], req["IDtgs"], req["TS1"]
        client = get_client(IDc)
        tgs = get_tgs_by_id(IDtgs)

        if not tgs:
            return send_json(conn, {"type": "ERR", "reason": "unknown TGS"})

        if not client:
            return send_json(conn, {"type": "ERR", "reason": "unknown client"})

        nowm = now_minutes(initial_epoch)
        Kc_tgs = f"Kc_tgs::{IDc}::{nowm}"
        Lifetime2 = tgs["default_lifetime_tgt"]
        TS2 = nowm

        ADc = addr[0]  # client IP
        # Build TGT (encrypted with Ktgs)
        Tickettgs = encrypt_obj({
            "Kc_tgs": Kc_tgs,
            "IDc": IDc,
            "ADc": ADc,
            "IDtgs": IDtgs,
            "TS2": TS2,
            "Lifetime2": Lifetime2
        }, tgs["ktgs"])

        # Encrypt response for client using client's password (long-term key)
        enc_for_c = encrypt_obj({
            "Kc_tgs": Kc_tgs,
            "IDtgs": IDtgs,
            "TS2": TS2,
            "Lifetime2": Lifetime2,
            "Tickettgs": Tickettgs
        }, client["password"])

        send_json(conn, {"type": "AS_REP", "data": enc_for_c})
        log(f"[AS] TGT→{IDc} TS2={TS2} life={Lifetime2}m")
    except Exception as e:
        send_json(conn, {"type": "ERR", "reason": str(e)})
    finally:
        conn.close()


# --- TGS: Handles service ticket requests ---
def run_tgs(host: str, port: int, initial_epoch: int):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)
    log(f"[TGS] Listening on {host}:{port}")
    
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_tgs_conn, args=(conn, addr, initial_epoch), daemon=True).start()


def handle_tgs_conn(conn, addr, initial_epoch: int):
    try:
        req = recv_json(conn)
        if req.get("type") != "TGS_REQ":
            return send_json(conn, {"type": "ERR", "reason": "bad type"})

        IDv = req["IDv"]
        Tickettgs = req["Tickettgs"]
        Authc = req["Authenticatorc"]

        tgt_data = decrypt_obj(Tickettgs, None)

        tgs = get_tgs()
        tgt_data = decrypt_obj(Tickettgs, tgs["ktgs"])
        Kc_tgs, IDc, ADc_tgt, _, TS2, Lifetime2 = (
            tgt_data["Kc_tgs"],
            tgt_data["IDc"],
            tgt_data["ADc"],
            tgt_data["IDtgs"],
            tgt_data["TS2"],
            tgt_data["Lifetime2"],
        )

        nowm = now_minutes(initial_epoch)
        if not (TS2 <= nowm <= TS2 + Lifetime2):
            return send_json(conn, {"type": "ERR", "reason": "TGT expired"})

        auth_data = decrypt_obj(Authc, Kc_tgs)
        if auth_data["IDc"] != IDc:
            return send_json(conn, {"type": "ERR", "reason": "client mismatch"})
        if auth_data["ADc"] != ADc_tgt:
            return send_json(conn, {"type": "ERR", "reason": "addr mismatch"})
        if auth_data["TS3"] > nowm or auth_data["TS3"] < TS2:
            return send_json(conn, {"type": "ERR", "reason": "stale authenticator"})

        service = get_server(IDv)
        if not service:
            return send_json(conn, {"type": "ERR", "reason": "unknown service"})
        Kv = service["password"]

        Kc_v = f"Kc_v::{IDc}::{IDv}::{nowm}"
        Lifetime4 = tgs["default_lifetime_st"]
        TS4 = nowm

        Ticketv = encrypt_obj({
            "Kc_v": Kc_v,
            "IDc": IDc,
            "ADc": ADc_tgt,
            "IDv": IDv,
            "TS4": TS4,
            "Lifetime4": Lifetime4
        }, Kv)

        enc_for_c = encrypt_obj({
            "Kc_v": Kc_v,
            "IDv": IDv,
            "TS4": TS4,
            "Ticketv": Ticketv
        }, Kc_tgs)

        send_json(conn, {"type": "TGS_REP", "data": enc_for_c})
        log(f"[TGS] SGT→{IDc} for {IDv} TS4={TS4} life={Lifetime4}m")
    except Exception as e:
        send_json(conn, {"type": "ERR", "reason": str(e)})
    finally:
        conn.close()


# --- Main ---
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--as-port", type=int, default=6000)
    ap.add_argument("--tgs-port", type=int, default=6001)
    ap.add_argument(
        "--initial-wall-clock",
        type=int,
        required=False,
        help="Shared initial epoch (UNIX seconds). Will read from epoch.txt.",
    )
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

    threading.Thread(target=run_as, args=(args.host, args.as_port, args.initial_wall_clock), daemon=True).start()
    run_tgs(args.host, args.tgs_port, args.initial_wall_clock)


if __name__ == "__main__":
    main()
