import socket
import argparse
from dotenv import load_dotenv
import os
from utils.crypto import encrypt_obj, decrypt_obj, send_json, recv_json, now_minutes, log
from diskcache import Cache

# --- Load client config ---
load_dotenv()

CLIENT_NAME = os.getenv("CLIENT_NAME")
CLIENT_PASSWORD = os.getenv("CLIENT_PASSWORD")
TGS_HOST = os.getenv("TGS_HOST", "127.0.0.1")
TGS_PORT = int(os.getenv("TGS_PORT", 6001))
TGS_ID = os.getenv("TGS_ID", "tgs1")
CLIENT_AD = os.getenv("CLIENT_AD", "127.0.0.1")  # Optional, usually client IP

# --- Cache for TGTs / Service Tickets ---
cache = Cache("./kerberos_cache")

# --- AS request ---
def as_req(as_host, as_port, client_name, client_pass, idtgs, adc, initial_epoch):
    cached = cache.get("tgt", default=None)
    nowm = now_minutes(initial_epoch)

    if cached and (nowm <= cached["TS2"] + cached["Lifetime2"]):
        return cached["Kc_tgs"], cached["Tickettgs"], cached["Lifetime2"], cached["TS2"]

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((as_host, as_port))
    TS1 = nowm
    send_json(s, {"type":"AS_REQ", "IDc":client_name, "IDtgs":idtgs, "TS1":TS1})
    rep = recv_json(s)
    s.close()

    if rep.get("type") != "AS_REP":
        raise RuntimeError(f"AS error: {rep}")

    plain = decrypt_obj(rep["data"], client_pass)
    cache.set("tgt", plain)
    return plain["Kc_tgs"], plain["Tickettgs"], plain["Lifetime2"], plain["TS2"]

# --- TGS request ---
def tgs_req(tgs_host, tgs_port, service, tickettgs, Kc_tgs, client_name, adc, initial_epoch):
    key = f"sgt:{service}"
    cached = cache.get(key, default=None)
    nowm = now_minutes(initial_epoch)

    if cached and (nowm <= cached["TS4"] + cached["Lifetime4"]):
        return cached["Kc_v"], cached["Ticketv"], cached["Lifetime4"], cached["TS4"]

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((tgs_host, tgs_port))
    TS3 = nowm
    authenticator_c = encrypt_obj({"IDc":client_name, "ADc":adc, "TS3":TS3}, Kc_tgs)

    send_json(s, {
        "type":"TGS_REQ",
        "IDv": service,
        "Tickettgs": tickettgs,
        "Authenticatorc": authenticator_c
    })
    rep = recv_json(s)
    s.close()

    if rep.get("type") != "TGS_REP":
        raise RuntimeError(f"TGS error: {rep}")

    plain = decrypt_obj(rep["data"], Kc_tgs)
    cache.set(key, plain)
    return plain["Kc_v"], plain["Ticketv"], plain["Lifetime4"] ,plain["TS4"]

# --- Application request ---
def app_req(server_host, server_port, Ticketv, Kc_v, client_name, adc, message, initial_epoch):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server_host, server_port))

    TS5 = now_minutes(initial_epoch)
    Authenticatorc = encrypt_obj({"IDc":client_name, "ADc":adc, "TS5":TS5}, Kc_v)
    enc_msg = encrypt_obj({"msg": message, "TS5": TS5}, Kc_v)

    send_json(s, {"type":"APP_REQ", "Ticketv": Ticketv, "Authenticatorc": Authenticatorc, "Message": enc_msg})
    rep = recv_json(s)
    s.close()

    if rep.get("type") != "APP_REP":
        raise RuntimeError(f"APP error: {rep}")

    data = decrypt_obj(rep["data"], Kc_v)
    return data

# --- Main ---
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--as-host", default="127.0.0.1")
    ap.add_argument("--as-port", type=int, default=6000)
    ap.add_argument("--tgs-host", default=TGS_HOST)
    ap.add_argument("--tgs-port", type=int, default=TGS_PORT)
    ap.add_argument("--service", required=True, help="Service principal to access")
    ap.add_argument("--message", default="Hello from client!")
    ap.add_argument("--initial-wall-clock", type=int, required=False)
    args = ap.parse_args()

    # Initial epoch
    if args.initial_wall_clock is None:
        try:
            with open("epoch.txt", "r") as f:
                args.initial_wall_clock = int(f.read().strip())
            log(f"[INFO] Loaded initial wall clock from epoch.txt: {args.initial_wall_clock}")
        except FileNotFoundError:
            raise FileNotFoundError("epoch.txt not found. Please run time_synchronize.py first")
        except ValueError:
            raise ValueError("Invalid value in epoch.txt")

    # 1) AS exchange
    k_c_tgs, tgt, tgt_life, ts2 = as_req(
        args.as_host, args.as_port, CLIENT_NAME, CLIENT_PASSWORD, TGS_ID, CLIENT_AD, args.initial_wall_clock
    )
    log(f"[Client:{CLIENT_NAME}] Got TGT (life={tgt_life}m)")

    # 2) TGS exchange
    server_host = "127.0.0.1"  # for testing, can be configured
    k_c_s, ticket_s, lifetime4 ,ts4 = tgs_req(
        args.tgs_host, args.tgs_port, args.service, tgt, k_c_tgs, CLIENT_NAME, CLIENT_AD, args.initial_wall_clock
    )
    log(f"[Client:{CLIENT_NAME}] Got ServiceTicket for {args.service}, lifetime: {lifetime4}")

    # 3) App request
    # Replace with actual service port mapping or config
    SERVICE_PORT = int(os.getenv(f"{args.service.upper()}_PORT", 7000))
    rep = app_req(server_host, SERVICE_PORT, ticket_s, k_c_s, CLIENT_NAME, CLIENT_AD, args.message, args.initial_wall_clock)
    log(f"[Client:{CLIENT_NAME}] Server reply: {rep['ack']}")

    # 4) Reuse ticket within lifetime
    log(f"[Client:{CLIENT_NAME}] Reusing ServiceTicket within lifetime...")
    rep2 = app_req(server_host, SERVICE_PORT, ticket_s, k_c_s, CLIENT_NAME, CLIENT_AD, args.message + " (second call)", args.initial_wall_clock)
    log(f"[Client:{CLIENT_NAME}] Second reply: {rep2['ack']}")

if __name__ == "__main__":
    main()
