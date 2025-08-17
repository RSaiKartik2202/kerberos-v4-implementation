
# Kerberos Authentication System — Socket Simulation

This is a minimal end‑to‑end simulation of the Kerberos v4 flow using Python sockets.
It includes:
- **KDC** with **AS** (port `6000`) and **TGS** (port `6001`)
- **Two services/servers**: `filesvc` (port `7000`) and `chatsvc` (port `7001`)
- **Two clients**: `alice` and `bob`
- A shared **Auth DB** storing `<clientName, passwd>` and `<serverName:port, passwd>`

> Encryption here is a deliberately simple XOR keystream for teaching purposes,
> derived from SHA‑256; it’s **not secure**. Use it only for learning/demonstration.

## Time & lifetime model
All processes accept `--initial-wall-clock`, a UNIX epoch **shared by all** (e.g., `int(time.time())` when you start the demo).
The current **Kerberos timestamp** is computed as minutes since that epoch. Lifetimes:
- **TGT**: 10 minutes (default)
- **Service Ticket**: 5 minutes (default)

## Files
- `common.py` — helpers for toy crypto, JSON framing, and time
- `kdc.py` — runs **AS** on `6000` and **TGS** on `6001`
- `server.py` — run any service listed in `auth_db.json`
- `client.py` — performs AS, TGS, and application requests
- `auth_db.json` — authentication database
- `run_demo.sh` / `run_demo.bat` — quickstart scripts (optional)

## Quickstart (4 terminals)
All commands run in this folder. Use the **same** `EPOCH=$(python -c "import time; print(int(time.time()))")` for all.

### 1) Start KDC (AS+TGS)
```bash
python kdc.py --initial-wall-clock $EPOCH
```

### 2) Start Server 1 (filesvc)
```bash
python server.py --name filesvc --initial-wall-clock $EPOCH
```

### 3) Start Server 2 (chatsvc)
```bash
python server.py --name chatsvc --initial-wall-clock $EPOCH
```

### 4) Run two clients
```bash
python client.py --client alice --service filesvc --message "hi file" --initial-wall-clock $EPOCH
python client.py --client bob   --service chatsvc --message "yo chat" --initial-wall-clock $EPOCH
```

You should see:
- AS issues TGTs to clients
- TGS issues service tickets
- Servers validate tickets, decrypt messages, and send encrypted ACKs
- Each client **reuses** the service ticket once within lifetime

## Demonstrating expiry
Wait >5 minutes (service ticket lifetime), then run the client **again** without re‑getting a new ticket (modify client to skip TGS) to observe an **expired** ticket error. Or simply re-run `client.py` after >10 minutes to see TGT changes.

## Extending / Testing Notes
- Add more clients/servers by editing `auth_db.json`.
- Change lifetimes by adjusting `default_lifetime_tgt` / `default_lifetime_st` in `auth_db.json`.
- All messages are framed JSON (`len|json`) over TCP sockets.
- The **authenticator** includes `{client, ts}` encrypted with the corresponding session key.
- The **ticket** contains `{client, session_key, ts, lifetime}` encrypted with the service’s secret.

## Mapping to Kerberos 4 (conceptual)
- `AS_REQ/AS_REP` ↔ Client ↔ AS for TGT
- `TGS_REQ/TGS_REP` ↔ Client ↔ TGS for Service Ticket
- `APP_REQ/APP_REP` ↔ Client ↔ Service using Service Ticket
- Timestamps measured in minutes since a shared start time; lifetimes enforced at TGS/Service.

## Security disclaimer
This is an **educational** emulation. Real Kerberos uses strong crypto (e.g., AES), secure replay caches, clock skew handling, and more rigorous validation.
