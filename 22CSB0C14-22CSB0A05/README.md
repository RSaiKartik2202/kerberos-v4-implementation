# Kerberos Authentication System — Socket Simulation with MongoDB

This is a minimal end‑to‑end simulation of the **Kerberos v4 flow** using Python sockets and MongoDB as the authentication database.

It includes:

- **KDC** with:
  - **AS** (port `6000`) and
  - **TGS** (port `6001`)
- **Two services/servers**:
  - `ftpServer` (port `7002`)
  - `mailServer` (port `7001`)
- **Two clients**: `Sai_Kartik` and `Karthikeya_Mittapalli`
- A shared **MongoDB Auth DB** storing:
  - `<clientName, password>`
  - `<serverName:port, password>`  

> Encryption here is a simplified DES-like scheme (for teaching purposes). **Not secure for production**.

---

## Time & lifetime model

- All processes accept `--initial-wall-clock`, a UNIX epoch **shared by all** (e.g., `int(time.time())`).
- The **Kerberos timestamp** is measured in **minutes since that epoch**.
- Lifetimes:
  - **TGT**: 10 minutes (default)
  - **Service Ticket**: 5 minutes (default)

---

## Files

- `utils/crypto.py` — DES-like encryption/decryption, JSON framing, and logging  
- `utils/kerberos_db.py` — MongoDB helper functions to add/get clients, servers, TGS
- `setup_db.py` — Script to initialize MongoDB with clients, servers, and TGS entries
- `time_synchronize.py` — writes a common UNIX epoch (`epoch.txt`) used for synchronized Kerberos timestamps.
- `kdc.py` — main KDC process, runs **AS** (port 6000) and **TGS** (port 6001)  
- `server.py` — run any service stored in MongoDB  (e.g., ftpServer, mailServer)
- `client.py` — performs AS, TGS, and application requests  with caching
- `.env` — client/server credentials and port mapping  
- `epoch.txt` — synchronized initial wall-clock  
- `kerberos_cache/` — Diskcache used by clients to store TGT/Service Tickets

---

### System Setup (4 terminals)

Run all commands in this folder.

### 1) Synchronize initial wall-clock
python time_synchronize.py

### 2) Initialize MongoDB authentication database
python setup_db.py


### 3) Start KDC (AS + TGS)
python kdc.py

### 4) Start Servers
python server.py --server ftpServer
python server.py --server mailServer

### 5) Run Clients
python client.py --service ftpServer --message "Hello file"
python client.py --service mailServer --message "Hey mail"


---

---

## Expected Behavior

- AS issues **Ticket-Granting Tickets (TGTs)** to clients.  
- TGS issues **Service Tickets (SGTs)** to clients for requested services.  
- Servers validate tickets, decrypt messages, and send **encrypted ACKs** (mutual auth via `TS5+1`).  
- The **client proactively checks ticket lifetimes** and **only contacts TGS/servers when needed**.

---

## Demonstrating Expiry (Client-Enforced)

- **Service Ticket lifetime (default 5 minutes):**  
  - If the client requests the same service **within 5 minutes**, it **reuses the cached SGT**.  
  - If the client requests **after 5 minutes**, the client detects SGT expiry **locally** and **obtains a fresh SGT from the TGS** (using the current TGT if still valid).

- **TGT lifetime (default 10 minutes):**  
  - If the client needs any service **after 10 minutes**, it detects TGT expiry and **first obtains a new TGT from the AS**, then requests a new SGT from the TGS.

> Note: Servers still verify lifetime for defense-in-depth, but the **client already avoids sending expired tickets** by checking its cache timestamps before making requests.

---

## Client-Side Caching (with Local Lifetime Checks)

- The client caches:
  - **TGT** after the AS exchange (`TS2`, `Lifetime2` stored alongside `Kc_tgs` and `Tickettgs`).  
  - **SGTs** per service after the TGS exchange (`TS4`, `Lifetime4` stored with `Kc_v` and `Ticketv`).  

- Before contacting TGS or a service:
  - The client **computes current Kerberos minutes** (since `epoch.txt`) and **compares** with cached `TS2 + Lifetime2` or `TS4 + Lifetime4`.  
  - If **still valid**, it **reuses** the cached ticket; if **expired**, it **refreshes** (TGT from AS, SGT from TGS).

- Mutual authentication: after `APP_REP`, the client **verifies** the server returned **`TS5+1`** (encrypted with `Kc_v`) to confirm the server also knows the session key.

---

## Protocol Flow (Mapping to Kerberos v4)

- **AS_REQ / AS_REP** → Client ↔ Authentication Server (obtain **TGT**, `Kc_tgs`).  
- **TGS_REQ / TGS_REP** → Client ↔ Ticket-Granting Server (obtain **SGT**, `Kc_v`).  
- **APP_REQ / APP_REP** → Client ↔ Application Server (present **Ticketv** + **Authenticatorc**; receive encrypted ACK with `TS5+1`).  

**Message Components**:
- **Ticketv (to service)**: `{IDc, Kc_v, ADc, IDv, TS4, Lifetime4}` encrypted with **server key** `Kv`.  
- **Tickettgs (to TGS)**: `{IDc, Kc_tgs, ADc, IDtgs, TS2, Lifetime2}` encrypted with **TGS key** `Ktgs`.  
- **Authenticator**: `{IDc, ADc, TS}` encrypted with the corresponding session key (`Kc_tgs` or `Kc_v`).  
- **Application Message/ACK**: encrypted with `Kc_v`.

---

## Security Disclaimer

This project is for **educational purposes only**:
- Uses simplified DES-like/stream-style toy crypto.  
- No replay cache, no clock skew tolerance, not production-grade.  
- **Do not use in real deployments.**

---
