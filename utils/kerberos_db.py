from pymongo import MongoClient
from datetime import datetime,timezone

# --- DB Connection ---
client = MongoClient("mongodb://localhost:27017/")
db = client["kerberos_db"]

# --- Clients Collection ---
def get_client(name: str):
    return db.clients.find_one({"name": name})

def add_client(name: str, password: str):
    db.clients.insert_one({
        "name": name,             # IDc
        "password": password,     # long-term key (hashed ideally)
        "created_at": datetime.now(timezone.utc)
    })


# --- Servers Collection ---
def get_server(name: str):
    return db.servers.find_one({"name": name})

def add_server(name: str, key: str, port: int):
    db.servers.insert_one({
        "name": name,            # IDv
        "password": key,         # Kv
        "port": port,
        "created_at": datetime.now(timezone.utc)
    })


# --- TGS Collection ---
def get_tgs():
    return db.tgs.find_one({})

def get_tgs_by_id(idtgs: str):
    return db.tgs.find_one({"idtgs": idtgs})

def add_tgs(idtgs: str, ktgs: str, lifetime_tgt: int, lifetime_st: int):
    db.tgs.insert_one({
        "idtgs": idtgs,                   # e.g. "tgs1"
        "ktgs": ktgs,                     # shared secret key
        "default_lifetime_tgt": lifetime_tgt,
        "default_lifetime_st": lifetime_st,
        "created_at": datetime.now(timezone.utc)
    })

