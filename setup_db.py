from utils.kerberos_db import add_client, add_server, add_tgs

# Add clients
add_client("Karthikeya_Mittapalli", "22csb0c14_kincorrect")
add_client("Sai_Kartik", "22csb0a05_sk2202")

# Add servers
add_server("ftpServer", "fileserverkey", 7002)
add_server("mailServer", "mailserverkey", 7001)

# Add TGS
add_tgs("tgs1", "22csb0c14_22csb0a05_kerberos_v4_tgs", lifetime_tgt=10, lifetime_st=5)

print("Database initialized.")
