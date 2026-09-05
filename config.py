import os
from dotenv import load_dotenv

load_dotenv(Path.home() / ".clapi" / ".env") #find .env and load

#assign the tokens we retrieved from the .env file to a variable
API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not API_TOKEN or not ZONE_ID:
    print("[!] Error: Please define the CLOUDFLARE_API_TOKEN and CLODFLARE_ZONE_ID values in your .env file.")
    exit(1)
