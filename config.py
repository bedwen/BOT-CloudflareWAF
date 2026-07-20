import os
from dotenv import load_dotenv

load_dotenv() #find .env and load

#assign the tokens we retrieved from the .env file to a variable
API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")

