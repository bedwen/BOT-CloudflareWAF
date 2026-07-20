import os
from dotenv import load_dotenv
from cloudflare_client import CloudflareClient
from config import API_TOKEN, ZONE_ID

#load .env settings
load_dotenv()

API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")

def main():
    if not API_TOKEN or not ZONE_ID:
        print("Error: Please define the CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID values in your .env file.")
        return

    print("Cloudflare WAF Bot Starting...\n")

    #API Client
    cf_client = CloudflareClient(API_TOKEN, ZONE_ID)

    #WAF rules
    rules = cf_client.get_waf_rules()
    if rules:
        print(f"{len(rules)} Rules")
        print("-"*50)
        for index, rule in enumerate(rules, start=1):
            rule_id = rule.get("id", "No ID")
            description = rule.get("description", "No Description")
            action = rule.get("action", "No Action")

            print(f"Rule #{index}")
            print(f"ID          : {rule_id}")
            print(f"Action      : {action.upper()}")
            print(f"Description : {description}")
            print("-"*50)

    elif rules is not None and len(rules) == 0:
        print("\n Connection was established to the API, but no WAF rules were found in this zone.")
    else:
        print("\n No rule was found, or an API connection error occurred.")

if __name__ == "__main__":
    main()