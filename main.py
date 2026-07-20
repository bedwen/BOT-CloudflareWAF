import os
from dotenv import load_dotenv
from cloudflare_client import CloudflareClient
from config import API_TOKEN, ZONE_ID

#load .env settings
load_dotenv()

API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")

def waf_rules_list(cf_client):
    #WAF rules
    rules = cf_client.get_waf_rules()

    if rules:
        print(f"\n[✔] Success. {len(rules)} Rules \n")
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


def block_ip(cf_client):
    #take ip address from user and block.
    print("\n"+"-"*50)
    print("--- IP BLOCK ---")

    target_ip = input("Enter the IP address to block: ")
    if not target_ip.strip():
        print("[!] Error: The IP address cannot be left blank. The transaction was canceled.")
        return

    description = input("Enter a description/note (Press Enter to leave blank): ")
    if not description.strip():
        description = "The target IP has been blocked via CLDBOT."

    #try to add rule
    print(f"\n [/] A rule is being created for the address {target_ip}")
    block_check = cf_client.block.ip(target_ip(), description)

    if block_ip():
        print(f"[✔] System: {target_ip} The IP address has been successfully added to the WAF rules.")
    else:
        print(f"[X] System: {target_ip} The IP address could not be blocked")


def main():
    if not API_TOKEN or not ZONE_ID:
        print("[!] Error: “Please define the CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID values in your .env file.")
        return

    print("""
 ██████╗██╗     ██████╗ ██████╗  ██████╗ ████████╗
 ██╔════╝██║     ██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝
 ██║     ██║     ██║  ██║██████╔╝██║   ██║   ██║   
 ██║     ██║     ██║  ██║██╔══██╗██║   ██║   ██║   
 ╚██████╗███████╗██████╔╝██████╔╝╚██████╔╝   ██║   
  ╚═════╝╚══════╝╚═════╝ ╚═════╝  ╚═════╝    ╚═╝""")
    print("[/] CLDBOT Starting...")
    cf_client = CloudflareClient(API_TOKEN, ZONE_ID)

    while True:
        print("\n" + "="*50)
        print("CLDBOT MENU")
        print("="*50+"\n")
        print("[1] List Rules\n"
              "[2] Block IP Address\n"
              "[0] Exit")
        print("\n" + "="*50)

        choose = input("[>] Please select an operation: ")

        if choose == "1":
            waf_rules_list(cf_client)
        elif choose == "2":
            block_ip(cf_client)
        elif choose == "0":
            print("\n[/] Exiting...")
        else:
            print("\n[!] Error: Invalid selection. Please select one of the options provided.")


if __name__ == "__main__":
    main()