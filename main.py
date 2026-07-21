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


def block_ip_main(cf_client):
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
    block_check = cf_client.block_ip(target_ip, description)

    if block_check:
        print(f"[✔] System: {target_ip} The IP address has been successfully added to the WAF rules.")
    else:
        print(f"[X] System: {target_ip} The IP address could not be blocked")

def delete_rule_main(cf_client):
    print("\n"+"-"*50)
    print("--- DELETE RULE ---")

    #first list rule
    rule_list = waf_rules_list(cf_client)

    if not rule_list:
        print("No rule was found to delete. Returning to the main menu.")
        return

    choose_rule = input(f"\nEnter the sequence number of the rule you want to delete (1-{len(rule_list)}) or 'q' for cancel operation.")

    if choose_rule.lower() == 'q':
        print("[-] The operation was canceled.")
        return

    try:
        index = int(choose_rule) - 1 #-1 for index calculating.
        if 0 <= index < len(rule_list): #index range
            selected_rule = rule_list[index]
            rule_id = selected_rule.get("id")
            target_rule = selected_rule.get("configuration", {}).get("value", "Unknown Target")

            approval = input(f"[!] WARN: Rule {choose_rule} containing the target ‘{target_rule}’ will be deleted. Do you confirm? (Y/N): ")
            if approval.lower() == 'y':
                print(f"\n[/] Rule is deleting...")
                cf_client.delete_rule(rule_id)
            else:
                print("[-] The operation was canceled")
        else:
            print(("[X] Error: The number you entered is not on the list."))
    except ValueError:
        print("[X] Error: Please enter a valid number.")
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
  ╚═════╝╚══════╝╚═════╝ ╚═════╝  ╚═════╝    ╚═╝ v0.1""")
    print("[/] CLDBOT Starting...")
    cf_client = CloudflareClient(API_TOKEN, ZONE_ID)

    while True:
        print("\n" + "="*50)
        print("CLDBOT MENU")
        print("="*50+"\n")
        print("[1] List Rules\n"
              "[2] Block IP Address\n"
              "[3] Delete Rule\n"
              "[0] Exit")
        print("\n" + "="*50)

        choose = input("[>] Please select an operation: ")

        if choose == "1":
            waf_rules_list(cf_client)
        elif choose == "2":
            block_ip_main(cf_client)
        elif choose == "3":
            delete_rule_main(cf_client)
        elif choose == "0":
            print("\n[/] Exiting...")
            break
        else:
            print("\n[!] Error: Invalid selection. Please select one of the options provided.")


if __name__ == "__main__":
    main()