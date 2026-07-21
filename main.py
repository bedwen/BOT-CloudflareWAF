import os
from asyncio.staggered import staggered_race
from ipaddress import ip_address

from dotenv import load_dotenv
from requests.packages import target

from cloudflare_client import CloudflareClient
from config import API_TOKEN, ZONE_ID

#load .env settings
load_dotenv()

API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")



def waf_rules_list(cf_client):
    #WAF rules
    print("\n"+"-"*50)
    print("[1] Custom Rules\n[2] Rate-Limiting Rules\n [3] IP Block Rules")
    rule_type = input("[>] Select the rule you want to list: ")
    rule_list = cf_client.get_waf_rules(rule_type)

    if not rule_list:
        print("The rule could not be found or listed.")
        return



    for index, rule in enumerate(rule_list, start=1):
        if rule_type == '3':
            #ip access rules format, it is different from the other rules
            target = rule.get("configuration", {}).get("value", "Unknown")
            mode = rule.get("mode", "Unknown")
            notes = rule.get("notes","No Description")
            print(f"[{index}] IP: {target:<15} | Mod: {mode:<8} | Note: {notes}")
        else:
            #for custom and rate-limit format (they have extra description and action)
            description = rule.get("description","No Description")
            action = rule.get("action","Unknown")
            print(f"[{index}] Rule: {description:<25} | Action: {action}")
    print("="*60)


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
    print("[1] Custom Rules\n[2] Rate-Limiting Rules\n [3] IP Block Rules")
    rule_type = input("[>] Select the rule you want to delete it: ")

    #show rules before delete
    rule_list = cf_client.get_waf_rules((rule_type))

    if not rule_list:
        print("No rule was found to delete. Returning to the main menu.")
        return

    print("\n"+"="*50)
    print("Rules:")
    print("\n"+"="*50)

    for index, rule in enumerate(rule_list, start=1):
        if rule_type == '3':
            target = rule.get("configuration",{}).get("value","Unknown")
            print(f"[{index}] Target IP: {target}")
        else:
            description = rule.get("description","No Description")
            print(f"[{index}] Rule Name: {description}")
    print("="*50)

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
        zone_id = ZONE_ID
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