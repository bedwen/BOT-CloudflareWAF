import os.path
from unittest.result import failfast

from config import API_TOKEN, ZONE_ID
from core.api_client import CloudflareAPIClient
from modules.ip_access import IPAccessManager
from modules.waf_rules import WafRulesManager
from utils.ip_validation import is_valid_ip

def waf_rule_list(ip_mgr, waf_mgr):
    #WAF Rules
    print("="*50)
    print("[1] Custom Rules\n[2] Rate-Limiting Rules\n[3] IP Block Rules")
    rule_type = input("[>] Select the rule you want to list: ")

    #Get rules based on selection
    if rule_type == '3':
        rule_list = ip_mgr.get_rules()
    elif rule_type in ['1','2']:
        rule_list = waf_mgr.get_rules(rule_type)
    else:
        print("[X] Invalid selection.")
        return

    if not rule_list:
        print("The rule could not be found or listed.")
        return

    for index, rule in enumerate(rule_list, start=1):
        if rule_type == '3':
            #ip access rules format, it is different from the other rules
            target = rule.get("configuration", {}).get("value", "Unknown")
            mode = rule.get("mode", "Unknown")
            notes = rule.get("notes", "No Description")
            print(f"[{index}] IP: {target:<15} | Mode: {mode:<8} | Note: {notes}")
        else:
            #for custom and rate-limit format (they have extra description and action layer)
            description = rule.get("description","No Description")
            action = rule.get("action","Unknown")
            print(f"[{index}] Rule: {description:<25} | Action: {action}")
    print("="*50)

def block_ip_main(ip_mgr):
    #take ip address from user and block.
    print("--- IP BLOCK ---")

    while True:
        target_ip = input("Enter the IP address to block: ")
        if target_ip.lower() == 'q':
            print("[-] The operation was canceled.")
            return

        if not target_ip:
            print("[!] Error: The IP address cannot be left blank.")
            continue

        #ip validation
        if not is_valid_ip(target_ip):
            print(f"[!] Error: '{target_ip}' is not a valid IP address. Please try again.")
            continue

        break

    description = input("Enter a description/note (Press Enter to leave blank): ")
    if not description.strip():
        description = "The target IP has been blocked via CLDBOT."


def bulk_block_main(ip_mgr):
    print("--- BULK IP BLOCK ---")

    file_path = input("Enter the file name containing IP addresses (e.g., ips.txt) or 'q' to cancel: ").strip()

    if file_path.lower() == 'q':
        print("[-] The operation was canceled.")
        return

    #check file
    if not os.path.isfile(file_path):
        print(f"[!] Error: The file '{file_path}' was not found in the directory.")
        return

    description = input("Enter a common description for these IPs (Press Enter for defaul): ").strip()
    if not description:
        description = "Bulk blocked via CLDBOT"

    print(f"\n[/] Reading '{file_path}' and processing IPs...")

    success_count = 0
    fail_count = 0
    invalid_count = 0

    try:
        #open file with write mode
        with open(file_path, 'r') as file:
            for line in file:
                ip = line.strip()
                if not ip:
                    continue

                if not is_valid_ip(ip):
                    print(f"[!] Invalid IP format skipped: {ip}")
                    invalid_count += 1
                    continue

                block_check = ip_mgr.block_ip(ip, description)
                if block_check:
                    success_count += 1
                else:
                    fail_count += 1

    except Exception as e:
        print(f"[X] Error reading file: {e}")
        return

    print("--- BULK BLOCK SUMMARY ---")
    print(f"Total processed : {success_count + fail_count + invalid_count}\n"
          f"Successful      : {success_count}\n"
          f"Failed          : {fail_count}\n"
          f"Invalid format  : {invalid_count}\n"
          f"="*50)

def delete_rule_main(ip_mgr, waf_mgr):
    print("--- DELETE RULE ---")
    print("[1] Custom Rules\n[2] Rate-Limiitng Rules\n[3] IP Block Rules")
    rule_type = input("[>] Select the rule you want to delete it: ")

    #show rules before delete
    if rule_type == '3':
        rule_list = ip_mgr.get_rules()
    elif rule_type in ['1','2']:
        rule_list = waf_mgr.get_rules(rule_type)
    else:
        print("[X] Invalid selection.")
        return

    if not rule_list:
        print("[-] No rule was found to delete. Returning to the main menu.")
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

    choose_rule = input(f"\nEnter the sequence number of the rule you want to delete (1-{len(rule_list)}) or 'q' for cancel operation: ")

    if choose_rule.lower() == 'q':
        print("[-] The operation was canceled.")
        return

    try:
        index = int(choose_rule) - 1 #-1 for index calculating.
        if 0 <= index < len(rule_list): #index range
            selected_rule = rule_list[index]
            rule_id = selected_rule.get("id")
            target_rule = selected_rule.get("configuration", {}).get("value","Unknown Target")

            approval = input(f"[!] WARN: Rule {choose_rule} containing the target '{target_rule}' will be deleted. Do you confirm? (Y/N): ")
            if approval.lower() == 'y':
                print(f"\n[/] Rule is deleting...")

                if rule_type == '3':
                    ip_mgr.delete_rule(rule_id)
                else:
                    waf_mgr.delete_rule(rule_id, rule_type)
            else:
                print("[-] The operation was canceled.")
        else:
            print("[X] Error: The number you entered is not on the list.")
    except ValueError:
        print("[X] Error: Please enter a valid number.")

def main():
    print("""
     ██████╗ ██╗     ██████╗ ██████╗  ██████╗ ████████╗
     ██╔════╝██║     ██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝
     ██║     ██║     ██║  ██║██████╔╝██║   ██║   ██║   
     ██║     ██║     ██║  ██║██╔══██╗██║   ██║   ██║   
     ╚██████╗███████╗██████╔╝██████╔╝╚██████╔╝   ██║   
      ╚═════╝╚══════╝╚═════╝ ╚═════╝  ╚═════╝    ╚═╝ v1.0.2""")
    print("[/] CLDBOT Starting...")

    api_client = CloudflareAPIClient(API_TOKEN, ZONE_ID)

    ip_mgr = IPAccessManager(api_client)
    waf_mgr = WafRulesManager(api_client)

    while True:
        print("\n"+"="*50)
        print("CLDBOT MENU")
        print("="*50+"\n")
        print("[1] List Rules\n"
              "[2] Block IP Address\n"
              "[3] Delete Rule\n"
              "[4] Bulk Block IPs (from file)\n"
              "[0] Exit")
        print("\n"+"="*50)

        choose = input("[>] Please select an operation: ")

        if choose == "1":
            waf_rule_list(ip_mgr,waf_mgr)
        elif choose == "2":
            block_ip_main(ip_mgr)
        elif choose == "3":
            delete_rule_main(ip_mgr,waf_mgr)
        elif choose == "4":
            bulk_block_main(ip_mgr)
        elif choose == "0":
            print("\n[/] Exiting...")
            break
        else:
            print("\n[!] Error: Invalid selection. Please select one of the options provided.")

if __name__ == "__main__":
    main()