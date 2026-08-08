import os.path
from unittest.result import failfast

from requests.packages import target

from modules.threat_intel import ThreatIntelManager
from utils.ip_validation import is_valid_ip
from utils.logger import log, Colors

from config import API_TOKEN, ZONE_ID, ABUSE_API_KEY
from core.api_client import CloudflareAPIClient
from modules.ip_access import IPAccessManager
from modules.waf_rules import WafRulesManager
from utils.ip_validation import is_valid_ip
from modules.zone_settings import ZoneSettingsManager
from modules.firewall_logs import FirewallLogsManager


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
        log.error("Invalid selection.")
        return

    if not rule_list:
        log.info("The rule could not be found or listed.")
        return

    for index, rule in enumerate(rule_list, start=1):
        if rule_type == '3':
            #ip access rules format, it is different from the other rules
            target = rule.get("configuration", {}).get("value", "Unknown")
            mode = rule.get("mode", "Unknown")
            notes = rule.get("notes", "No Description")
            log.info(f"[{index}] IP: {target:<15} | Mode: {mode:<8} | Note: {notes}")
        else:
            #for custom and rate-limit format (they have extra description and action layer)
            description = rule.get("description","No Description")
            action = rule.get("action","Unknown")
            log.info(f"[{index}] Rule: {description:<25} | Action: {action}")
    print("="*50)

def block_ip_main(ip_mgr):
    #take ip address from user and block.
    log.info("--- IP BLOCK ---")

    while True:
        target_ip = input("[>]Enter the IP address to block: ")
        if target_ip.lower() == 'q':
            log.info("The operation was canceled.")
            return

        if not target_ip:
            log.warning("Error: The IP address cannot be left blank.")
            continue

        #ip validation
        if not is_valid_ip(target_ip):
            log.error(f"Error: '{target_ip}' is not a valid IP address. Please try again.")
            continue

        break

    description = input("Enter a description/note (Press Enter to leave blank): ")
    if not description.strip():
        description = "The target IP has been blocked via CLDBOT."

    ip_mgr.block_ip(target_ip, description)

def bulk_block_main(ip_mgr):
    log.info("--- BULK IP BLOCK ---")

    file_path = input("[>] Enter the file name containing IP addresses (e.g., ips.txt) or 'q' to cancel: ").strip()

    if file_path.lower() == 'q':
        log.info("The operation was canceled.")
        return

    #check file
    if not os.path.isfile(file_path):
        log.error(f"Error: The file '{file_path}' was not found in the directory.")
        return

    description = input("[>] Enter a common description for these IPs (Press Enter for defaul): ").strip()
    if not description:
        description = "Bulk blocked via CLDBOT"

    log.info(f"\nReading '{file_path}' and processing IPs...")

    success_count = 0
    fail_count = 0
    invalid_count = 0

    try:
        #open file with write mode
        with open(file_path, 'r') as file:
            lines = [line.strip() for line in file.readlines() if line.strip()]
    except Exception as e:
        log.error(f"Error reading file: {e}")
        return

    if not lines:
        log.info("The file is empty.")
        return

    for line in lines:
        ip = line.strip()

        if not ip:
            continue

        if not is_valid_ip(ip):
            log.warning(f"Invalid IP format skipped: {ip}")
            invalid_count += 1
            continue

        block_check = ip_mgr.block_ip(ip, description)
        if block_check:
            success_count += 1
        else:
            fail_count += 1

def bulk_unblock_main(ip_mgr):
    log.info("--- BULK IP UNBLOCK ---")

    file_path = input("[>] Enter the file name containing IP addresses (e.g., ips.txt) or 'q' to cancel: ")

    if file_path.lower() == 'q':
        log.info("The operation was canceled.")
        return

    if not os.path.isfile(file_path):
        log.error(f"Error: The file '{file_path}' was not found in the directory.")
        return

    log.info(f"\nReading '{file_path}' and processing IPs for unblocking...")

    success_count = 0
    fail_count = 0
    invalid_count = 0

    try:
        with open(file_path, 'r') as file:
            lines = [line.strip() for line in file.readlines() if line.strip()]
    except Exception as e:
        log.error(f"Error reading file: {e}")
        return

    if not lines:
        log.info("The file is empty.")
        return

    for line in lines:
        ip = line.strip()

        if not ip:
            continue

        if not is_valid_ip(ip):
            log.warning(f"Invalid IP format skipped: {ip}")
            invalid_count += 1
            continue

        unblock_check = ip_mgr.unblock_ip(ip)
        if unblock_check:
            success_count += 1
        else:
            fail_count += 1

    log.info(f"Bulk Unblock Process Completed! Succes: {success_count}, Failed: {fail_count}, Invalid: {invalid_count}")




def delete_rule_main(ip_mgr, waf_mgr):
    log.info("--- DELETE RULE ---")
    print("[1] Custom Rules\n[2] Rate-Limiitng Rules\n[3] IP Block Rules")
    rule_type = input("[>] Select the rule you want to delete it: ")

    #show rules before delete
    if rule_type == '3':
        rule_list = ip_mgr.get_rules()
    elif rule_type in ['1','2']:
        rule_list = waf_mgr.get_rules(rule_type)
    else:
        log.error("Invalid selection.")
        return

    if not rule_list:
        log.info("No rule was found to delete. Returning to the main menu.")
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

    choose_rule = input(f"\n[>] Enter the sequence number of the rule you want to delete (1-{len(rule_list)}) or 'q' for cancel operation: ")

    if choose_rule.lower() == 'q':
        log.info("The operation was canceled.")
        return

    try:
        index = int(choose_rule) - 1 #-1 for index calculating.
        if 0 <= index < len(rule_list): #index range
            selected_rule = rule_list[index]
            rule_id = selected_rule.get("id")
            target_rule = selected_rule.get("configuration", {}).get("value","Unknown Target")

            approval = input(log.warning("WARN: Rule {choose_rule} containing the target '{target_rule}' will be deleted. Do you confirm? (Y/N): "))
            if approval.lower() == 'y':
                log.info(f"\nRule is deleting...")

                if rule_type == '3':
                    ip_mgr.delete_rule(rule_id)
                else:
                    waf_mgr.delete_rule(rule_id, rule_type)
            else:
                log.info("The operation was canceled.")
        else:
            log.error("Error: The number you entered is not on the list.")
    except ValueError:
        log.error("Error: Please enter a valid number.")

def unblock_ip_main(ip_mgr):
    log.info("--- UNBLOCK BY IP ---")

    while True:
        target_ip = input("[>] Enter the IP address you want to unblock (or 'q' to cancel): ").strip()

        if target_ip.lower() == 'q':
            log.info("The operation was canceled.")
            return

        if not target_ip:
            log.error("Error: The IP address cannot be left blank.")
            continue

        if not is_valid_ip(target_ip):
            log.error(f"Error: '{target_ip}' is not a valid IP address. Please try again.")
            continue

        break

    ip_mgr.unblock_ip(target_ip)


def check_ip_reputation_main(threat_mgr):
    log.info("--- THREAT INTELLIGENCE (AbuseIPDB) ---")
    while True:
        target_ip = input("[>] Enter the IP address to check (or 'q' to cancel): ").strip()

        if target_ip.lower() == 'q':
            log.info("The operation was canceled.")
            return

        if not target_ip:
            log.warning("Error: The IP address cannot be left blank.")
            continue

        if not is_valid_ip(target_ip):
            log.error(f"Error: '{target_ip}' is not a valid IP address. Pleaase try again.")
            continue

        break

    threat_mgr.check_ip_reputation(target_ip)

def security_level_menu(zone_mgr):
    while True:
        log.info("--- SECURITY LEVEL & UNDER ATTACK MODE ---")
        print("[1] Check Current Security Level\n"
              "[2] Set to LOW\n"
              "[3] Set to MEDIUM - Disable Under Attack Mode\n"
              "[4] Set to HIGH\n"
              "[5] Enable Under Attack Mode\n"
              "[9] Exit")

        choice = input("[>] Please select an operation: ").strip()

        if choice == '1':
            zone_mgr.get_security_level()
        elif choice == '2':
            zone_mgr.set_security_level("low")
        elif choice == '3':
            zone_mgr.set_security_level("medium")
        elif choice == '4':
            zone_mgr.set_security_level("high")
        elif choice == '5':
            log.warning("WARN: This will present a JS challange to ALL visitors.")
            confirm = input("Are you sure? (y/n): ").strip().lower()
            if confirm == 'y':
                zone_mgr.set_security_level("under_attack")
            else:
                log.info("Operation canceled.")
        elif choice == '9':
            break
        else:
            log.error("Invalid selection. Please select one of the options provided.")

def firewall_logs_main(fw_logs_mgr):
    log.info("--- LIVE LOGS ---")
    events = fw_logs_mgr.get_recent_events(limit=15)

    if not events:
        return

    print(f"\n{'-'*90}")
    print(f"{'TIME (UTC)':<20} | {'IP ADDRESS':>16} | {'COUNTRY':<15} | {'ACTION':<15} | {'SOURCE'}")
    print(f"{'-'*90}")

    for ev in events:
        dt_raw = ev.get('datetime', '')
        dt_clean = dt_raw.replace('T', ' ').replace('Z','')

        ip = ev.get('clientIP', 'Unknown')
        country = ev.get('clientCountryName','Unknown')
        action = ev.get('action', 'Unknown').upper()
        source = ev.get('soruce','Unknown')

        if action == 'BLOCK' or action == 'DROP':
            action_str = f"{Colors.RED}{action:<15}{Colors.RESET}"
        elif 'CHALLANGE' in action:
            action_str = f"{Colors.YELLOW}{action:<15}{Colors.RESET}"
        else:
            action_str = f"{Colors.CYAN}{action:<15}{Colors.RESET}"

            print(f"{dt_clean:<20} | {ip:<16} | {country:<15} | {action_str} | {source}")

        print(f"{'-'*90}\n")


def main():
    print("""
   █████████  █████         █████████   ███████████  █████
  ███░░░░░███░░███         ███░░░░░███ ░░███░░░░░███░░███ 
 ███     ░░░  ░███        ░███    ░███  ░███    ░███ ░███ 
░███          ░███        ░███████████  ░██████████  ░███ 
░███          ░███        ░███░░░░░███  ░███░░░░░░   ░███ 
░░███     ███ ░███      █ ░███    ░███  ░███         ░███ 
 ░░█████████  ███████████ █████   █████ █████        █████
  ░░░░░░░░░  ░░░░░░░░░░░ ░░░░░   ░░░░░ ░░░░░        ░░░░░  v1.4.0""")
    print("[/] CLDBOT Starting...")

    api_client = CloudflareAPIClient(API_TOKEN, ZONE_ID)

    ip_mgr = IPAccessManager(api_client)
    waf_mgr = WafRulesManager(api_client)
    threat_mgr = ThreatIntelManager(ABUSE_API_KEY)
    zone_mgr = ZoneSettingsManager(api_client)
    fw_logs_mgr = FirewallLogsManager(api_client)


    while True:
        print("\n"+"="*50)
        print("CLDBOT MENU")
        print("="*50+"\n")


        log.info(f"24H Requests: {zone_mgr.get_zone_analytics()}")
        zone_mgr.get_security_level()
        print("")

        print("[0] Under Attack Mode\n"
              "[1] List Rules\n"
              "[2] Delete Rule\n"
              "[3] Block IP Address\n"
              "[4] Bulk Block IPs (from file)\n"
              "[5] Bulk Unblock IPs (from file)\n"
              "[6] Unblock IP (Fast)\n"
              "[7] IP Threat Intelligence\n"
              "[8] Live Logs\n"
              "[9] Exit")
        print("\n"+"="*50)

        choose = input("[>] Please select an operation: ")

        if choose == "0":
            security_level_menu(zone_mgr)
        elif choose == "1":
            waf_rule_list(ip_mgr,waf_mgr)
        elif choose == "2":
            delete_rule_main(ip_mgr,waf_mgr)
        elif choose == "3":
            block_ip_main(ip_mgr)
        elif choose == "4":
            bulk_block_main(ip_mgr)
        elif choose == "5":
            bulk_unblock_main(ip_mgr)
        elif choose == "6":
            unblock_ip_main(ip_mgr)
        elif choose == "7":
            check_ip_reputation_main(threat_mgr)
        elif choose == "8":
            firewall_logs_main(fw_logs_mgr)
        elif choose == "9":
            print("\n[/] Exiting...")
            break
        else:
            print("\n[!] Error: Invalid selection. Please select one of the options provided.")

if __name__ == "__main__":
    main()