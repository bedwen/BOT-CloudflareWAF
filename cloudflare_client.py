import os
from http.client import responses
from tokenize import endpats

import requests
from dotenv import load_dotenv
from config import API_TOKEN, ZONE_ID

load_dotenv()

API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")


class CloudflareClient:
    def __init__(self, api_token, zone_id):
        self.api_token = api_token
        self.zone_id = zone_id

        #cloudflare base api url
        self.base_url = f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}"

        #authorization header for identify
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }


    def get_waf_rules(self,rule_type):
        #retrieves the existing firewall rules for the specified zone.
        #endpoint for rules

        #Custom Rules
        if rule_type == '1':
            endpoint = f"{self.base_url}/rulesets/phases/http_request_firewall_custom/entrypoint"

            try:
                #sending a GET request to the API
                response = requests.get(endpoint, headers=self.headers)

                if response.status_code == 200:
                    data = response.json()
                    # Rulesets API fixed: result -> rules
                    result = data.get("result", {})
                    if isinstance(result, dict):
                        return result.get("rules", [])
                    return []
                else:
                    print(f"API Error: {response.status_code} - {response.text}")
                    return []
            except requests.exceptions.RequestException as e:
                print(f"Connection Error: {e}")
                return []

        #Rate-Limiting Rules
        elif rule_type == '2':
            endpoint = f"{self.base_url}/rulesets/phases/http_ratelimit/entrypoint"
            try:
                # sending a GET request to the API
                response = requests.get(endpoint, headers=self.headers)

                if response.status_code == 200:
                    data = response.json()

                    result = data.get("result", {})
                    if isinstance(result, dict):
                        return result.get("rules", [])
                    return []
                else:
                    print(f"API Error: {response.status_code} - {response.text}")
                    return []
            except requests.exceptions.RequestException as e:
                print(f"Connection Error: {e}")
                return []

        #IP Block Rules
        elif rule_type == '3':
            endpoint = f"{self.base_url}/firewall/access_rules/rules"
            try:
                # sending a GET request to the API
                response = requests.get(endpoint, headers=self.headers)

                if response.status_code == 200:
                    data = response.json()
                    # IP Access Rules doğrudan result içinde liste döndürür
                    result = data.get("result", [])
                    return result if isinstance(result, list) else []
                else:
                    print(f"API Error: {response.status_code} - {response.text}")
                    return []
            except requests.exceptions.RequestException as e:
                print(f"Connection Error: {e}")
                return []


def block_ip(self, ip_address, description="Target IP blocked by CLDBOT"):
        endpoint = f"{self.base_url}/firewall/access_rules/rules"
        #the content of the rule we will send to cloudflare (payload)
        payload = {
            "mode": "block",
            "configuration": {
                "target": "ip",
                "value": ip_address
            },
            "notes": description
        }

        try:
            #this request is POST because we are sending data.
            response = requests.post(endpoint, headers=self.headers, json=payload)

            if response.status_code == 200:
                print(f"[✔] {ip_address} The IP address has been successfully blocked.")
                return True
            else:
                print(f"[X] Rule Addition Error: {response.status_code} - {response.text}")
                return False

        except requests.exceptions.RequestException as e:
            print(f"[X] Connection Error: {e}")
            return False


def delete_rule(self, rule_id, rule_type):
    if rule_type == '1':
        if not hasattr(self, 'custom_ruleset_id') or not self.custom_ruleset_id:
            print("[X] Error: Ruleset ID not found. Please list the rules before deleting them.")
            return False
        endpoint = f"{self.base_url}/rulesets/{self.custom_ruleset_id}/rules/{rule_id}"

    elif rule_type == '2':
        if not hasattr(self, 'ratelimit_ruleset_id') or not self.ratelimit_ruleset_id:
            print("[X] Error: Ruleset ID not found. Please list the rules before deleting them.")
            return False
        endpoint = f"{self.base_url}/rulesets/{self.ratelimit_ruleset_id}/rules/{rule_id}"

    elif rule_type == '3':
        endpoint = f"{self.base_url}/firewall/access_rules/rules/{rule_id}"

    else:
        print("[X] Invalid rule type!")
        return False

    try:
        response = requests.delete(endpoint, headers=self.headers)

        if response.status_code == 200:
            print(f"[✔] Success! Rule (ID: ({rule_id}) delet.d")
            return True
        else:
            print(f"[X] Rule Deleting Error: {response.status_code} - {response.text}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"[X] Connection Error: {e}")
        return False
    
