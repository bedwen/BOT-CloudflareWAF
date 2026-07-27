from idlelib.rpc import response_queue
from ipaddress import ip_address

import requests

class IPAccessManager:
    #rule type 3 - handless only ip access rule

    def __init__(self, api_client):
        self.api = api_client
        self.endpoint = f"{self.api.base_url}/firewall/access_rules/rules"

    def get_rules(self):
        try:
            #sending a GET request to the API
            response = requests.get(self.endpoint, headers=self.api.headers)
            if response.status_code == 200:
                data = response.json()
                #IP Access -> result list
                result = data.get("result", [])
                return result if isinstance(result, list) else []
            else:
                print(f"API Error: {response.status_code} - {response.text}")
                return []
        except requests.exceptions.RequestException as e:
            print(f"Connection Error: {e}")
            return []

    def block_ip(self, ip_address, description="Target IP blocked by CLDBOT"):
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
            response = requests.post(self.endpoint, headers=self.api.headers, json=payload)
            if response.status_code == 200:
                print(f"[✔] {ip_address} The IP address has been successfully blocked.")
                return True

            else:
                if "10009" in response.text or "81057" in response.text or "duplicate" in response.text.lower():
                    print(f"[-] {ip_address} is already blocked. Skipping.")
                    return True

                print(f"[X] Rule Addition Error: {response.status_code} - {response.text}")
                return False

        except requests.exceptions.RequestException as e:
            print(f"[X] Connection Error: {e}")
            return False

    def delete_rule(self, rule_id):
        url = f"{self.endpoint}/{rule_id}"
        try:
            response = requests.delete(url, headers=self.api.headers)
            if response.status_code == 200:
                print(f"[✔] Success! Rule (ID: ({rule_id}) deleted")
                return True
            else:
                print(f"[X] Rule Deleting Error: {response.status_code} - {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"[X] Connection Error: {e}")
            return False

    def unblock_ip(self, ip_address):
        print(f"[/] Searching for IP {ip_address} in your Cloudflare rules...")

        params = {
            "configuration.value": ip_address
        }

        try:
            response = requests.get(self.endpoint, headers=self.api.headers, params=params)

            if response.status_code == 200:
                data = response.json()
                result = data.get("result", [])

                if not result:
                    print(f"[-] The IP {ip_address} is not currently blocked in IP Access Rules.")
                    print(f"[i] Note: If it is blocked via WAF Custom Rules, this menu cannot see it.")
                    return False

                success = False
                for rule in result:
                    rule_id = rule.get("id")
                    print(f"[/] Match found! Deleting rule (ID: {rule_id}) for {ip_address}...")


                    if self.delete_rule(rule_id):
                        success = True

                return success

            else:
                print(f"[X] API Error: {response.status_code} - {response.text}")
                return False

        except requests.exceptions.RequestException as e:
            print(f"[X] Connection Error: {e}")
            return False