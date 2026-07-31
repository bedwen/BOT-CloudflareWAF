import requests
from utils.logger import log


class WafRulesManager:
    #handles only custom rules and rate-limiting rules
    #rule type 1 and 2

    def __init__(self, api_client):
        self.api = api_client
        self.custom_ruleset_id = None
        self.ratelimit_ruleset_id = None

    def get_rules(self, rule_type):
        #Custom Rules
        if rule_type == '1':
            endpoint = f"{self.api.base_url}/rulesets/phases/http_request_firewall_custom/entrypoint"

        #Rate-Limiting Rules
        elif rule_type == '2':
            endpoint = f"{self.api.base_url}/rulesets/phases/http_ratelimit/entrypoint"
        else:
            return []

        try:
            #sending a GET request to the API
            response = requests.get(endpoint, headers=self.api.headers)
            if response.status_code == 200:
                data = response.json()
                #Rulesets API fixed: result -> rules
                result = data.get("result", {})
                if isinstance(result, dict):
                    #Save the ruleset ID for future deletion
                    if rule_type == '1':
                        self.custom_ruleset_id = result.get("id")
                    elif rule_type == '2':
                        self.ratelimit_ruleset_id = result.get("id")
                    return result.get("rules", [])
                return []
            else:
                log.error(f"API Error: {response.status_code} - {response.text}")
                return []
        except requests.exceptions.RequestException as e:
            log.error(f"Connection Error: {e}")
            return []

    def delete_rule(self, rule_id, rule_type):
        if rule_type == '1':
            if not self.custom_ruleset_id:
                log.error("Error: Ruleset ID not found. Please list the rules before deleting them.")
                return False
            endpoint = f"{self.api.base_url}/rulesets/{self.custom_ruleset_id}/rules/{rule_id}"

        elif rule_type == '2':
            if not self.ratelimit_ruleset_id:
                log.error("Error: Ruleset ID not found. Please list the rules before deleting them.")
                return False
            endpoint = f"{self.api.base_url}/rulesets/{self.ratelimit_ruleset_id}/rules/{rule_id}"
        else:
            log.error("Invalid rule type!")
            return False

        try:
            response = requests.delete(endpoint, headers=self.api.headers)
            if response.status_code == 200:
                log.success(f"Success! Rule (ID: ({rule_id}) deleted")
                return True
            else:
                log.error(f"  Rule Deleting Error: {response.status_code} - {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            log.error(f"Connection Error: {e}")
            return False


