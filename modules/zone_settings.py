import requests
from utils.logger import log

class ZoneSettingsManager:
    def __init__(self,api_client):
        self.api = api_client
        #zone settings endpoint: /zones/{zone_id}/settings/security_level
        self.endpoint = f"{self.api.base_url}/settings/security_level"

    def get_security_level(self):

        try:
            response = requests.get(self.endpoint, headers=self.api.headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                current_level = data.get("result", {}).get("value","Unknown")

                if current_level == "under_attack":
                    log.warning("Under Attack Mode Is Active")
                elif current_level == "high":
                    log.warning("Security Level: HIGH")
                else:
                    log.success(f"Security Level: {current_level.upper()} ")

                return current_level
            else:
                log.error(f"API Error: ({response.status_code}): {response.text}")
                return None

        except requests.exceptions.Timeout:
            log.error("Connection Error: Request timed out while fetching security level.")
            return None
        except requests.exceptions.RequestException as e:
            log.error(f"Connection Error: {e}")
            return None


    def set_security_level(self,level):
        #change security level
        #levels: essentially_off, low, medium, high, under_attack
        valid_levels = ['essentially_off', 'low', 'medium', 'high', 'under_attack']

        if level not in valid_levels:
            log.error(f"Invalid security level: {level}")
            return False

        payload = {
            "value": level
        }
        try:
            log.info(f"Changing security level to '{level.upper()}'...")

            response = requests.patch(self.endpoint, headers=self.api.headers, json=payload, timeout=10)

            if response.status_code == 200:
                data = response.json()
                new_level = data.get("result", {}).get("value","Unknown")

                if new_level == "under_attack":
                    log.success("Under Attack mode has been successfully activated.")
                    log.warning("ALERT: Site is now in 'Under Attack' mode! All visitors will be challenged.")
                else:
                    log.success(f"Success! Security level updated to: {new_level.upper()}")
                return True

            else:
                log.error(f"Failed to change security level ({response.status_code}): {response.text})")
                return False

        except requests.exceptions.Timeout:
            log.error("Connection Error: Request timed out while changing security level.")
            return False
        except requests.exceptions.RequestException as e:
            log.error(f"Connection Error: {e}")
            return False