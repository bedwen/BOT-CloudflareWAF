import requests
from utils.logger import log

class ThreatIntelManager:
    def __init__(self,abuse_api_key):
        self.api_key = abuse_api_key
        self.base_url = "https://api.abuseipdb.com/api/v2/check"

    def check_ip_reputation(self, ip_address):
        if not self.api_key:
            log.error("AbuseIPDB API Key is missing! Please add it to your config/env file.")
            return None

        log.info(f"Querying AbuseIPDB for IP: {ip_address}...")

        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }

        querystring = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90'
        }

        try:
            response = requests.get(url=self.base_url, headers=headers, params=querystring, timeout=10)

            if response.status_code == 200:
                data = response.json().get('data', {})

                abuse_score = data.get('abuseConfidenceScore',0)
                total_reports = data.get('totalReports',0)
                country = data.get('countryCode','Unknown')
                usage_type = data.get('usageType','Unknown')

                if abuse_score > 50:
                    log.warning(f"HIGH RISK! {ip_address} (Country: {country}, Type: {usage_type})")
                    log.warning(f"Abuse Score: {abuse_score}% | Total Reports: {total_reports}%")
                elif abuse_score > 0:
                    log.info(f"Suspicious: {ip_address} (Country: {country}) | Abuse Score: {abuse_score}%")
                else:
                    log.success(f"Clean IP: {ip_address} (Country: {country}) | No recent reports found.")

                return data

            elif response.status_code == 401:
                log.error("AbuseIPDB API Key is invalid or expired.")
                return None
            elif response.status_code == 429:
                log.error("AbuseIPDB Rate Limit Exceeded. Try again later.")
                return None
            else:
                log.error(f"AbuseIPDB API Error: {response.status_code} - {response.text}")
                return None

        except requests.exceptions.Timeout:
            log.error("AbuseIPDB query timed out.")
            return None
        except requests.exceptions.RequestException as e:
            log.error(f"AbuseIPDB Connection Error: {e}")
            return None
