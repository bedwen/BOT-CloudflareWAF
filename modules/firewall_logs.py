from idlelib import query

import requests
import datetime
from utils.logger import log

class FirewallLogsManager:
    def __init__(self, api_client):
        self.api = api_client
        self.graphql_url = "https://api.cloudflare.com/client/v4/graphql"

    def get_recent_events(self, limit=15):
        log.info(f"Fetching the last {limit} firewall events from Cloudflare")
        zone_id = self.api.base_url.rstrip('/').split('/')[-1]

        now = datetime.datetime.utcnow()
        yesterday = now - datetime.timedelta(days=1)
        since = yesterday.strftime("%Y-%m-%dT%H:%M:%SZ")
        until = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        query = """
        query {
          viewer {
            zones(filter: {zoneTag: "%s"}) {
              firewallEventsAdaptive(
                filter: {datetime_geq: "%s", datetime_lt: "%s"}
                limit: %d
                orderBy: [datetime_DESC]
              ) {
                action
                clientCountryName
                clientIP
                datetime
                source
              }
            }
          }
        }
        """ % (zone_id, since, until, limit)


        try:
            response = requests.post(self.graphql_url, headers=self.api.headers, json={"query": query}, timeout=10)

            if response.status_code == 200:
                data = response.json()
                try:
                    events = data["data"]["viewer"]["zones"][0]["firewallEventsAdaptiver"]
                    if not events:
                        log.info("No firewall events found in the last 24 horus.")
                        return []
                    return events
                except (KeyError, IndexError, TypeError):
                    log.error("Failed to parse GraphQL response. Data might me empty.")
                    return []
            else:
                log.error(f"GraphQL Error ({response.status_code}): {response.text}")
                return []

        except requests.exceptions.Timeout:
            log.error("Connection Error: Request timed out while fetching logs.")
            return []
        except requests.exceptions.RequestException as e:
            log.error(f"Connection Error: {e}")
            return []

