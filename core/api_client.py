class CloudflareAPIClient:

    def __init__(self,api_token, zone_id):
        self.api_token = api_token
        self.zone_id = zone_id

        #cloudflare base api url
        self.base_url = f"https://api.cloudflare.com/client/v4/zones/{self.zone_id}"

        #authorization header for identify
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }
