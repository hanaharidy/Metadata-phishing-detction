import requests

class VirusTotalIPChecker:
    def __init__(self):
        # Store API key and base URL
        self.api_key = "d8013f5ca38a1d7cfe6c72d24d25ca27b696cbdb6d52e24699259e3fc0c3b5c4"
        self.base_url = "https://www.virustotal.com/api/v3/ip_addresses/"

    def archetecure(self):
        """Return architecture details of this checker"""
        return {
            "service": "VirusTotal IP reputation API",
            "base_url": self.base_url,
            "headers": {"x-apikey": "API_KEY_HIDDEN"}
        }

    def check_ip(self, ip: str) -> dict:
        """Check IP reputation using VirusTotal API"""
        vt_url = f"{self.base_url}{ip}"
        headers = {"x-apikey": self.api_key}
        response = requests.get(vt_url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            result = {
                "ip": ip,
                "country": attributes.get("country"),
                "asn": attributes.get("asn"),
                "last_analysis_stats": attributes.get("last_analysis_stats"),
                "tags": attributes.get("tags"),
                "resolutions": attributes.get("resolutions"),
            }
            return result
        else:
            return {"error": f"Request failed with status {response.status_code}"}

    def run_interactive(self, ip_to_check):
        """Function to take input and print output"""
        result = self.check_ip(ip_to_check)
        print("\n--- IP Reputation Report ---")
        for key, value in result.items():
            print(f"{key}: {value}")
        return result
