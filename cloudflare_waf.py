import os
import json
import requests
import argparse

CONFIG_FILE = "cloudflare_config.json"

# WAF rules to be applied
WAF_RULES = [
    {
        "description": "Good Bots Allow",
        "expression": '(cf.client.bot) or (cf.verified_bot_category in {"Search Engine Crawler"})',
        "action": "skip",
        "action_parameters": {
            "ruleset": "current",
            "phases": ["http_request_firewall_managed"],
            "products": ["waf"]
        },
    },
    {
        "description": "MC Aggressive Crawlers",
        "expression": '(http.user_agent contains "yandex") or (http.user_agent contains "ahrefs")',
        "action": "managed_challenge"
    },
    {
        "description": "Block Web Hosts / WP Paths / TOR",
        "expression": '(http.request.uri.path contains "xmlrpc") or (ip.src.country in {"T1"})',
        "action": "block"
    }
]


def load_config():
    """Load API credentials from config file."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}


def save_config(data):
    """Save API credentials to config file."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=4)


def get_headers():
    """Return HTTP headers for Cloudflare API requests."""
    config = load_config()
    return {
        "X-Auth-Email": config.get("email"),
        "X-Auth-Key": config.get("api_key"),
        "Content-Type": "application/json",
    }


def make_request(url, method="GET", data=None):
    """Make a request to the Cloudflare API."""
    headers = get_headers()
    response = requests.request(method, url, headers=headers, json=data)
    return response.json()


def list_zones():
    """Retrieve and display Cloudflare zones."""
    config = load_config()
    url = f"https://api.cloudflare.com/client/v4/zones?account.id={config.get('account_id')}"
    response = make_request(url)
    
    if response.get("success"):
        zones = response["result"]
        for idx, zone in enumerate(zones, start=1):
            print(f"{idx}. {zone['name']} (ID: {zone['id']})")
        return {str(i): z["id"] for i, z in enumerate(zones, start=1)}
    else:
        print("Error fetching zones:", response.get("errors"))
        return {}


def get_ruleset_id(zone_id):
    """Retrieve the ruleset ID for a given zone."""
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets"
    response = make_request(url)
    
    if response.get("success"):
        for ruleset in response["result"]:
            if ruleset["kind"] == "zone" and ruleset["phase"] == "http_request_firewall_custom":
                return ruleset["id"]
    return None


def create_ruleset(zone_id):
    """Create a new WAF ruleset for a zone."""
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets"
    data = {
        "name": "Custom WAF Ruleset",
        "kind": "zone",
        "phase": "http_request_firewall_custom",
    }
    response = make_request(url, method="POST", data=data)
    return response.get("result", {}).get("id")


def apply_waf_rules(zone_id):
    """Apply WAF rules to a specified zone."""
    ruleset_id = get_ruleset_id(zone_id) or create_ruleset(zone_id)
    if not ruleset_id:
        print(f"Failed to create or retrieve ruleset for Zone ID {zone_id}.")
        return

    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/rulesets/{ruleset_id}"
    data = {"rules": WAF_RULES}
    response = make_request(url, method="PUT", data=data)

    if response.get("success"):
        print(f"Successfully updated WAF rules for Zone ID {zone_id}.")
    else:
        print(f"Failed to update WAF rules for Zone ID {zone_id}: {response.get('errors')}")


def setup_credentials():
    """Prompt the user to enter Cloudflare API credentials."""
    email = input("Enter Cloudflare API Email: ").strip()
    api_key = input("Enter Cloudflare API Key: ").strip()
    account_id = input("Enter Cloudflare Account ID: ").strip()

    save_config({"email": email, "api_key": api_key, "account_id": account_id})
    print("Credentials saved successfully.")


def delete_credentials():
    """Delete stored API credentials."""
    if os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)
        print("Credentials deleted successfully.")
    else:
        print("No credentials found.")


def main():
    parser = argparse.ArgumentParser(description="Cloudflare WAF Rules Manager")
    parser.add_argument("--setup", action="store_true", help="Set up API credentials")
    parser.add_argument("--list-zones", action="store_true", help="List available Cloudflare zones")
    parser.add_argument("--apply-rules", action="store_true", help="Apply WAF rules to selected zones")
    parser.add_argument("--clear", action="store_true", help="Delete stored credentials")

    args = parser.parse_args()

    if args.setup:
        setup_credentials()
    elif args.list_zones:
        list_zones()
    elif args.apply_rules:
        zones = list_zones()
        if zones:
            selection = input("Enter the numbers of the zones to update (comma-separated): ").split(",")
            selected_zone_ids = [zones[num.strip()] for num in selection if num.strip() in zones]
            for zone_id in selected_zone_ids:
                apply_waf_rules(zone_id)
    elif args.clear:
        delete_credentials()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
