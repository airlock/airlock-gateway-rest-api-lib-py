#!/usr/bin/env python3
# coding=utf-8
"""
Script to manage maintenance page settings on Airlock WAF mappings.
Operations include:
    - Showing mappings with activated maintenance page:
         ./maintenance.py -g mywaf.example.com --mapping-regex "^mapping.*pattern$" -a show
    - Enabling/disabling maintenance on selected mappings:
         ./maintenance.py -g mywaf.example.com --mapping-regex "^mapping.*pattern$" -a enable
         ./maintenance.py -g mywaf.example.com --mapping-regex "^mapping.*pattern$" -a disable
    - Deleting selected mappings:
         ./maintenance.py -g mywaf.example.com --mapping-regex "^mapping.*pattern$" -a delete

By default, configuration changes are saved; add the --activate flag to activate them.
If the API key is not provided with -k, it will be read from an "api_key.conf" file 
(with a [KEY] section and an "api_key" value).

Usage example:
  ./maintenance.py -g mywaf.example.com --mapping-regex "^mapping.*pattern$" -a enable -k <YOUR_API_KEY> -f --activate -c "Update deny rule group"
"""

import sys
import os
import argparse
import configparser
import logging
import re

import airlock_gateway_rest_api_lib as al
from .utils import terminate_session_with_error, setup_session

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
module_logger = logging.getLogger(__name__)

# Global session variable
DEFAULT_API_KEY_FILE = "api_key.conf"


def get_api_key(args, key_file=DEFAULT_API_KEY_FILE):
    """Return the API key from command line or config file."""
    if args.api_key:
        return args.api_key.strip()
    elif os.path.exists(key_file):
        config = configparser.ConfigParser()
        config.read(key_file)
        try:
            return config.get("KEY", "api_key").strip()
        except Exception as e:
            sys.exit("Error reading API key from api_key.conf: " + str(e))
    else:
        sys.exit("API key needed, either via -k option or in an api_key.conf file.")

def get_selected_mappings(session, mapping_pattern):
    """Return a sorted list of mappings whose names match the given pattern."""
    all_mappings = al.get_all_mappings(session)
    selected = [m for m in all_mappings if re.search(mapping_pattern, m["attributes"]["name"])]
    return sorted(selected, key=lambda m: m["attributes"]["name"])

def create_change_info(affected_mapping_names, action):
    """Return a text description of the change based on the action."""
    if action == "enable":
        info = "Enable maintenance page for"
    elif action == "disable":
        info = "Disable maintenance page for"
    elif action == "delete":
        info = "Delete"
    else:
        info = "Change"
    info += " the following mapping(s):\n\t" + "\n\t".join(affected_mapping_names)
    return info

def main():
    parser = argparse.ArgumentParser(
        description="Manage maintenance page settings (or delete mappings) on Airlock WAF mappings. "
                    "By default configuration changes are saved; use --activate to activate them."
    )
    parser.add_argument("-g", "--gateway", required=True,
                        help="Airlock WAF hostname")
    parser.add_argument("--mapping-regex", required=True,
                        help="Regular expression to select mappings (e.g. '^mapping_a$')")
    parser.add_argument("-a", "--action", choices=["enable", "disable", "show", "delete"],
                        required=True, help="Action to perform on the selected mappings")
    # The -f/--force flag: if provided, confirmation is skipped.
    parser.add_argument("-f", "--force", dest="force", action="store_false",
                        help="Force activation without confirmation")
    parser.add_argument("--activate", action="store_true",
                        help="Activate configuration (default is to save configuration)")
    parser.add_argument("-k", "--api-key", help="REST API key for Airlock Gateway")
    parser.add_argument("-p", "--port", type=int, default=443,
                        help="Gateway HTTPS port (default: 443)")
    parser.add_argument("-c", "--comment", default="Script: {action} deny rule group for all mappings",
                        help="Comment for the configuration change")

    args = parser.parse_args()

    # Process the comment: replace placeholders if present.
    comment = args.comment.format(action=args.action)

    api_key = get_api_key(args, DEFAULT_API_KEY_FILE)

    SESSION = setup_session(args.gateway, api_key, args.port)

    # Get selected mappings based on the provided regex.
    mappings = get_selected_mappings(SESSION, args.mapping_regex)
    if not mappings:
        terminate_session_with_error(SESSION, "No mappings found matching the selector pattern.")

    if args.action == "show":
        print("Mapping Name, Maintenance Page Status")
        for mapping in mappings:
            status = mapping["attributes"].get("enableMaintenancePage", "N/A")
            print(f"{mapping['attributes']['name']}, {status}")
        al.terminate_session(SESSION)
        sys.exit(0)

    if args.action in ["enable", "disable"]:
        new_value = "true" if args.action == "enable" else "false"
        for mapping in mappings:
            data = {
                "data": {
                    "attributes": {
                        "enableMaintenancePage": new_value
                    },
                    "id": mapping["id"],
                    "type": "mapping"
                }
            }
            res = al.patch(SESSION, f"/configuration/mappings/{mapping['id']}", data, exp_code=[200,404])
            if res.status_code == 200:
                print(f"Updated mapping '{mapping['attributes']['name']}' successfully.")
            else:
                print(f"Failed to update mapping '{mapping['attributes']['name']}'.")
    elif args.action == "delete":
        for mapping in mappings:
            res = al.delete(SESSION, f"/configuration/mappings/{mapping['id']}", exp_code=[204,404])
            if res.status_code == 204:
                print(f"Deleted mapping '{mapping['attributes']['name']}'.")
            else:
                print(f"Failed to delete mapping '{mapping['attributes']['name']}'.")

    # Build a change summary.
    affected_names = [mapping["attributes"]["name"] for mapping in mappings]
    change_info = create_change_info(affected_names, args.action)
    
    # Prompt for confirmation (unless force flag is used).
    if args.force:
        # If force flag is False (i.e. not forced), then prompt.
        prompt_text = "\nContinue to "
        if args.activate:
            prompt_text += "save and activate "
        else:
            prompt_text += "save "
        prompt_text += "the new configuration? [y/n] "
        ans = input(prompt_text)
        if ans.lower() != "y":
            terminate_session_with_error(SESSION, "Operation cancelled.")

    # Save or activate the configuration based on --activate flag.
    if args.activate:
        if al.activate(SESSION, comment):
            print("Configuration activated successfully.")
        else:
            al.save_config(SESSION, comment)
            print("Activation failed; configuration saved instead.")
    else:
        al.save_config(SESSION, comment)
        print("Configuration saved.")

    al.terminate_session(SESSION)

if __name__ == "__main__":
    main()
