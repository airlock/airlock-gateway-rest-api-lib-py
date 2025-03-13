#!/usr/bin/env python3
# coding=utf-8
"""
Script to manage maintenance page settings on Airlock WAF mappings.
Operations include:
    - Showing mappings with activated maintenance page:
         ./maintenance.py -g my_airlock --mapping-regex "^mapping.*pattern$" -a show
    - Enabling/disabling maintenance on selected mappings:
         ./maintenance.py -g my_airlock --mapping-regex "^mapping.*pattern$" -a enable
         ./maintenance.py -g my_airlock --mapping-regex "^mapping.*pattern$" -a disable
    - Deleting selected WAF mappings:
         ./maintenance.py -g my_airlock --mapping-regex "^mapping.*pattern$" -a delete

Tested with Airlock Gateway versions 8.3 and 8.4.

If the API key is not provided with -k, it will be read from an api_key.conf file 
(with a [KEY] section and an "api_key" value).
"""

import sys
import os
import argparse
import configparser
import logging
import signal
import re
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.airlock_gateway_rest_api_lib import airlock_gateway_rest_api_lib as al

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)

# Global session variable
SESSION = None

def terminate_with_error(message=None):
    """Terminate the session and exit with an error message."""
    if message:
        print(message)
    al.terminate_session(SESSION)
    sys.exit(1)

def register_cleanup_handler():
    """Register signal handlers to terminate the session on interruption."""
    def cleanup(signum, frame):
        al.terminate_session(SESSION)
        sys.exit("Session terminated due to signal.")
    for sig in (signal.SIGABRT, signal.SIGILL, signal.SIGINT, signal.SIGSEGV,
                signal.SIGTERM, signal.SIGQUIT):
        signal.signal(sig, cleanup)

def get_api_key(args, key_file):
    """Return the API key from command line or config file."""
    if args.api_key:
        return args.api_key.strip()
    elif os.path.exists(key_file):
        config = configparser.ConfigParser()
        config.read(key_file)
        try:
            return config.get("KEY", "api_key").strip()
        except Exception as e:
            sys.exit(f"Error reading API key from {key_file}: {e}")
    else:
        sys.exit("API key needed, either via -k option or in an api_key.conf file.")

def get_selected_mappings(SESSION, mapping_pattern):
    """Return a sorted list of mappings whose names match the given pattern."""
    all_mappings = al.get_all_mappings(SESSION)
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

def confirm(change_info, force_confirm):
    """Ask for confirmation if not forced."""
    if force_confirm is False:
        return True
    print(change_info)
    answer = input("\nContinue to activate the new config? [y/n] ")
    if answer.lower() == "y":
        return True
    print("Nothing changed")
    return False

def activate_config(SESSION, change_info):
    """Activate the configuration with a comment."""
    if not confirm(change_info, args.force):
        terminate_with_error("Activation cancelled by user.")
    comment = "REST: " + change_info.replace("\n\t", ", ").replace(": ,", ":")
    if al.activate(SESSION, comment):
        print("Configuration activated successfully.")
    else:
        print("Failed to activate configuration.")

def main():
    parser = argparse.ArgumentParser(
        description="Manage maintenance page settings (or delete mappings) on Airlock WAF mappings."
    )
    parser.add_argument("-g", "--gateway", required=True,
                        help="Airlock WAF hostname")
    parser.add_argument("--mapping-regex", required=True,
                        help="Regular expression to select mappings (e.g. '^mapping_a$')")
    parser.add_argument("-a", "--action", choices=["enable", "disable", "show", "delete"],
                        required=True, help="Action to perform on the selected mappings")
    parser.add_argument("-f", "--force", dest="force", action="store_false",
                        help="Force activation without confirmation")
    parser.add_argument("-k", "--api-key", help="REST API key for Airlock Gateway")
    parser.add_argument("-p", "--port", type=int, default=443,
                        help="Gateway HTTPS port (default: 443)")
    global args
    args = parser.parse_args()

    api_key = get_api_key(args, "./api_key.conf")

    global SESSION
    SESSION = al.create_session(args.gateway, api_key, args.port)
    if not SESSION:
        sys.exit("Could not create session. Check gateway, port, and API key.")

    register_cleanup_handler()

    al.load_active_config(SESSION)

    # Get selected mappings based on mapping selector regex
    mappings = get_selected_mappings(SESSION, args.mapping_regex)
    if not mappings:
        terminate_with_error("No mappings found matching the selector pattern.")

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

    # Prepare change info and activate configuration.
    affected_names = [mapping["attributes"]["name"] for mapping in mappings]
    change_info = create_change_info(affected_names, args.action)
    activate_config(SESSION, change_info)

    al.terminate_session(SESSION)

if __name__ == "__main__":
    main()