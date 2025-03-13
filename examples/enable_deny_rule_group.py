#!/usr/bin/env python3
"""
Script to enable or disable a deny rule group on all mappings.

Tested with Airlock Gateway versions 8.3 and 8.4.

Usage example:
  ./enable_deny_rule_group.py -g mywaf.example.com --group-regex SQLI_PARAM_VALUE -a enable -k <YOUR_API_KEY> -y -c "Update deny rule group"
  
If -k is not provided, the script will try to read the API key from "api_key.conf"
with a [KEY] section and an "api_key" value.
"""

import sys
import os
import argparse
import configparser
import logging
import signal
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
DEFAULT_API_KEY_FILE = "api_key.conf"

def terminate_with_error(message=None):
    """Terminate the session and exit with an error message."""
    if message:
        print(message)
    al.terminate_session(SESSION)
    sys.exit(1)

def register_cleanup_handler():
    """
    Cleanup handler; terminates the session if a program error occurs.
    """
    def cleanup(signum, frame):
        al.terminate_session(SESSION)
        sys.exit("Session terminated due to signal.")
    for sig in (signal.SIGABRT, signal.SIGILL, signal.SIGINT, signal.SIGSEGV, signal.SIGTERM, signal.SIGQUIT):
        signal.signal(sig, cleanup)

def get_api_key(args, key_file=DEFAULT_API_KEY_FILE):
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

def main():
    parser = argparse.ArgumentParser(
        description="Enable or disable a deny rule group on all WAF mappings."
    )
    parser.add_argument("-g", "--gateway", required=True,
                        help="Airlock WAF hostname")
    parser.add_argument("--group-regex", required=True,
                        help="Deny Rule Group shortname")
    parser.add_argument("-a", "--action", choices=['enable', 'disable'], default='enable',
                        help="Enable or disable the deny rule group")
    parser.add_argument("-p", "--port", type=int, default=443,
                        help="Gateway HTTPS port (default: 443)")
    parser.add_argument("-k", "--api-key", help="REST API key for Airlock Gateway")
    parser.add_argument("-y", "--assumeyes", action="store_true",
                        help="Automatically confirm configuration changes without prompting")
    parser.add_argument("-c", "--comment", default="Script: {action} deny rule group {group_id} for all mappings",
                        help="Comment for the configuration change")
    args = parser.parse_args()

    # Process the comment: replace placeholders if present.
    comment = args.comment.format(action=args.action, group_id=args.group_regex)

    # Get API key: either from command-line or config file.
    api_key = get_api_key(args)


    # Create a new session.
    global SESSION
    SESSION = al.create_session(args.gateway, api_key, args.port)
    if not SESSION:
        sys.exit("Could not create session. Check gateway, port, and API key.")

    register_cleanup_handler()
    # Load the currently active configuration.
    al.load_active_config(SESSION)

    # Retrieve all mappings.
    mappings = al.get_all_mappings(SESSION)
    if not mappings:
        terminate_with_error("No mappings found.")

    enable_flag = True if args.action == "enable" else False

    # For each mapping, update the deny rule group settings.
    for mapping in mappings:
        mapping_id = mapping['id']
        # Retrieve the current deny rule group settings.
        mapping_drg = al.get_mapping_deny_rule_group(SESSION, mapping_id, args.group_regex)
        print(f"Mapping ID {mapping_id}: Current settings:")
        print(json.dumps(mapping_drg, indent=4))
        # Update the "enabled" attribute.
        mapping_drg['attributes']['enabled'] = enable_flag
        success = al.update_mapping_deny_rule_group(
            SESSION,
            mapping_id,
            args.group_regex,
            mapping_drg['attributes']
        )
        if success:
            print(f"Updated mapping '{mapping['attributes']['name']}', mapping ID: {mapping_id}")
        else:
            print(f"Failed to update mapping '{mapping['attributes']['name']}', mapping ID: {mapping_id}")

    # Prompt for confirmation if not assumeyes.
    if not args.assumeyes:
        ans = input("\nContinue to save and activate the new configuration? [y/n] ")
        if ans.lower() != "y":
            terminate_with_error("Operation cancelled.")

    # Activate configuration; if activation fails, save config.
    if al.activate(SESSION, comment):
        print("Configuration activated successfully.")
    else:
        al.save_config(SESSION, comment)
        print("Configuration saved.")

    al.terminate_session(SESSION)

if __name__ == "__main__":
    main()