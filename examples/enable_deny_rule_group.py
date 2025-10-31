#!/usr/bin/env python3
"""
Script to enable or disable a deny rule group on all mappings.

Tested with Airlock Gateway versions 8.3 and 8.4.

Usage example:
  ./enable_deny_rule_group.py -g mywaf.example.com --group-regex SQLI_PARAM_VALUE -a enable -k <YOUR_API_KEY> -y -c "Update deny rule group" --activate

If -k is not provided, the script will try to read the API key from "api_key.conf"
(with a [KEY] section and an "api_key" value).

By default, changes are saved (but not activated). To activate the configuration,
supply the --activate flag.
"""

import sys
import os
import argparse
import configparser
import logging
import json

from ..src import rest_api_lib as al
from .utils import terminate_session_with_error, setup_session


# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
module_logger = logging.getLogger(__name__)

# Global session variable
SESSION = None
DEFAULT_API_KEY_FILE = "api_key.conf"

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
    parser.add_argument("--activate", action="store_true",
                        help="Activate the configuration (default: save configuration only)")
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
    SESSION = setup_session(args.gateway, api_key, args.port)


    # Retrieve all mappings.
    mappings = al.get_all_mappings(SESSION)
    if not mappings:
        terminate_session_with_error(SESSION, "No mappings found.")

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

    # If not in assumeyes mode, prompt for confirmation with different text based on the --activate flag.
    if not args.assumeyes:
        prompt_text = "\nContinue to activate the new configuration? [y/n] " if args.activate else "\nContinue to save the new configuration? [y/n] "
        ans = input(prompt_text)
        if ans.lower() != "y":
            terminate_session_with_error(SESSION, "Operation cancelled.")

    # If --activate flag is provided, attempt to activate; otherwise, simply save.
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
