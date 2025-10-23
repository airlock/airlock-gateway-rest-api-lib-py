#!/usr/bin/env python3
# coding=utf-8
"""
Script to update log‑only mode on deny rule groups for selected mappings.

Tested with Airlock Gateway versions 8.3 and 8.4.

This script directly interacts with the REST API endpoint:

    PATCH /configuration/mappings/{mappingId}/deny-rule-groups/{groupShortName}

It updates the “logOnly” attribute for the specified deny rule groups on all mappings
selected by a regex. By default changes are saved; if the --activate flag is provided,
the configuration will be activated after confirmation.

The `--group-regex` argument takes a regex pattern matched against deny rule group short names (e.g., "SQLI_PARAM_VALUE").
You can retrieve the list of these short names directly from your gateway's REST API endpoint, e.g. by using a browser:
`GET https://<gateway-hostname>/airlock/rest/configuration/deny-rule-groups`

API key is provided via the –k flag or read from an “api_key.conf” file (with a [KEY] section).

Usage examples:
  Enable log‑only mode for deny rule groups (selected by group regex '.*') on all mappings matching “^cust”:
      ./set_log_only.py -g mywaf.example.com --mapping-regex '^cust' --group-regex '.*' --activate -k YOUR_API_KEY

  Disable log‑only mode (using --disable) for deny rule group 'SQL_PARAM_VALUE':
      ./set_log_only.py -g mywaf.example.com --mapping-regex '^cust' --group-regex 'SQL_PARAM_VALUE' --disable -k YOUR_API_KEY

  (Optionally add –y to skip confirmation and –c to provide a comment; –p to specify a port)
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

SESSION = None

def get_api_key(args, key_file="api_key.conf"):
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

def get_mappings_and_groups(mapping_regex, group_regex, assumeyes):
    selected_mappings = al.select_mappings(SESSION, pattern=mapping_regex)
    if not selected_mappings:
        terminate_session_with_error(SESSION, "No mappings selected")
    selected_groups = []
    for dr_group in al.get_deny_rule_groups(SESSION):
        if re.search(group_regex, dr_group["attributes"]["name"]):
            selected_groups.append(dr_group)
    if not selected_groups:
        terminate_session_with_error(SESSION, "No deny-rule groups selected")
    print("Selected mappings:")
    for m in selected_mappings:
        print("\t" + m["attributes"]["name"])
    print("Selected deny-rule groups:")
    for g in selected_groups:
        print("\t" + g["attributes"]["name"])
    if not assumeyes:
        ans = input("Do you want to continue? [y/n] ")
        if ans.lower() != "y":
            terminate_session_with_error(SESSION, "Operation cancelled by user.")
    return selected_mappings, selected_groups

def update_logonly_mode(mapping_regex, group_regex, log_only_value, assumeyes):
    selected_mappings, selected_groups = get_mappings_and_groups(mapping_regex, group_regex, assumeyes)
    for mapping in selected_mappings:
        for group in selected_groups:
            # Retrieve the current deny rule group usage data.
            group_data = al.get_mapping_deny_rule_group(SESSION, mapping["id"], group["id"])
            print(group_data, "\n")
            # Patch the deny rule group: update logOnly attribute.
            al.update_mapping_deny_rule_group(SESSION, mapping["id"], group["id"], {"logOnly": log_only_value})
    return

def main():
    parser = argparse.ArgumentParser(
        description="Update log‑only mode for deny rule groups on selected mappings. "
                    "By default changes are saved; use --activate to activate the new configuration."
    )
    parser.add_argument("-g", "--gateway", required=True,
                        help="Airlock Gateway hostname")
    parser.add_argument("--mapping-regex", required=True,
                        help="Regex to select mappings by name")
    parser.add_argument("--group-regex", required=True,
                        help="Regex to select deny-rule groups by name")
    parser.add_argument("--disable", action="store_true",
                        help="Disable log‑only mode (default is to enable)")
    parser.add_argument("--activate", action="store_true",
                        help="Activate configuration changes instead of just saving")
    parser.add_argument("-y", "--assumeyes", action="store_true",
                        help="Automatically confirm without prompting")
    parser.add_argument("-k", "--api-key", help="REST API key for Airlock Gateway")
    parser.add_argument("-p", "--port", type=int, default=443,
                        help="Gateway HTTPS port (default: 443)")
    parser.add_argument("-c", "--comment", default="Set log-only mode via REST API",
                        help="Comment for the configuration change")
    args = parser.parse_args()

    global SESSION
    api_key = get_api_key(args)
    SESSION = setup_session(args.gateway, api_key, args.port)

    # Determine desired logOnly mode
    log_only_value = False if args.disable else True

    # Update log-only mode for each mapping and each deny rule group selected
    update_logonly_mode(args.mapping_regex, args.group_regex, log_only_value, args.assumeyes)

    # Prepare change summary
    affected_names = [m["attributes"]["name"] for m in al.select_mappings(SESSION, pattern=args.mapping_regex)]
    change_info = f"Log‑only mode {'disabled' if args.disable else 'enabled'} for deny rule groups on mappings: " + ", ".join(affected_names)
    print("\n" + change_info)

    # Confirm change (unless assumeyes is given) and then save/activate config
    if not args.assumeyes:
        prompt_text = "\nContinue to "
        if args.activate:
            prompt_text += "save and activate "
        else:
            prompt_text += "save "
        prompt_text += "the new configuration? [y/n] "
        ans = input(prompt_text)
        if ans.lower() != "y":
            terminate_session_with_error(SESSION, "Operation cancelled.")
    if args.activate:
        if al.activate(SESSION, args.comment):
            print("Configuration activated successfully.")
        else:
            al.save_config(SESSION, args.comment)
            print("Activation failed; configuration saved instead.")
    else:
        al.save_config(SESSION, args.comment)
        print("Configuration saved.")

    al.terminate_session(SESSION)

if __name__ == "__main__":
    main()
