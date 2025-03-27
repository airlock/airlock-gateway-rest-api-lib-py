#!/usr/bin/env python3
# coding=utf-8
"""
Script to add a custom deny rule (with a single restriction) and create or update an associated custom deny rule group on an Airlock Gateway.

This script performs the following steps:
  1. Creates a custom deny rule using the POST /configuration/custom-deny-rules endpoint.
  2. Checks if a custom deny rule group with the name given by --custom-group-name exists:
       • If it exists, the new custom deny rule is added to that group.
       • Otherwise, a new custom deny rule group is created with that name and the custom deny rule is added to it.
  3. Prompts (unless --assumeyes is given) and then either activates (if --activate is provided) or saves the configuration change.
  
API key is read from the file "api_key.conf" (which must contain a [KEY] section with key "api_key") unless supplied via the -k/--api-key flag.

Command-line arguments:
  -g, --gateway         : Airlock Gateway hostname (required)
  -p, --port            : HTTPS port (default: 443)
  -k, --api-key         : API key for the Airlock Gateway (if omitted, read from api_key.conf)
  --deny-rule-name      : Name for the custom deny rule (required)
  --pattern-type        : Restriction type to set (e.g. httpMethodPattern, pathPattern, parameterNamePattern, parameterValuePattern, contentTypePattern, httpHeaderNamePattern, httpHeaderValuePattern) (required)
  --pattern             : The regex pattern for the restriction (required)
  --pattern-name        : (Optional) Display name for the restriction. Will be generated if empty.
  --case-ignored        : Set caseIgnored to true (default: false)
  --inverted            : Set inverted to true (default: false)
  --multiple-regex      : Set multipleSingleLineRegex to true (default: false)
  --log-only            : Enable logOnly mode (default: false)
  --custom-group-name   : Name for the custom deny rule group. If a group with this name already exists, add the custom deny rule to that group.
  -y, --assumeyes       : Automatically confirm without prompting
  -c, --comment         : Comment for the configuration change (default: "Add custom deny rule")
  --activate            : Immediately activate the new configuration (by default, changes are only saved)

Usage Example:
  To create a custom deny rule that only allows GET requests (i.e. denies non‑GET) and to add it to a group named "ALPOOL-36269" (creating the group if needed), run:

      ./add_custom_dr.py \
         -g mywaf.example.com \
         -k YOUR_API_KEY \
         --deny-rule-name "Deny non-GET" \
         --pattern-type httpMethodPattern \
         --pattern "^GET$" \
         --inverted \
         --log-only \
         --custom-group-name "CRUD restrictions" \
         -y -c "Add custom deny rule for non-GET requests" --activate
"""

import sys
import os
import argparse
import configparser
import logging
import signal
import json

# Ensure the library is in the path.
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.airlock_gateway_rest_api_lib import airlock_gateway_rest_api_lib as al

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)

DEFAULT_API_KEY_FILE = "api_key.conf"

def terminate_with_error(message=None, session=None):
    if message:
        print(message)
    if session:
        al.terminate_session(session)
    sys.exit(1)

def register_cleanup_handler(session):
    def cleanup(signum, frame):
        al.terminate_session(session)
        sys.exit("Session terminated due to signal.")
    for sig in (signal.SIGABRT, signal.SIGILL, signal.SIGSEGV, signal.SIGINT, signal.SIGTERM):
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
            sys.exit(f"Error reading API key from {key_file}: {e}")
    else:
        sys.exit("API key needed, either via -k option or in an api_key.conf file.")

def main():
    parser = argparse.ArgumentParser(
        description="Add a custom deny rule (with one restriction) and create or update an associated custom deny rule group in log-only mode."
    )
    parser.add_argument("-g", "--gateway", required=True,
                        help="Airlock Gateway hostname")
    parser.add_argument("-p", "--port", type=int, default=443,
                        help="HTTPS port (default: 443)")
    parser.add_argument("-k", "--api-key", help="API key for the Airlock Gateway (or read from api_key.conf)")
    parser.add_argument("--deny-rule-name", required=True,
                        help="Name for the custom deny rule")
    parser.add_argument("--pattern-type", required=True,
                        help="Restriction type to set (e.g. httpMethodPattern, pathPattern, parameterNamePattern, parameterValuePattern, contentTypePattern, httpHeaderNamePattern, httpHeaderValuePattern)")
    parser.add_argument("--pattern", required=True,
                        help="The regex pattern for the restriction")
    parser.add_argument("--pattern-name", default="custom pattern",
                        help="(Optional) Display name for the restriction.")
    parser.add_argument("--case-ignored", action="store_true",
                        help="Set caseIgnored to true (default: false)")
    parser.add_argument("--inverted", action="store_true",
                        help="Set inverted to true (default: false)")
    parser.add_argument("--multiple-regex", action="store_true",
                        help="Set multipleSingleLineRegex to true (default: false)")
    parser.add_argument("--log-only", action="store_true",
                        help="Enable logOnly mode (default: false)")
    parser.add_argument("--custom-group-name", required=True,
                        help="Name for the custom deny rule group. If a group with this name exists, add the custom deny rule to that group; otherwise, create a new group with this name.")
    parser.add_argument("-y", "--assumeyes", action="store_true",
                        help="Automatically confirm without prompting")
    parser.add_argument("-c", "--comment", default="Add custom deny rule",
                        help="Comment for the configuration change")
    parser.add_argument("--activate", action="store_true",
                        help="Immediately activate the new configuration (default is to only save)")
    args = parser.parse_args()

    api_key = get_api_key(args)
    SESSION = al.create_session(args.gateway, api_key, args.port)
    if not SESSION:
        sys.exit("Could not create session. Check gateway, port, and API key.")
    register_cleanup_handler(SESSION)
    al.load_active_config(SESSION)

    # Build the restrictions payload.
    restriction = {
        args.pattern_type: {
            "enabled": True,
            "name": args.pattern_name,  # backend will generate if empty
            "pattern": args.pattern,
            "caseIgnored": args.case_ignored,
            "inverted": args.inverted,
            "multipleSingleLineRegex": args.multiple_regex
        }
    }
    custom_rule_payload = {
        "data": {
            "type": "custom-deny-rule",
            "attributes": {
                "name": args.deny_rule_name,
                "restrictions": restriction,
                "logOnly": args.log_only
            }
        }
    }
    print("Creating custom deny rule...")
    res_rule = al.post(SESSION, "/configuration/custom-deny-rules", custom_rule_payload, exp_code=201)
    if res_rule.status_code != 201:
        terminate_with_error("Failed to create custom deny rule.", SESSION)
    new_rule = res_rule.json().get("data", {})
    new_rule_id = new_rule.get("id")
    print(f"Custom deny rule created with ID: {new_rule_id}")

    # Check if a custom deny rule group with the given name already exists.
    res_groups = al.get(SESSION, "/configuration/custom-deny-rule-groups", exp_code=200)
    existing_groups = res_groups.json().get("data", [])
    target_group = None
    for group in existing_groups:
        if group.get("attributes").get("name") == args.custom_group_name:
            target_group = group
            break

    if target_group:
        group_id = target_group.get("id")
        print(f"Custom deny rule group '{args.custom_group_name}' already exists with ID: {group_id}")
    else:
        # Create a new custom deny rule group with the given name.
        group_payload = {
            "data": {
                "type": "custom-deny-rule-group",
                "attributes": {
                    "name": args.custom_group_name
                }
            }
        }
        print("Creating custom deny rule group...")
        res_group = al.post(SESSION, "/configuration/custom-deny-rule-groups", group_payload, exp_code=201)
        if res_group.status_code != 201:
            terminate_with_error("Failed to create custom deny rule group.", SESSION)
        new_group = res_group.json().get("data", {})
        group_id = new_group.get("id")
        print(f"Custom deny rule group created with ID: {group_id}")

    # Connect the custom deny rule to the custom deny rule group.
    connect_payload = {
        "data": [
            {"type": "custom-deny-rule", "id": new_rule_id}
        ]
    }
    rel_endpoint = f"/configuration/custom-deny-rule-groups/{group_id}/relationships/custom-deny-rules"
    print("Connecting custom deny rule to the custom deny rule group...")
    res_conn = al.patch(SESSION, rel_endpoint, connect_payload, exp_code=[204,404])
    if res_conn.status_code != 204:
        print("Failed to associate the custom deny rule with the group.")
    else:
        print("Custom deny rule successfully associated with the group.")

    # Confirm and then activate (if --activate is provided) or save the configuration.
    if not args.assumeyes:
        ans = input("\nContinue to save and activate the new configuration? [y/n] ")
        if ans.lower() != "y":
            terminate_with_error("Operation cancelled.", SESSION)
    if args.activate:
        if al.activate(SESSION, args.comment):
            print("Configuration activated successfully.")
        else:
            al.save_config(SESSION, args.comment)
            print("Configuration saved.")
    else:
        al.save_config(SESSION, args.comment)
        print("Configuration saved.")

    al.terminate_session(SESSION)

if __name__ == "__main__":
    main()
