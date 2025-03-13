#!/usr/bin/env python3
# coding=utf-8
"""
Script to add a custom deny rule (with a single restriction) and an associated custom deny rule group 
to an Airlock Gateway.

This script performs the following steps:
  1. Creates a custom deny rule using the POST /configuration/custom-deny-rules endpoint.
     The user must supply:
       • --deny-rule-name : Name for the custom deny rule.
       • --pattern-type   : The type of restriction to set. Supported pattern types are:
                             - httpMethodPattern
                             - pathPattern
                             - parameterNamePattern
                             - parameterValuePattern
                             - contentTypePattern
                             - httpHeaderNamePattern
                             - httpHeaderValuePattern
       • --pattern        : The regex pattern for the restriction.
       • --pattern-name   : (Optional) Display name for the restriction. Will be generated if empty.
       • Optional flags: --case-ignored, --inverted, --multiple-regex.
       • --log-only       : Enable logOnly mode (default: false). If not specified, logOnly will be false.
  2. Creates a custom deny rule group (named as the deny rule name with " group" appended) 
     using POST /configuration/custom-deny-rule-groups.
  3. Connects the newly created custom deny rule with the group via a PATCH to the relationships endpoint.
  4. Prompts (unless --assumeyes is given) and then activates (or saves) the configuration.

API key is read from the file "api_key.conf" (in a [KEY] section with key "api_key") unless supplied via -k/--api-key.

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
  -y, --assumeyes       : Automatically confirm without prompting
  -c, --comment         : Comment for the configuration change (default: "Add custom deny rule")

Usage Example:
  To create a custom deny rule that allows only GET requests (i.e. denies non‑GET),
  and then create an associated group, run:

      ./create_custom_deny_rule.py \
         -g mywaf.example.com \
         -k YOUR_API_KEY \
         --deny-rule-name "Deny non-GET" \
         --pattern-type httpMethodPattern \
         --pattern "^GET$" \
         --inverted \
         --log-only \
         -y -c "Add custom deny rule for non-GET requests"
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
        description="Add a custom deny rule (with one restriction) and create an associated custom deny rule group in log-only mode."
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
    parser.add_argument("--pattern-name", default="",
                        help="(Optional) Display name for the restriction. Will be generated if empty.")
    parser.add_argument("--case-ignored", action="store_true",
                        help="Set caseIgnored to true (default: false)")
    parser.add_argument("--inverted", action="store_true",
                        help="Set inverted to true (default: false)")
    parser.add_argument("--multiple-regex", action="store_true",
                        help="Set multipleSingleLineRegex to true (default: false)")
    parser.add_argument("--log-only", action="store_true",
                        help="Enable logOnly mode (default: false)")
    parser.add_argument("-y", "--assumeyes", action="store_true",
                        help="Automatically confirm without prompting")
    parser.add_argument("-c", "--comment", default="Add custom deny rule",
                        help="Comment for the configuration change")
    args = parser.parse_args()

    api_key = get_api_key(args)
    SESSION = al.create_session(args.gateway, api_key, args.port)
    if not SESSION:
        sys.exit("Could not create session. Check gateway, port, and API key.")
    register_cleanup_handler(SESSION)
    al.load_active_config(SESSION)

    # Build the restrictions payload.
    # If --pattern-name is empty, the backend will generate a display name.
    restriction = {
        args.pattern_type: {
            "enabled": True,
            "name": args.pattern_name,
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

    # Create a custom deny rule group.
    group_name = args.deny_rule_name + " group"
    group_payload = {
        "data": {
            "type": "custom-deny-rule-group",
            "attributes": {
                "name": group_name
            }
        }
    }
    print("Creating custom deny rule group...")
    res_group = al.post(SESSION, "/configuration/custom-deny-rule-groups", group_payload, exp_code=201)
    if res_group.status_code != 201:
        terminate_with_error("Failed to create custom deny rule group.", SESSION)
    new_group = res_group.json().get("data", {})
    new_group_id = new_group.get("id")
    print(f"Custom deny rule group created with ID: {new_group_id}")

    # Connect the custom deny rule to the group.
    connect_payload = {
        "data": [
            {"type": "custom-deny-rule", "id": new_rule_id}
        ]
    }
    rel_endpoint = f"/configuration/custom-deny-rule-groups/{new_group_id}/relationships/custom-deny-rules"
    print("SKIP Connecting custom deny rule to the custom deny rule group...")
    res_conn = al.patch(SESSION, rel_endpoint, connect_payload, exp_code=[204,404])
    if res_conn.status_code != 204:
        print("Failed to associate the custom deny rule with the group.")
    else:
        print("Custom deny rule successfully associated with the group.")

    # Confirm and then activate or save the configuration.
    if not args.assumeyes:
        ans = input("\nContinue to save and activate the new configuration? [y/n] ")
        if ans.lower() != "y":
            terminate_with_error("Operation cancelled.", SESSION)
    if al.activate(SESSION, args.comment):
        print("Configuration activated successfully.")
    else:
        al.save_config(SESSION, args.comment)
        print("Configuration saved.")

    al.terminate_session(SESSION)

if __name__ == "__main__":
    main()
