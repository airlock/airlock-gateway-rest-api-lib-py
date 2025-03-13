#!/usr/bin/env python3
# coding=utf-8
"""
IP List Management on Airlock Gateway Version 8.2
Script to update an IP address list’s relationships (whitelist or blacklist)
by appending mapping entries using the REST endpoint 'configuration/ip-address-lists/{ip_list_id}/relationships/(mappings-whitelist|mappings-blacklist)'

After performing the update, the script will prompt (unless --assumeyes is given)
to confirm and then either activate or save the new configuration using al.activate and al.save_config.

Usage Examples:
  List all IP address lists:
      ./update_ip_list_relationship_8.2.py list -g mywaf.example.com -k YOUR_API_KEY

  Update the whitelist relationship of IP list 3 by appending all mappings whose names match "^cust":
      ./update_ip_list_relationship_8.2.py update -g mywaf.example.com --ip-list-id 3 --whitelist --mapping-regex '^cust' -y -c "Add cust mappings to whitelist" -k YOUR_API_KEY

  Update the blacklist relationship (without forcing confirmation):
      ./update_ip_list_relationship_8.2.py update -g mywaf.example.com --ip-list-id 3 --blacklist --mapping-regex '^cust' -c "Add cust mappings to blacklist" -k YOUR_API_KEY
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

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)

SESSION = None
DEFAULT_API_KEY_FILE = "api_key.conf"

def terminate_with_error(message=None):
    if message:
        print(message)
    al.terminate_session(SESSION)
    sys.exit(1)

def register_cleanup_handler():
    def cleanup(signum, frame):
        al.terminate_session(SESSION)
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

def list_ip_lists(session):
    res = al.get(session, "/configuration/ip-address-lists", exp_code=200)
    ip_lists = res.json().get("data")
    if not ip_lists:
        print("No IP address lists found.")
    else:
        for ip in ip_lists:
            attrs = ip.get("attributes", {})
            print(f"ID: {ip.get('id')}, Name: {attrs.get('name')}, IPs: {attrs.get('ips')}")
    return

def update_ip_list_relationship(session, ip_list_id: str, relationship_field: str,
                                mapping_regex: str, force: bool) -> dict:
    """
    For the given IP list ID, select all mappings whose names match mapping_regex,
    then update the specified relationship (either "mappings-whitelist" or "mappings-blacklist")
    by appending mapping references.
    """
    # Select mappings using the library function.
    mappings = al.select_mappings(session, pattern=mapping_regex)
    if not mappings:
        terminate_with_error("No mappings found matching the regex.")

    new_entries = []
    mapping_refs = []
    for mapping in mappings:
        entry = {"type": "mapping", "id": mapping["id"]}
        if entry not in mapping_refs:
            mapping_refs.append(entry)
            new_entries.append(entry)

    if not new_entries:
        print("No new mapping entries to add.")
        return {}

    payload = {"data": mapping_refs}

    if not force:
        print(f"About to update IP list {ip_list_id} on endpoint {relationship_field} with these mapping IDs:")
        for entry in new_entries:
            print(f"  {entry['id']}")
        ans = input("Continue with update? [y/n] ")
        if ans.lower() != "y":
            terminate_with_error("Operation cancelled.")

    endpoint = f"/configuration/ip-address-lists/{ip_list_id}/relationships/{relationship_field}"
    # Expect a 204 response.
    res = al.patch(session, endpoint, payload, exp_code=[204,404])
    if res.status_code == 204:
        print("IP list updated successfully.")
    else:
        print("Failed to update IP list.")
    return {} # the return value is not used.

def main():
    parser = argparse.ArgumentParser(
        description="Manage IP address list relationships on Airlock Gateway."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: list
    parser_list = subparsers.add_parser("list", help="List all IP address lists")
    parser_list.add_argument("-g", "--gateway", required=True,
                             help="Airlock Gateway hostname")
    parser_list.add_argument("-k", "--api-key", help="REST API key for Airlock Gateway")
    parser_list.add_argument("-p", "--port", type=int, default=443,
                             help="Gateway HTTPS port (default: 443)")

    # Subcommand: update
    parser_update = subparsers.add_parser("update", help="Update IP list relationships")
    parser_update.add_argument("-g", "--gateway", required=True,
                               help="Airlock Gateway hostname")
    parser_update.add_argument("-k", "--api-key", help="REST API key for Airlock Gateway")
    parser_update.add_argument("-p", "--port", type=int, default=443,
                               help="Gateway HTTPS port (default: 443)")
    parser_update.add_argument("-i", "--ip-list-id", required=True,
                               help="ID of the IP address list to update")
    group = parser_update.add_mutually_exclusive_group(required=True)
    group.add_argument("--whitelist", action="store_true", help="Append mappings to the whitelist")
    group.add_argument("--blacklist", action="store_true", help="Append mappings to the blacklist")
    parser_update.add_argument("--mapping-regex", required=True,
                               help="Regex pattern to select mappings by name")
    parser_update.add_argument("-y", "--assumeyes", action="store_true",
                               help="Automatically answer yes for confirmation")
    parser_update.add_argument("-c", "--comment", default="Update IP list relationships via REST API",
                               help="Comment for the configuration change")
    args = parser.parse_args()

    global SESSION
    api_key = get_api_key(args)
    SESSION = al.create_session(args.gateway, api_key, args.port)
    if not SESSION:
        sys.exit("Could not create session. Check gateway, port, and API key.")
    register_cleanup_handler()
    al.load_active_config(SESSION)

    if args.command == "list":
        list_ip_lists(SESSION)
    elif args.command == "update":
        rel_field = "mappings-whitelist" if args.whitelist else "mappings-blacklist"
        result = update_ip_list_relationship(SESSION, args.ip_list_id, rel_field, args.mapping_regex, args.assumeyes)
        print(json.dumps(result, indent=4))
        # Confirm change (unless assumeyes is provided) and then save/activate config.
        if not args.assumeyes:
            ans = input("\nContinue to save and activate the new configuration? [y/n] ")
            if ans.lower() != "y":
                terminate_with_error("Operation cancelled.")
        # Try to activate; if activation fails, save the config.
        if al.activate(SESSION, args.comment):
            print("Configuration activated successfully.")
        else:
            al.save_config(SESSION, args.comment)
            print("Configuration saved.")
    else:
        sys.exit("Unsupported command.")

    al.terminate_session(SESSION)

if __name__ == "__main__":
    main()