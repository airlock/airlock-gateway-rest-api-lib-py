#!/usr/bin/env python3
# coding=utf-8
"""
IP List Management on Airlock Gateway Versions 8.3.2 and later.

This script supports three operations:
  1. list   : Lists all IP address lists (with IDs and IPs).

  2. update : Updates an IP list's relationships. Two update modes are supported:
       --blacklist: Assign an IP list as a blacklist to one or more mappings by updating the IP list's blacklist relationship.
                    The specified mappings are appended to the existing blacklist set.
                    
       --whitelist: Assign an IP list as a whitelist for one or more mappings by modifying the mapping's 
                    ipRules.ipAddressWhitelists attribute. If an entry for the specified path exists, 
                    the IP list is added to the existing set of whitelists. Otherwise, a new whitelist entry is created.

After performing the updates, the script prompts (unless --assumeyes is given) and then saves the configuration by default.
If the --activate flag is provided, the script will attempt to activate the configuration instead of just saving it.

API key is provided via the -k/--api-key flag or read from an "api_key.conf" file (with a [KEY] section).

Usage Examples:
  List IP address lists:
      ./ip_list_relationships.py list -g mywaf.example.com -k YOUR_API_KEY

  Update blacklist:
      ./ip_list_relationships.py update -g mywaf.example.com -i 3 --blacklist --mapping-regex '^cust' -y -c "Add blacklist entries" -k YOUR_API_KEY

  Update whitelist (requires --path-pattern):
      ./ip_list_relationships.py update -g mywaf.example.com -i 3 --whitelist --mapping-regex '^cust' --path-pattern 'testpath' -c "Add whitelist entries" -k YOUR_API_KEY

By default, configuration changes are saved; add the --activate flag to activate them.
"""

import sys
import os
import argparse
import configparser
import logging
import json

from ..src import rest_api_lib as al
from .utils import terminate_session_with_error, setup_session

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
module_logger = logging.getLogger(__name__)

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

def update_blacklist(session, ip_list_id: str, mapping_regex: str, force: bool) -> dict:
    """
    Updates the IP blacklist for the given IP list by selecting mappings
    matching the provided regex.
    """
    # Retrieve selected mappings by regex.
    selected_mappings = al.select_mappings(session, pattern=mapping_regex)
    if not selected_mappings:
        terminate_session_with_error(SESSION, "No mappings found matching the regex.")

    # Build the payload with mapping references.
    mapping_refs = [{"type": "mapping", "id": mapping["id"]} for mapping in selected_mappings]
    mapping_info = [(mapping["id"], mapping["attributes"]["name"]) for mapping in selected_mappings]

    if not force:
        print(f"About to update IP list {ip_list_id} blacklist relationship with these mappings:")
        for mapping_id, mapping_name in mapping_info:
            print(f"  ID: {mapping_id}, Name: {mapping_name}")
        ans = input("Continue with update? [y/n] ")
        if ans.lower() != "y":
            terminate_session_with_error(SESSION, "Operation cancelled.")

    endpoint = f"/configuration/ip-address-lists/{ip_list_id}/relationships/mappings-blacklist"
    payload = {"data": mapping_refs}
    res = al.patch(session, endpoint, payload, exp_code=[204,404])
    if res.status_code == 204:
        print("IP blacklist updated successfully.")
    else:
        print("Failed to update IP blacklist.")

    return {"updated_mappings": [name for _, name in mapping_info]}

def update_whitelist(session, ip_list_id: str, mapping_regex: str, path_pattern: str, force: bool) -> dict:
    """
    For all mappings matching the provided regex, update each mapping’s
    ipRules.ipAddressWhitelists by either appending a new whitelist entry or
    extending an existing entry.
    
    If an entry with the same path pattern exists, its ipAddressListIds array is
    extended with the given ip_list_id (if not already present).
    Returns a result dictionary containing a list of updated mapping names.
    """
    selected_mappings = al.select_mappings(session, pattern=mapping_regex)
    if not selected_mappings:
        terminate_session_with_error(SESSION, "No mappings found matching the regex.")

    updated = []
    for mapping in selected_mappings:
        mapping_id = mapping["id"]
        m = al.get_mapping_by_id(session, mapping_id)
        attrs = m.get("attributes", {})
        ip_rules = attrs.get("ipRules", {})
        whitelist = ip_rules.get("ipAddressWhitelists", {})
        if not whitelist or not isinstance(whitelist, dict):
            whitelist = {"logOnly": False, "pathWhitelists": []}
        path_whitelists = whitelist.get("pathWhitelists", [])

        ip_id = int(ip_list_id)
        found_entry = None
        for entry in path_whitelists:
            if entry.get("pathPattern", {}).get("pattern") == path_pattern:
                found_entry = entry
                break

        if found_entry:
            current_ids = found_entry.get("ipAddressListIds", [])
            if ip_id not in current_ids:
                current_ids.append(ip_id)
                found_entry["ipAddressListIds"] = current_ids
                print(f"Mapping '{attrs.get('name')}' (ID: {mapping_id}): Extended whitelist entry for path '{path_pattern}' with IP list ID {ip_list_id}.")
            else:
                print(f"Mapping '{attrs.get('name')}' (ID: {mapping_id}) already contains IP list ID {ip_list_id} for path '{path_pattern}'.")
        else:
            new_entry = {
                "enabled": True,
                "pathPattern": {
                    "pattern": path_pattern,
                    "caseIgnored": False,
                    "inverted": False
                },
                "ipAddressListIds": [ip_id]
            }
            path_whitelists.append(new_entry)
            print(f"Mapping '{attrs.get('name')}' (ID: {mapping_id}): Added new whitelist entry for path '{path_pattern}' with IP list ID {ip_list_id}.")
        
        whitelist["pathWhitelists"] = path_whitelists
        ip_rules["ipAddressWhitelists"] = whitelist
        update_attrs = {"ipRules": ip_rules}
        if al.update_mapping(session, mapping_id, update_attrs):
            updated.append(attrs.get("name"))
            print(f"Mapping '{attrs.get('name')}' (ID: {mapping_id}) updated successfully.")
        else:
            print(f"Failed to update mapping '{attrs.get('name')}' (ID: {mapping_id}).")
    
    return {"updated_mappings": updated}

def main():
    parser = argparse.ArgumentParser(
        description="Manage IP address list relationships on Airlock Gateway.\n"
                    "By default, configuration changes are saved; use --activate to activate them."
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
    group.add_argument("--blacklist", action="store_true",
                       help="Update the blacklist (uses /relationships/mappings-blacklist)")
    group.add_argument("--whitelist", action="store_true",
                       help="Update the whitelist (updates each mapping's ipRules.ipAddressWhitelists)")
    parser_update.add_argument("--mapping-regex", required=True,
                               help="Regex pattern to select mappings by name")
    parser_update.add_argument("--path-pattern",
                               help="(Required for whitelist updates) Path pattern for the whitelist entry")
    parser_update.add_argument("-y", "--assumeyes", action="store_true",
                               help="Automatically confirm without prompting")
    parser_update.add_argument("-c", "--comment", default="Update IP list relationships via REST API",
                               help="Comment for the configuration change")
    parser_update.add_argument("--activate", action="store_true",
                               help="Activate configuration (default: save configuration)")
    args = parser.parse_args()

    api_key = get_api_key(args)
    global SESSION
    SESSION = setup_session(args.gateway, api_key, args.port)

    if args.command == "list":
        list_ip_lists(SESSION)
    elif args.command == "update":
        if args.blacklist:
            result = update_blacklist(SESSION, args.ip_list_id, args.mapping_regex, args.assumeyes)
            print(json.dumps(result, indent=4))
        elif args.whitelist:
            if not args.path_pattern:
                sys.exit("For whitelist updates, --path-pattern is required.")
            result = update_whitelist(SESSION, args.ip_list_id, args.mapping_regex, args.path_pattern, args.assumeyes)
            print(json.dumps(result, indent=4))

        if not args.assumeyes:
            prompt_text = "\nContinue to " + ("save and activate " if args.activate else "save ") + "the new configuration? [y/n] "
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
    else:
        sys.exit("Unsupported command.")

    al.terminate_session(SESSION)

if __name__ == "__main__":
    main()
