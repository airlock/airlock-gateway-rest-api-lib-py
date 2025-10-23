#!/usr/bin/env python3

"""
This Python script interacts with Airlock Gateway's REST API for managing the configuration of deny rule groups.
It enables the addition, deletion, and listing of exceptions for deny rule groups through command-line options.

**Important:** This script manages exceptions exclusively for built-in deny rule groups.
It does not support custom deny rule groups. Custom deny rule groups use a different REST endpoint and thus require separate handling.

Tested with Airlock Gateway versions 8.3 and 8.4.

The script requires a REST API key for Airlock Gateway. This key can be stored in "./api_key.conf" file or it can
directly be provided using the '-k' command-line option.

**Functionality and Commands**
The script contains three main functionalities:

1. add: Add exceptions to a deny rule group on matching mappings.
2. delete: Delete exceptions from a deny rule group on matching mappings.
3. list: List exceptions from a deny rule group on matching mappings.

Command-line arguments: 
- `-g` or `--gateway`: Specify the gateway address
- `-p` or `--port`: Specify the HTTPS port for the gateway (default is 443)
- `--group-regex`: Regex to select deny rule groups
- `--mapping-regex`: Regex to select mappings
- `--parameter-name`: Specify a Parameter Name Pattern.
- `--header-name`:  Specify a Header Name Pattern.
- `--mapping-regex`:  Select mappings by using a regular expression on the mapping name.
- `--group-regex`:  Select deny rule groups by using a regular expression on the group name.
- `-k` or `--api-key`: REST API key for Airlock Gateway.
- `-i` or `--identifier`: Identifier for the exception.
- `-c` or `--comment`: Comment for the change (default is 'Modify exceptions through REST API')
- `-y` or `--assumeyes`: Automatically answer yes for all questions.
- `--activate`: Activate the configuration changes on the gateway, by default the changes will be saved but not activated.

**Examples**
Add an exception for the parameter "comment" to all parameter value deny-rule groups on all "MyBank"-mappings:
    ./deny_rule_exceptions.py add -g mywaf.example.com --mapping-regex '^MyBank.*' --group-regex '.*' --parameter-name '^comment$' -i 'paymentComment1' -c test --activate
Delete the exception 'paymentComment1' from all "MyBank"-mappings in all deny rule groups, activate the configuration:
    ./deny_rule_exceptions.py delete -g mywaf.example.com --mapping-regex '^MyBank.*' --group-regex '.*'  -i 'paymentComment1' -c test --activate
List exceptions from all "MyBank"-mappings:
    ./deny_rule_exceptions.py list -g mywaf.example.com --mapping-regex '^MyBank.*' --group-regex '.*'
"""

import argparse
import configparser
import logging
import os
import re
import sys

import airlock_gateway_rest_api_lib as al
from .utils import terminate_session_with_error, setup_session, confirm_prompt

logging.basicConfig(
    level=logging.DEBUG,
    filename="last_run.log",
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
module_logger = logging.getLogger(__name__)

SESSION = None

def get_mappings_and_groups(mapping_regex, group_regex, assumeyes):
    """
    Get selected mappings and groups.
    """

    selected_mappings = al.select_mappings(SESSION, mapping_regex)

    if not selected_mappings:
        terminate_session_with_error(SESSION, "No mappings selected")

    selected_groups = []
    for dr in al.get_deny_rule_groups(SESSION):
        if re.search(group_regex, dr["attributes"]["name"]):
            selected_groups.append(dr)

    if not selected_groups:
        terminate_session_with_error(SESSION, "No deny-rule groups selected")

    print("Selected mappings:")
    [print("\t" + mapping["attributes"]["name"]) for mapping in selected_mappings]
    print("Selected deny-rule groups:")
    [print("\t" + group["attributes"]["name"]) for group in selected_groups]
    if not assumeyes and not confirm_prompt("Do you want to continue?", default=True):
        terminate_session_with_error(SESSION)

    return selected_mappings, selected_groups


def add_exception(mapping_regex, group_regex, parameter_name_pattern, header_name_pattern, identifier, assumeyes):
    """
    Add an exception to a deny rule group and mapping.
    """

    selected_mappings, selected_groups = get_mappings_and_groups(mapping_regex, group_regex, assumeyes)

    for mapping in selected_mappings:
        for group in selected_groups:
            group_data = al.get_mapping_deny_rule_group(SESSION, mapping["id"], group["id"])
            for exception in group_data["attributes"]["exceptions"]:
                if "parameterNamePattern" in exception and exception["parameterNamePattern"]["name"] == identifier:
                    print(
                        f'''A parameter name exception with identifier "{identifier}"
                        already exists in mapping "{mapping["attributes"]["name"]}"
                        and deny-rule group "{group["attributes"]["name"]}"'''
                    )
                    terminate_session_with_error(SESSION, "Use the delete command to remove these exceptions or choose a different identifier")

                if "headerNamePattern" in exception and exception["headerNamePattern"]["name"] == identifier:
                    print(
                        f'''A header name exception with identifier "{identifier}"
                        already exists in mapping "{mapping["attributes"]["name"]}"
                        and deny-rule group "{group["attributes"]["name"]}"'''
                    )
                    terminate_session_with_error(SESSION, "Use the delete command to remove these exceptions or choose a different identifier")

    if parameter_name_pattern:
        pattern = "parameterNamePattern"
        exception_regex = parameter_name_pattern
    else:
        pattern = "headerNamePattern"
        exception_regex = header_name_pattern

    exception = {
        "enabled": True,
        f"{pattern}": {
            "enabled": True,
            "pattern": f"{exception_regex}",
            "name": f"{identifier}",
        },
    }
    for mapping in selected_mappings:
        for group in selected_groups:
            group_data = al.get_mapping_deny_rule_group(SESSION, mapping["id"], group["id"])
            exceptions = group_data["attributes"]["exceptions"] + [exception]
            al.update_mapping_deny_rule_group(SESSION, mapping["id"], group["id"], {"exceptions": exceptions})


def delete_exception(mapping_regex, group_regex, identifier, assumeyes):
    """
    Delete an exception from a deny rule group and mapping.
    """
    deleted_something = False
    selected_mappings, selected_groups = get_mappings_and_groups(mapping_regex, group_regex, assumeyes)

    for mapping in selected_mappings:
        for group in selected_groups:
            group_ids = SESSION, mapping["id"], group["id"]
            deny_rule_group_data = al.get_mapping_deny_rule_group(*group_ids)

            exceptions = deny_rule_group_data["attributes"]["exceptions"]
            pattern = "parameterNamePattern"
            for exception in exceptions:
                if pattern in exception and exception[pattern]["name"] == identifier:
                    exceptions.remove(exception)
                    deleted_something = True
            pattern = "headerNamePattern"
            for exception in exceptions:
                if pattern in exception and exception[pattern]["name"] == identifier:
                    exceptions.remove(exception)
                    deleted_something = True

            al.update_mapping_deny_rule_group(*group_ids, {"exceptions": exceptions})

    if deleted_something:
        return

    terminate_session_with_error(SESSION, f'No exceptions with identifier "{identifier}" found')


def list_exceptions(mapping_regex, group_regex):
    """
    List exceptions for specific deny rule groups and mapping.
    """
    selected_mappings = al.select_mappings(SESSION, mapping_regex)
    selected_groups = []
    for dr in al.get_deny_rule_groups(SESSION):
        if re.search(group_regex, dr["attributes"]["name"]):
            selected_groups.append(dr)

    table = []
    for mapping in selected_mappings:
        for group in selected_groups:
            group_ids = SESSION, mapping["id"], group["id"]
            deny_rule_group_data = al.get_mapping_deny_rule_group(*group_ids)
            exceptions = deny_rule_group_data["attributes"]["exceptions"]
            for exception in exceptions:
                name = None
                pattern = None
                # TODO: robustness for all exception types
                if "parameterNamePattern" in exception:
                    name = exception["parameterNamePattern"]["name"]
                    pattern = exception["parameterNamePattern"]["pattern"]
                    type = "Parameter"
                if "headerNamePattern" in exception:
                    name = exception["headerNamePattern"]["name"]
                    pattern = exception["headerNamePattern"]["pattern"]
                    type = "Header"
                table.append(
                    [
                        mapping["attributes"]["name"],
                        group["attributes"]["name"],
                        type,
                        name if name else "<n/a>",
                        pattern if pattern else "<n/a>",
                    ]
                )

    if table:
        print("Exceptions:")
        # print the table, without using tabulate
        for row in table:
            print("--------------------")
            print(f"Mapping: {row[0]}")
            print(f"Group: {row[1]}")
            print(f"Type: {row[2]}")
            print(f"Name: {row[3]}")
            print(f"Pattern: {row[4]}")


def main():
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(required=True)
    parser_add = subparsers.add_parser("add", help="Add exceptions")
    parser_del = subparsers.add_parser("delete", help="Delete exceptions")
    parser_lst = subparsers.add_parser("list", help="List exceptions")

    subparsers.required = True
    subparsers.dest = "command"

    parser_add.add_argument("--group-regex", help="Identifier for the deny rule", required=True)
    parser_add.add_argument("--mapping-regex", help="Pattern selecting mapping names", required=True)
    parser_add.add_argument("-g", "--gateway", help="Gateway to activate config on", required=True)
    parser_add.add_argument("-k", "--api-key", help="REST API key")
    parser_add.add_argument("-p", "--port", help="Gateway HTTPS port", type=int, default=443)

    parser_del.add_argument("--group-regex", help="Identifier for the deny rule", required=True)
    parser_del.add_argument("--mapping-regex", help="Pattern selecting mapping names", required=True)
    parser_del.add_argument("-g", "--gateway", help="Gateway to activate config on", required=True)
    parser_del.add_argument("-k", "--api-key", help="REST API key")
    parser_del.add_argument("-p", "--port", help="Gateway HTTPS port", type=int, default=443)

    parser_lst.add_argument("--group-regex", help="Identifier for the deny rule", required=True)
    parser_lst.add_argument("--mapping-regex", help="Pattern selecting mapping names", required=True)
    parser_lst.add_argument("-g", "--gateway", help="Gateway to activate config on", required=True)
    parser_lst.add_argument("-k", "--api-key", help="REST API key")
    parser_lst.add_argument("-p", "--port", help="Gateway HTTPS port", type=int, default=443)

    parse_pattern = parser_add.add_mutually_exclusive_group(required=True)
    parse_pattern.add_argument("--header-name", help="Header Name Pattern")
    parse_pattern.add_argument("--parameter-name", help="Parameter Name Pattern")

    parser_add.add_argument("--activate", help="Activate configuration", action="store_true")
    parser_add.add_argument("-c", "--comment", help="Comment for the change", default="Modify exceptions with REST API")
    parser_add.add_argument("-i", "--identifier", help="Identifier for the exception", required=True)
    parser_add.add_argument("-y", "--assumeyes", help="Automatically answer yes for all questions", action="store_true")

    parser_del.add_argument("--activate", help="Activate configuration", action="store_true")
    parser_del.add_argument("-c", "--comment", help="Comment for the change", default="Modify exceptions with REST API")
    parser_del.add_argument("-i", "--identifier", help="Identifier for the exception", required=True)
    parser_del.add_argument("-y", "--assumeyes", help="Automatically answer yes for all questions", action="store_true")

    args = parser.parse_args()

    if args.api_key:
        api_key = args.api_key
    elif os.path.exists("api_key.conf"):
        config = configparser.ConfigParser()
        config.read("api_key.conf")
        api_key = config.get("KEY", "api_key")
    else:
        sys.exit("API key needed, either with -k flag or in a api_key.conf file")

    global SESSION
    SESSION = setup_session(args.gateway, api_key, args.port)

    # Save backup of original config file
    # al.export_current_config_file(session, "./config.zip")

    if args.command == "list":
        list_exceptions(args.mapping_regex, args.group_regex)
        al.terminate_session(SESSION)
        return
    
    if args.command == "add":
        # Corrected the argument names here
        add_exception(args.mapping_regex, args.group_regex, args.parameter_name, args.header_name,
                      args.identifier, args.assumeyes)
    elif args.command == "delete":
        delete_exception(args.mapping_regex, args.group_regex, args.identifier, args.assumeyes)

    if not args.assumeyes:
        prompt_text = "\nContinue to activate the new configuration? [y/n] " if args.activate else "\nContinue to save the new configuration? [y/n] "
        ans = input(prompt_text)
        if ans.lower() != "y":
            terminate_session_with_error(SESSION, "Operation cancelled.")

    # If --activate flag is provided, attempt to activate; otherwise, simply save.
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