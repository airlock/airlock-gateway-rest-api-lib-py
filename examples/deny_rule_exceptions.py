#!/usr/bin/env python3

"""
This Python script interacts with Airlock Gateway's REST API for managing the configuration of deny rule groups.
It enables the addition, deletion, and listing of exceptions for deny rule groups through command-line options.

Tested with Airlock Gateway versions 8.3 and 8.4.

**Requirements**

The script uses a Python library for interacting with Airlock Gateway's REST API. This library is available at
https://github.com/airlock/airlock-gateway-rest-api-lib-py/tree/main/src/airlock_gateway_rest_api_lib and should be
placed in the directory airlock_gateway_rest_api_lib:

git clone https://github.com/airlock/airlock-gateway-rest-api-lib-py.git airlock_gateway_rest_api_lib

The script requires a REST API key for Airlock Gateway. This key can be stored in "./api_key.conf" file or it can
directly be provided using the '-k' command-line option.

**Functionality and Commands**
The script contains three main functionalities:

1. add: Add exceptions to a deny rule group.
2. delete: Delete exceptions from a deny rule group.
3. list: List exceptions from a deny rule group.

Each function requires regexes for selecting the deny rule groups and mappings.
The regex patterns can be specified using the '--group-regex' and '--mapping-regex' command-line options.

The add and delete functions require an identifier for the exception (-i command-line option).

Moreover, the add function requires a pattern for the exception ('--parameter-name' or '--header-name' command-line options):
- `--parameter-name`: Specifies a Parameter Name exception.
- `--header-name`:  Specifies a Header Name exception.

**Other important options:**

- `-g` or `--gateway`: Specify the gateway address
- `-p` or `--port`: Specify the HTTPS port for the gateway (default is 443)
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
    ./deny_rule_exceptions.py add -g gateway --mapping-regex '^MyBank.*' --group-regex '.*' --parameter-name '^comment$' -i 'paymentComment1' -c test --activate
Delete the exception 'paymentComment1' from all "MyBank"-mappings in all deny rule groups, activate the configuration:
    ./deny_rule_exceptions.py delete -g gateway --mapping-regex '^MyBank.*' --group-regex '.*'  -i 'paymentComment1' -c test --activate
List exceptions from all "MyBank"-mappings:
    ./deny_rule_exceptions.py list -g gateway --mapping-regex '^MyBank.*' --group-regex '.*'
"""

import argparse
import click
import configparser
import logging
import os
import re
import signal
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.airlock_gateway_rest_api_lib import airlock_gateway_rest_api_lib as al

logging.basicConfig(
    level=logging.DEBUG,
    filename="last_run.log",
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)


def register_cleanup_handler():
    """
    Cleanup handler, will terminate the session if a program error
    occurs at runtime.
    """

    def cleanup(signum, frame):
        al.terminate_session(SESSION)

    for sig in (
        signal.SIGABRT,
        signal.SIGILL,
        signal.SIGINT,
        signal.SIGSEGV,
        signal.SIGTERM,
        signal.SIGQUIT,
    ):
        signal.signal(sig, cleanup)

def terminate_with_error(message=None):
    """
    Terminate the session and exit with an error message.
    """
    if message:
        print(message)
    al.terminate_session(SESSION)
    sys.exit(1)


def get_mappings_and_groups(mapping_regex, group_regex, assumeyes):
    """
    Get selected mappings and groups.
    """

    selected_mappings = al.select_mappings(SESSION, mapping_regex)

    if not selected_mappings:
        terminate_with_error("No mappings selected")

    selected_groups = []
    for dr in al.get_deny_rule_groups(SESSION):
        if re.search(group_regex, dr["attributes"]["name"]):
            selected_groups.append(dr)

    if not selected_groups:
        terminate_with_error("No deny-rule groups selected")

    print("Selected mappings:")
    [print("\t" + mapping["attributes"]["name"]) for mapping in selected_mappings]
    print("Selected deny-rule groups:")
    [print("\t" + group["attributes"]["name"]) for group in selected_groups]
    if not assumeyes and not click.confirm("Do you want to continue?", default=True):
        terminate_with_error("")

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
                    terminate_with_error("Use the delete command to remove these exceptions or choose a different identifier")

                if "headerNamePattern" in exception and exception["headerNamePattern"]["name"] == identifier:
                    print(
                        f'''A header name exception with identifier "{identifier}"
                        already exists in mapping "{mapping["attributes"]["name"]}"
                        and deny-rule group "{group["attributes"]["name"]}"'''
                    )
                    terminate_with_error("Use the delete command to remove these exceptions or choose a different identifier")

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

    terminate_with_error(f'No exceptions with identifier "{identifier}" found')


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
                        name,
                        pattern,
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

    try:
        global SESSION
        SESSION = al.create_session(args.gateway, api_key, args.port)
    except Exception as e:
        sys.exit("There was an error creating the session: are the gateway URL, port and API key valid?")

    register_cleanup_handler()

    # Makes sure the loaded configuration matches the currently active one.
    al.load_active_config(SESSION)

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
            terminate_with_error("Operation cancelled.")

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