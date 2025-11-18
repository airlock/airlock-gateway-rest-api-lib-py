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

import argparse
import logging
import re

from ..src.rest_api_lib import airlock_gateway_rest_requests_lib as al
from ..src.rest_api_lib import denyrules as dr
from .utils import terminate_session_with_error, setup_session, activate_or_save, confirm_prompt, get_api_key

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
module_logger = logging.getLogger(__name__)


def get_selected_mappings(session, mapping_regex):
    selected_mappings = al.select_mappings(session, pattern=mapping_regex)
    if not selected_mappings:
        terminate_session_with_error(session, "No mappings selected")
    return selected_mappings


def get_selected_groups(session, group_regex):
    selected_groups = []
    for dr_group in dr.get_deny_rule_groups(session):
        if re.search(group_regex, dr_group["attributes"]["name"]):
            selected_groups.append(dr_group)
    return selected_groups


def get_selected_custom_groups(session, group_regex):
    selected_groups = []
    for dr_group in dr.get_custom_deny_rule_groups(session):
        if re.search(group_regex, dr_group["attributes"]["name"]):
            selected_groups.append(dr_group)
    return selected_groups


def update_logonly_mode(session, mapping_regex, group_regex, log_only, assumeyes):
    selected_mappings = get_selected_mappings(session, mapping_regex)
    selected_groups = get_selected_groups(session, group_regex)
    selected_custom_groups = get_selected_custom_groups(session, group_regex)

    if not assumeyes and confirm_prompt("Show selected mappings and deny-rule groups?"):
        print("Selected mappings:")
        for m in selected_mappings:
            print("\t" + m["attributes"]["name"])
        print("Selected built-in deny rule groups:")
        for g in selected_groups:
            print("\t" + g["attributes"]["name"])
        print("Selected custom deny rule groups:")
        for g in selected_custom_groups:
            print("\t" + g["attributes"]["name"])

    if not assumeyes and not confirm_prompt("Do you want to continue and update the log-only mode?"):
        terminate_session_with_error(session, "Operation cancelled by user.")

    for mapping in selected_mappings:
        for group in selected_groups:
            # Patch the deny rule group: update logOnly attributes.
            dr.toggle_builtin_deny_rule_group_logonly(session, mapping["id"], group["id"], log_only)
        for group in selected_custom_groups:
            dr.toggle_custom_deny_rule_group_logonly(session, mapping["id"], group["id"], log_only)


def setup_argparser():
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
    parser.add_argument("-l", "--log-level", help="Set the logging level (debug, info, warning, error, critical). Default: info", default="info")

    return parser


def main():
    parser = setup_argparser()
    args = parser.parse_args()

    if args.log_level:
        numeric_level = getattr(logging, args.log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError('Invalid log level: %s' % args.log_level)
        logging.getLogger().setLevel(numeric_level)
        module_logger.setLevel(numeric_level)

    api_key = get_api_key(args)
    module_logger.debug("Successfully retrieved API key.")

    gw_session = setup_session(args.gateway, api_key, args.port)

    # Determine desired logOnly mode
    log_only = not args.disable
    if log_only:
        module_logger.info("Set log-only mode to 'ON'")
    else:
        module_logger.warning("Set log-only mode to 'OFF'")

    # Update log-only mode for each mapping and each deny rule group selected
    update_logonly_mode(gw_session, args.mapping_regex, args.group_regex, log_only, args.assumeyes)

    # Prepare change summary
    affected_names = [m["attributes"]["name"] for m in al.select_mappings(gw_session, pattern=args.mapping_regex)]
    change_info = f"Log‑only mode {'disabled' if args.disable else 'enabled'} for deny rule groups on mappings: " + ", ".join(affected_names)
    print("\n" + change_info)

    # Confirm change (unless assumeyes is given) and then save/activate config
    activate_or_save(gw_session, args.comment, args.assumeyes, args.activate)

    al.terminate_session(gw_session)

if __name__ == "__main__":
    main()
