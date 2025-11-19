#!/usr/bin/env python3

import logging

from . import airlock_gateway_rest_requests_lib as al


module_logger = logging.getLogger(__name__)


# Built-in deny rule lib calls
def get_mapping_deny_rule_group(gw_session: al.GatewaySession, mapping_id: str,
                                denyrule_group_shortname: str) -> dict:
    '''
    Returns a dictionary object describing the deny rule group in the
    specified Mapping, or None if the mapping or shortname specified were not
    found.
    '''
    path = f'/configuration/mappings/{mapping_id}/deny-rule-groups/{denyrule_group_shortname}'
    res = al.get(gw_session, path, exp_code=[200, 404])
    return res.json().get('data')


def update_mapping_deny_rule_group(gw_session: al.GatewaySession, mapping_id: str,
                                   denyrule_group_shortname: str,
                                   attributes: dict) -> bool:
    '''
    Updates the settings for a deny rule group within a specified mapping.
    Returns True if successful, and False if if the mapping or shortname
    specified were not found.
    '''
    path = f'/configuration/mappings/{mapping_id}/deny-rule-groups/{denyrule_group_shortname}'
    data = {
        "data": {
            "type": "mapping-deny-rule-group",
            "attributes": attributes
        }
    }
    res = al.patch(gw_session, path, data, exp_code=[200, 404])
    return res.status_code == 200


def get_mapping_deny_rule(gw_session: al.GatewaySession, mapping_id: str,
                          denyrule_shortname: str) -> dict:
    '''
    Returns a dictionary object describing the deny rule in the specified
    Mapping, or None if the mapping or shortname specified were not found.
    '''
    path = f'/configuration/mappings/{mapping_id}/deny-rules/{denyrule_shortname}'
    res = al.get(gw_session, path, exp_code=[200, 404])
    return res.json().get("data")


def update_mapping_deny_rule(gw_session: al.GatewaySession, mapping_id: str,
                             denyrule_shortname: str, attributes: dict) -> bool:
    '''
    Updates the settings for a deny rule within a specified mapping. Returns
    True if successful, and False if if the mapping or shortname specified
    were not found.
    '''
    path = f'/configuration/mappings/{mapping_id}/deny-rules/{denyrule_shortname}'
    data = {
        "data": {
            "type": "mapping-deny-rule",
            "attributes": attributes
        }
    }
    res = al.patch(gw_session, path, data, exp_code=[200, 404])
    return res.status_code == 200


def get_deny_rule_groups(gw_session: al.GatewaySession) -> dict:
    '''
    Returns a list of all deny rule groups on the Airlock Host.
    '''

    path = '/configuration/deny-rule-groups'
    res = al.get(gw_session, path, exp_code=200)
    return res.json().get("data")


def get_deny_rule_group(gw_session: al.GatewaySession, short_name: str) -> dict:
    '''
    Returns a dictionary object describing the specified deny rule group,
    or None if it does not exist.
    '''

    path = f'/configuration/deny-rule-groups/{short_name}'
    res = al.get(gw_session, path, exp_code=[200, 404])
    return res.json().get("data")


def get_deny_rules(gw_session: al.GatewaySession) -> list:
    '''
    Returns a list of all deny-rules on the Airlock Host.
    '''

    path = '/configuration/deny-rules'
    res = al.get(gw_session, path, exp_code=200)
    return res.json().get("data")


def get_deny_rule(gw_session: al.GatewaySession, short_name: str) -> dict:
    '''
    Returns a dictionary object describing the specified deny-rule, or None
    if it does not exist.
    '''
    path = f'/configuration/deny-rules/{short_name}'
    res = al.get(gw_session, path, exp_code=[200, 404])
    return res.json().get("data")


# Custom deny rule lib calls
def get_mapping_custom_deny_rule_group(gw_session: al.GatewaySession, mapping_id: str,
                                custom_denyrule_group_id: str) -> dict:
    '''
    Returns a dictionary object describing the custom deny rule group in the
    specified Mapping, or None if the mapping or group id specified were not
    found.
    '''
    path = f'/configuration/mappings/{mapping_id}/custom-deny-rule-groups/{custom_denyrule_group_id}'
    res = al.get(gw_session, path, exp_code=[200, 404])
    return res.json().get('data')


def update_mapping_custom_deny_rule_group(gw_session: al.GatewaySession, mapping_id: str,
                                   custom_denyrule_group_id: str,
                                   attributes: dict) -> bool:
    '''
    Updates the settings for a custom deny rule group within a specified mapping.
    Returns True if successful, and False if the mapping or group id
    specified were not found.
    '''
    path = f'/configuration/mappings/{mapping_id}/custom-deny-rule-groups/{custom_denyrule_group_id}'
    data = {
        "data": {
            "type": "mapping-custom-deny-rule-group",
            "id": custom_denyrule_group_id,
            "attributes": attributes
        }
    }
    res = al.patch(gw_session, path, data, exp_code=[200, 404])
    return res.status_code == 200


def get_mapping_custom_deny_rule(gw_session: al.GatewaySession, mapping_id: str,
                          custom_denyrule_id: str) -> dict:
    '''
    Returns a dictionary object describing the custom deny rule in the specified
    Mapping, or None if the mapping or shortname specified were not found.
    '''
    path = f'/configuration/mappings/{mapping_id}/custom-deny-rules/{custom_denyrule_id}'
    res = al.get(gw_session, path, exp_code=[200, 404])
    return res.json().get("data")


def update_mapping_custom_deny_rule(gw_session: al.GatewaySession, mapping_id: str,
                             custom_denyrule_id: str, attributes: dict) -> bool:
    '''
    Updates the settings for a custom deny rule within a specified mapping. Returns
    True if successful, and False if if the mapping or shortname specified
    were not found.
    '''
    path = f'/configuration/mappings/{mapping_id}/custom-deny-rules/{custom_denyrule_id}'
    data = {
        "data": {
            "type": "mapping-custom-deny-rule",
            "id": custom_denyrule_id,
            "attributes": attributes
        }
    }
    res = al.patch(gw_session, path, data, exp_code=[200, 404])
    return res.status_code == 200

def get_custom_deny_rule_groups(gw_session: al.GatewaySession) -> list:
    '''
    Returns a list of all custom deny rule groups on the Airlock Host.
    '''

    path = '/configuration/custom-deny-rule-groups'
    res = al.get(gw_session, path, exp_code=200)
    return res.json().get("data")

def get_custom_deny_rule_group(gw_session: al.GatewaySession, custom_denyrule_group_id: str) -> dict:
    '''
    Returns a dictionary object describing the specified custom deny rule group,
    or None if it does not exist.
    '''

    path = f'/configuration/custom-deny-rule-groups/{custom_denyrule_group_id}'
    res = al.get(gw_session, path, exp_code=[200, 404])
    return res.json().get("data")


def get_custom_deny_rules(gw_session: al.GatewaySession) -> list:
    '''
    Returns a list of all custom deny-rules on the Airlock Host.
    '''

    path = '/configuration/custom-deny-rules'
    res = al.get(gw_session, path, exp_code=200)
    return res.json().get("data")


def get_custom_deny_rule(gw_session: al.GatewaySession, custom_denyrule_id: str) -> dict:
    '''
    Returns a dictionary object describing the specified custom deny-rule, or None
    if it does not exist.
    '''
    path = f'/configuration/custom-deny-rules/{custom_denyrule_id}'
    res = al.get(gw_session, path, exp_code=[200, 404])
    return res.json().get("data")


# Functions to switch logOnly mode on or off
# for both built-in and custom deny rules and deny rule groups
def toggle_built_in_deny_rule_logonly(gw_session: al.GatewaySession, mapping_id: str,
                                   denyrule_shortname: str, log_only: bool) -> bool:
    '''
    Sets the logOnly attribute for a built-in deny rule on a specified mapping.
    Returns True if successful, False otherwise.
    '''
    return update_mapping_deny_rule(gw_session, mapping_id, denyrule_shortname, {"logOnly": log_only})


def toggle_custom_deny_rule_logonly(gw_session: al.GatewaySession, mapping_id: str,
                                 custom_denyrule_id: str, log_only: bool) -> bool:
    '''
    Sets the logOnly attribute for a custom deny rule on a specified mapping.
    Returns True if successful, False otherwise.
    '''
    return update_mapping_custom_deny_rule(gw_session, mapping_id, custom_denyrule_id, {"logOnly": log_only})


def toggle_builtin_deny_rule_group_logonly(gw_session: al.GatewaySession, mapping_id: str,
                                       group_shortname: str, log_only: bool) -> bool:
    '''
    Sets the logOnly attribute for a built-in deny rule group on a specified mapping and all its rules.
    Returns True if all is successful, False if atleast one update was unsuccessful.
    '''
    res = update_mapping_deny_rule_group(gw_session, mapping_id, group_shortname, {"logOnly": log_only})
    if not res:
        return res

    # Get all rules in group
    group_obj = get_deny_rule_group(gw_session, group_shortname)
    all_shortNames_in_group = set()
    for rules in group_obj["attributes"]["denyRules"]:
        for shortName in rules["shortNames"]:
            all_shortNames_in_group.add(shortName)

    # Also update all rules in group
    for shortName in all_shortNames_in_group:
        res = toggle_built_in_deny_rule_logonly(gw_session, mapping_id, shortName, log_only) and res
    return res


def toggle_custom_deny_rule_group_logonly(gw_session: al.GatewaySession, mapping_id: str,
                                      custom_denyrule_group_id: str, log_only: bool) -> bool:
    '''
    Sets the logOnly attribute for a custom deny rule group on a specified mapping.
    Returns True if successful, False otherwise.
    '''
    res = update_mapping_custom_deny_rule_group(gw_session, mapping_id, custom_denyrule_group_id, {"logOnly": log_only})
    if not res:
        return res

    # Get all rules in group
    group_obj = get_custom_deny_rule_group(gw_session, custom_denyrule_group_id)
    all_rule_ids_in_group = set()
    for rules in group_obj["relationships"]["custom-deny-rules"]["data"]:
        for rule_id in rules["id"]:
            all_rule_ids_in_group.add(rule_id)

    # Also update all rules in group
    for rule_id in all_rule_ids_in_group:
        res = toggle_custom_deny_rule_logonly(gw_session, mapping_id, rule_id, log_only) and res
    return res
