#!/usr/bin/env python3

import logging

from . import airlock_gateway_rest_requests_lib as al


module_logger = logging.getLogger(__name__)


#builtin

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


#### lib calls for custom deny rules
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
            "type": "mapping-deny-rule",
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
