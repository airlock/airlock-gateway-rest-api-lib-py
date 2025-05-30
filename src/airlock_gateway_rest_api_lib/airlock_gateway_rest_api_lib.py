#!/usr/bin/env python3
# Adapted from Frank Meier's personal Airlock
# REST Python library in February 2022

"""Library for easier use of Airlock's REST API.

This library is not part of the official Airlock product delivery and
Ergon/Airlock does not provide support for it. Best effort support may
be provided by the contributor of the library.

This library uses the `requests` library to perform standard HTTP requests
to Airlock Gateway REST endpoints.

404 response status codes are handled by this library, i.e. if a provided ID
or REST endpoint cannot be found, no exceptions will be raised.\n
For all other unexpected response status codes, e.g. malformed data is used to
generate a new mapping, a custom Exception named `AirlockGatewayRestError` is
raised.\n
In addition to that, any Exception raised by the `requests` library is not
handled by this library, so for example if network problems occur,
multiple Errors will be raised by the underlying library.
"""


import xml.etree.ElementTree as ET
from io import BytesIO
from typing import Tuple, Union
from zipfile import ZipFile
import logging
import re
import zipfile
import json
import requests
import urllib3
from requests import Session, Response


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
LIBRARY_COMPATIBILITY_VERSIONS = ['8.2', '8.3', '8.4']


class AirlockGatewayRestError(Exception):
    '''
    Custom Exception to inform Library users that an unexpected status
    has been returbned by the performed REST call.
    '''

    def __init__(self, status_code, message):
        self.status_code = status_code
        self.message = "Status code " + str(status_code) + ": " + message
        super().__init__(self.message)


class GatewaySession:
    '''Wrapper class for a REST Session with Airlock Gateway.

    Uses the `requests` Python library to perform HTTP.
    '''

    def __init__(self, host_name: str, ses: Session, port: int = None):
        self.port = port if port else 443
        self.host = f"{host_name}:{port}" if port != 443 else host_name
        self.host_name = host_name
        self.ses = ses
    host = None
    host_name = None
    port = 443
    ses = None

    def add_headers(self, headers: dict):
        '''
        Adds the given `headers` to the REST Session.\n
        If one of the given `headers` was already set, it will be
        overwritten.
        '''
        self.ses.headers.update(headers)

    def get_session(self) -> Session:
        '''
        Returns the internal Session object of this object.
        '''
        return self.ses


def get_version(gw_session: GatewaySession) -> Union[str, None]:
    '''
    Returns the major and minor realease number (for example 8.0) of the
    Airlock Host, or None if the version could not be retrieved.\n
    '''
    res = get(gw_session, "/system/status/node", exp_code=200)
    return res.json()["data"]["attributes"].get("version")


def _res_expect_handle(res: Response, exp_code: Union[list, int]) -> None:
    '''
    Raises a custom exception if the responses' status code
    is not in the list of expected status code.
    '''
    if exp_code:
        if not isinstance(exp_code, list):
            exp_code = [exp_code]
        if res.status_code not in exp_code:
            msg = f"Unexpected status code {res.status_code} was returned"
            logging.error(msg)
            raise AirlockGatewayRestError(res.status_code, res.text)


# pylint: disable = R0913
def req_raw(gw_session: GatewaySession, method: str, path: str,
            ctype: str = None, data=None,
            exp_code: Union[list, int] = None) -> Response:
    '''
    Performs a request to the Airlock Host at the specified path
    with the given method. Optionally, the Content Type, payload and
    expected response status codes can be specified.\n
    Returns the response object to the performed request.
    '''
    uri = f'https://{gw_session.host}/airlock/rest{path}'
    logging.info("Performing a %s request at URI: %s", method, uri)
    headers = None
    if ctype:
        headers = {'Content-Type': ctype}
    res = gw_session.ses.request(method, uri, data=data, headers=headers,
                                 verify=False)
    _res_expect_handle(res, exp_code)
    return res


def req(gw_session: GatewaySession, method: str,
        path: str, body_dict: dict = None,
        exp_code: Union[list, int] = None) -> Response:
    '''
    Performs a request to the Airlock Host at the specified path
    with the given method. Optionally, the JSON payload and
    expected response status codes can be specified.\n
    Returns the response object to the performed request.
    '''
    uri = f'https://{gw_session.host}/airlock/rest{path}'
    logging.info("Performing a %s request at URI: %s ", method, uri)
    if isinstance(body_dict, dict):
        logging.debug("JSON payload of request:")
        logging.debug(json.dumps(body_dict, indent=4))
    res = gw_session.ses.request(method, uri, json=body_dict)
    _res_expect_handle(res, exp_code)
    return res


def post(gw_session: GatewaySession, path: str, body_dict: dict = None,
         exp_code: Union[list, int] = None) -> Response:
    '''
    Performs a POST request to the Airlock Host at the specified path.
    Optionally, the JSON payload and expected response status codes
    can be specified.\n
    Returns the Response object to the performed request.
    '''
    return req(gw_session, 'POST', path, body_dict, exp_code)


def patch(gw_session: GatewaySession, path: str, body_dict: dict,
          exp_code: Union[list, int] = None) -> Response:
    '''
    Performs a PATCH request to the Airlock Host at the specified path.
    Optionally, the JSON payload and expected response status codes
    can be specified.\n
    Returns the Response object to the performed request.
    '''
    return req(gw_session, 'PATCH', path, body_dict, exp_code)


def put(gw_session: GatewaySession, path: str, body_dict: dict,
        exp_code: Union[list, int] = None) -> Response:
    '''
    Performs a PUT request to the Airlock Host at the specified path.
    Optionally, the JSON payload and expected response status codes
    can be specified.\n
    Returns the Response object to the performed request.
    '''
    return req(gw_session, 'PUT', path, body_dict, exp_code)


def delete(gw_session: GatewaySession, path: str, body_dict: dict = None,
           exp_code: Union[list, int] = None) -> Response:
    '''
    Performs a DELETE request to the Airlock Host at the specified path.
    Optionally, the expected response status codes can be specified.\n
    Returns the Response object to the performed request.
    '''
    return req(gw_session, 'DELETE', path, body_dict, exp_code)


def get(gw_session: GatewaySession, path: str,
        exp_code: Union[list, int] = None) -> Response:
    '''
    Performs a GET request to the Airlock Host at the specified path.
    Optionally, the expected response status codes can be specified.\n
    Returns the Response object to the performed request.
    '''
    return req(gw_session, 'GET', path, None, exp_code)


def create_session(host: str, api_key: str, port: int = 443) -> GatewaySession:
    '''
    Creates a new session with the given host.

    Returns the generated GatewaySession object,
    or None if the Session couldn't be started.
    '''
    ses = requests.Session()
    ses.verify = False
    gw_session = GatewaySession(host, ses, port)
    gw_session.add_headers({"Authorization": f"Bearer {api_key}"})
    logging.info("Starting the REST Session with Host %s", host)
    res = post(gw_session, "/session/create", exp_code=[200, 404])
    if res.status_code == 200:
        version = get_version(gw_session)
        if version:
            if not any(version.startswith(v) for v in LIBRARY_COMPATIBILITY_VERSIONS):
                logging.warning("You are using Airlock version %s while this \
                                library is tested for Airlock versions %s. Some Rest \
                                calls might not work on this Airlock version", 
                                version, ", ".join(LIBRARY_COMPATIBILITY_VERSIONS))
        else:
            logging.warning('The Airlock version could not be determined, \
this library version might be incompatible with this Airlock Host')
        return gw_session
    return None


def create_session_from_cookie(host: str, jsessionid: str, port: int = 443) -> GatewaySession:
    '''
    Retrieves an existing Gateway Session from the JSESSIONID Cookie.\n
    Returns the generated GatewaySession object.
    '''
    ses = requests.Session()
    ses.verify = False
    cookie = requests.cookies.create_cookie("JSESSIONID", jsessionid)
    ses.cookies.set_cookie(cookie)
    return GatewaySession(host, ses, port)


def _get_cookies(gw_session: GatewaySession) -> dict:
    '''
    Returns a dictionary object mapping all Cookie names in a GatewaySession
    to their value.
    '''
    return {x.name: x for x in gw_session.ses.cookies}


def get_jsession_id(gw_session: GatewaySession) -> str:
    '''
    Returns the value of the JSESSIONID Cookie,
    or None if no such Cookie was found.
    '''
    cookie = _get_cookies(gw_session).get('JSESSIONID')
    return cookie.value if cookie else None


def terminate_session(gw_session: GatewaySession) -> None:
    '''
    Terminates the Gateway Session.
    '''
    post(gw_session, "/session/terminate", exp_code=200)


def get_configs(gw_session: GatewaySession) -> list:
    '''
    Returns a list containing all configurations on the
    Airlock Host as dictionary objects.
    '''
    res = get(gw_session, "/configuration/configurations", exp_code=200)
    return res.json()["data"]


def validate(gw_session: GatewaySession) -> Tuple[bool, list]:
    '''
    Returns True and an empty list if the configuration is valid,
    False and a list of error messages if it isn't.
    '''
    path = "/configuration/validator-messages?filter=meta.severity==ERROR"
    res = get(gw_session, path, exp_code=200)
    rdata = res.json()
    if len(rdata["data"]) > 0:
        msgs = [e["attributes"]["detail"] for e in rdata["data"]]
        logging.info("Validation failed with the following error\
 message(s):\n %s", str(msgs))
        return False, msgs
    return True, []


def activate(gw_session: GatewaySession, comment: str = None) -> bool:
    '''
    Activates the currently loaded configuration on Airlock Host and
    optionally adds a comment to the activation.\n
    Returns True if the configuration was activated successfully and False
    otherwise
    '''
    data = None
    if comment:
        options = {"ignoreOutdatedConfiguration": True,
                   "failoverActivation": False}
        data = {"comment": comment, "options": options}
    if not validate(gw_session)[0]:
        logging.info("Configuration could not be activated as it isn't valid")
        return False
    path = "/configuration/configurations/activate"
    post(gw_session, path, data, 200)
    return True


def save_config(gw_session: GatewaySession, comment: str = None) -> str:
    '''
    Saves the current configuration with an optional
    `comment` without activating it.\n
    Returns the ID of the newly saved configuration or None if
    the configuration could not be saved.
    '''
    data = None
    if comment:
        data = {"comment": comment}
    path = "/configuration/configurations/save"
    res = post(gw_session, path, data, [200, 400])
    if res.status_code == 400:
        logging.warning("Configuration could not be saved\
 as no configuration was loaded!")
        return None
    return res.json()['data']['id']


def update_license(gw_session: GatewaySession, lic_str: str) -> None:
    '''
    Updates the license on the Airlock Host.
    '''
    res = get(gw_session, '/configuration/license')
    logging.debug("Current license: \n %s", json.dumps(res.json(), indent=4))

    lic_patch_data = {
        "data": {
            "type": "license",
            "attributes": {
                "license": lic_str
            }
        }
    }
    patch(gw_session, "/configuration/license", lic_patch_data, 200)


def get_virtualhosts(gw_session: GatewaySession) -> list:
    '''
    Returns a list of dictionary objects describing all
    virtual hosts on the Airlock Host.
    '''
    res = get(gw_session, '/configuration/virtual-hosts', exp_code=200)
    return res.json().get('data')


def gen_standard_virtual_host_data(vh_name: str, ipv4_addr: str,
                                   interface: str,
                                   certificate: dict) -> dict:
    '''
    Generates and returns the data object necessary to upload a new virtual
    host to the Airlock Host. This object can then for example be passed
    to the `add_virtual_host()` function to add a new virtual host. \n
    The virtual host data will have standard values for every attribute that
    can not be given to this function as an argument.
    '''
    host_data = {
        "data": {
            "type": "virtual-host",
            "attributes": {
                "name": vh_name,
                "hostName": vh_name,
                "serverAdmin": "admin@" + vh_name,
                "showMaintenancePage": False,
                "strictlyMatchFullyQualifiedDomainName": False,
                "keepAliveTimeout": 10,
                "networkInterface": {
                    "externalLogicalInterfaceName": interface,
                    "ipV4Address": ipv4_addr,
                    "ipV6Address": "",
                    "http": {
                        "enabled": True,
                        "port": 80,
                        "httpsRedirectEnforced": True
                    },
                    "https": {
                        "enabled": True,
                        "port": 443,
                        "http2Allowed": True
                    }
                },
                "tls": certificate,
            }
        }
    }
    return host_data


def add_virtual_host(gw_session: GatewaySession, data: dict) -> str:
    '''
    Adds a new virtual host to the Airlock Host. The `data` parameter
    has to fully specify a valid virtual host configuration.\n
    For standard virtual hosts configuration use
    `add_standard_virtual_host()` instead.\n
    Returns the ID of the added virtual host.
    '''
    res = post(gw_session, "/configuration/virtual-hosts", data, 201)
    return res.json()['data']['id']


def get_virtual_host_by_id(gw_session: GatewaySession, vh_id: str) -> dict:
    '''
    Returns a dictionary object representing the virtual host with
    the given `vh_id` or None if no such virtual host was found
    '''
    path = f'/configuration/virtual-hosts/{vh_id}'
    res = get(gw_session, path, exp_code=[200, 404])

    if res.status_code == 404:
        return None
    return res.json().get('data')


def update_virtual_host_by_id(gw_session: GatewaySession, vh_id: str,
                              attributes: dict) -> bool:
    '''
    Updates the virtual host with ID `vh_id` with the given `attributes`,
    for example name, showMaintenancePage etc.\n
    Returns True if the update was successful and False if no virtual
    host with ID `vh_id` was found.
    '''
    host_data = {
        "data": {
            "type": "virtual-host",
            "id": vh_id,
            "attributes": attributes
        }
    }
    path = f"/configuration/virtual-hosts/{vh_id}"
    res = patch(gw_session, path, host_data, [200, 404])
    return res.status_code == 200


def delete_virtual_host_by_id(gw_session: GatewaySession, vh_id: str) -> bool:
    '''
    Deletes the Virtual Host with the selected ID.\n
    Returns True if deletion was successful and False otherwise.
    '''
    path = f"/configuration/virtual-hosts/{vh_id}"
    res = delete(gw_session, path, exp_code=[204, 404])
    return res.status_code == 204


def get_all_mappings(gw_session: GatewaySession) -> list:
    '''
    Returns a list of dictionary object describing
    all mappings on the Airlock Host.
    '''
    res = get(gw_session, '/configuration/mappings', 200)
    return res.json().get('data')


def select_mappings(gw_session: GatewaySession, pattern: str = None,
                    label: str = None) -> list:
    '''
    Returns a list of dictionary object describing all mappings
    whose name is matched by the `pattern` regular expression
    or who are labeled with `label`.\n
    If no parameter is given, all mappings are returned.
    '''
    if (not pattern and not label):
        return get_all_mappings(gw_session)
    if (pattern and label):
        return list(set(select_mappings(gw_session, pattern=pattern))
                    + set(select_mappings(gw_session, label=label))
                    )
    if label:
        path = f'/configuration/mappings?filter=label=={label}'
        res = get(gw_session, path, exp_code=200)
        return res.json().get('data')
    mappings = []
    for mapping in get_all_mappings(gw_session):
        if re.search(pattern, mapping['attributes']['name']):
            mappings.append(mapping)
    return mappings


def get_mapping_id(gw_session: GatewaySession, name: str) -> str:
    '''
    Returns the ID of the mapping with the given `name`
    or None if no such mapping was found.
    '''
    mapping = get_mapping_by_name(gw_session, name)
    if mapping:
        return mapping['id']
    return None


def get_mapping_by_id(gw_session: GatewaySession, mapping_id: str) -> dict:
    '''
    Returns a dictionary object representing the mapping
    with the given `mapping_id` or None if no such mapping
    was found.
    '''
    path = f'/configuration/mappings/{mapping_id}'
    res = get(gw_session, path, exp_code=[200, 404])
    if res.status_code == 200:
        return res.json().get('data')
    return None


def get_mapping_by_name(gw_session: GatewaySession, name: str) -> dict:
    '''
    Returns a dictionary object representing the mapping
    with the given `name` or None if no such mapping was found.
    '''
    path = f'/configuration/mappings?filter=name=={name}'
    res = get(gw_session, path, exp_code=200)

    candidate_list = res.json().get('data')
    if len(candidate_list) == 1:
        return candidate_list[0]

    return None


def get_all_mapping_names(gw_session: GatewaySession) -> list:
    '''
    Returns a sorted list of all mapping names on the Airlock Host.
    '''
    mappings = get_all_mappings(gw_session)
    mapping_names = []
    for mapping in mappings:
        mapping_name = mapping["attributes"]["name"]
        mapping_names.append(mapping_name)
    return sorted(mapping_names)


def import_mappings_from_xml(gw_session, mappings_xmls: list):
    '''
    Adds all mappings specified in the list of dictionary objects
    representing XML files stored in  `mappings_xmls` on the
    Airlock Host. If a mapping with the same name already exists,
    it will be overwritten.
    '''
    for mapping_xml in mappings_xmls:
        mapping_zip = BytesIO()
        with ZipFile(mapping_zip, mode="w") as zip_file:
            zip_file.writestr("alec_table.xml", mapping_xml)

        mapping_zip.seek(0)

        req_raw(gw_session, "put", "/configuration/mappings/import",
                "application/zip", mapping_zip.read(), 200)


def export_mappings(gw_session: GatewaySession,
                    mapping_ids: list = None) -> list:
    '''
    Returns a list of the XML files describing the mappings with IDs
    contained in the `mapping_ids` list.\n
    `mapping_ids` must be a list of strings. If it is omitted, all mappings
    are returned. \n
    If one or more of the mappings IDs is not found, it is ignored.
    '''
    if mapping_ids is None:
        mapping_ids = [data["id"] for data in get_all_mappings(gw_session)]

    mapping_xmls = []
    for mapping_id in mapping_ids:
        gw_session.add_headers({"Accept": "application/zip"})
        path = f'/configuration/mappings/{mapping_id}/export'
        res = get(gw_session, path, exp_code=[200, 404])
        if res.status_code == 200:
            with ZipFile(BytesIO(res.content)) as zip_file:
                with zip_file.open("alec_table.xml", "r") as mapping_xml:
                    mapping_xmls.append(mapping_xml.read())
        else:
            logging.info("Mapping with ID %s was not found on Airlock Host",
                         mapping_id)

    gw_session.add_headers({"Accept": "application/json"})
    return mapping_xmls


def delete_mapping_by_id(gw_session: GatewaySession, mapping_id: str) -> bool:
    '''
    Deletes the Mapping with the selected ID.\n
    Returns True if deletion was successful and False if no mapping with ID
    `mapping_id` was found..
    '''
    path = f"/configuration/mappings/{mapping_id}"
    res = delete(gw_session, path, exp_code=[204, 404])
    return res.status_code == 204


def get_templates(gw_session: GatewaySession) -> dict:
    '''
    Returns a dictionary object mapping every mapping template name to its ID.
    '''
    res = get(gw_session, '/configuration/templates/mappings', 200)
    data = res.json()['data']
    return {x['attributes']['name']: x['id'] for x in data}


def update_mapping(gw_session: GatewaySession, mapping_id: str,
                   attributes: dict) -> bool:
    '''
    Updates the mapping with ID `mapping_id` with the given `attributes`,
    for example name or entry path.\n
    Returns True if update was successful and False if no mapping with ID
    `mapping_id` was found.
    '''
    data = {
        "data": {
            "type": 'mapping',
            "attributes": attributes
        }
    }
    path = f'/configuration/mappings/{mapping_id}'
    res = patch(gw_session, path, data, [200, 404])
    return res.status_code == 200


def add_mapping(gw_session: GatewaySession, name: str,
                template: str = 'New_Mapping', entry_path: str = '/') -> str:
    '''
    Adds a new mapping to the Airlock host, with the specified
    `name` and `entry_path`.\n Optionally, a template can
    be used for the new mapping.\n
    Returns the mapping ID of the new mapping.
    '''
    templates = get_templates(gw_session)
    data = {
        "data": {
            "type": "create-mapping-from-template",
            "attributes": {
                "id": templates[template]
            }
        }
    }
    path = '/configuration/mappings/create-from-template'
    res = post(gw_session, path, data, 201)
    mapping_id = res.json()['data']['id']
    attributes = {
        "name": name,
        "entryPath": {"value": entry_path}
    }
    update_mapping(gw_session, mapping_id, attributes)
    return mapping_id


def set_source_mapping(gw_session: GatewaySession, mapping_id: str,
                       src_mapping_id: str) -> bool:
    '''
    Sets the source mapping of mapping with ID `mapping_id`
    to the mapping with ID `src_mapping_id`. \n
    Returns True if the operation was successful and False if
    no mapping with ID `mapping_id` was found.
    '''
    data = {
        "data": {
            "type": 'mapping',
            "id": src_mapping_id
        }
    }
    path = f'/configuration/mappings/{mapping_id}/relationships/template'
    res = patch(gw_session, path, data, [204, 404])
    if res.status_code == 404:
        return False

    lock_cfg = {
        "enabled": True,
        "labels": True,
        "entryPath": {"settings": True}
    }

    return update_mapping(gw_session, mapping_id, {"locking": lock_cfg})


def pull_from_source_mapping(gw_session: GatewaySession,
                             mapping_id: str) -> bool:
    '''
    Performs a pull from the source mapping on the mapping with
    ID `mapping_id`.\n
    Returns True if the pull was succesfull and False if no mapping with ID
    `mapping_id` was found.
    '''
    path = f'/configuration/mappings/{mapping_id}/pull-from-source-mapping'
    res = post(gw_session, path, exp_code=[200, 404])
    return res.status_code == 200


def gen_backend_host(protocol: str, name: str, port: int) -> dict:
    '''
    Returns a dictionary object representing a new Backend Host.
    '''
    host_data = {
        "protocol": protocol,
        "hostName": name,
        "port": port
    }
    return host_data


def add_backend_group(gw_session: GatewaySession, beg_name: str,
                      be_hosts: list) -> str:
    '''
    Adds a new Backend Group with the name `beg_name` and the hosts
    contained in `be_hosts` to the Airlock Host.\n
    Returns the ID of the newly added Backend Group.
    '''
    beg_data = {
        "data": {
            "type": "back-end-group",
            "attributes": {
                "name": beg_name,
                "backendHosts": be_hosts
            }
        }
    }
    res = post(gw_session, "/configuration/back-end-groups", beg_data, 201)
    return res.json()['data']['id']


def get_backend_groups(gw_session: GatewaySession) -> list:
    '''
    Returns a list containing all backend groups on the Airlock Host.
    '''
    res = get(gw_session, '/configuration/back-end-groups', exp_code=200)
    return res.json().get('data')


def get_backend_group_by_id(gw_session: GatewaySession, beg_id: str) -> dict:
    '''
    Returns a dictionary object describing the backend group with ID
    `beg_id`, or None if no such group was found.
    '''
    path = f'/configuration/back-end-groups/{beg_id}'
    res = get(gw_session, path, exp_code=[200, 404])
    if res.status_code == 200:
        return res.json().get('data')
    return None


def update_backend_group_by_id(gw_session: GatewaySession, beg_id: str,
                               attributes: dict) -> bool:
    '''
    Updates the Backend Group with ID `beg_id` with the given attributes,
    for example hostname or port. \n
    Returns True if the update was succesfull and False if no Backend Group
    with ID `beg_id` was found.
    '''
    beg_data = {
        "data": {
            "type": "back-end-group",
            "id": beg_id,
            "attributes": attributes
        }
    }
    path = f"/configuration/back-end-groups/{beg_id}"
    res = patch(gw_session, path, beg_data, [200, 404])
    return res.status_code == 200


def delete_backend_group_by_id(gw_session: GatewaySession,
                               beg_id: str) -> bool:
    '''
    Deletes the Backend Group with ID `beg_id` from the Airlock Host.\n
    Returns True if deletion was successful and False if no Backend
    Group with ID `beg_id` was found.
    '''
    path = f"/configuration/back-end-groups/{beg_id}"
    res = delete(gw_session, path, exp_code=[204, 404])
    return res.status_code == 204


def connect_virtual_host_to_map(gw_session: GatewaySession, vh_id: str,
                                mapping_id: str) -> bool:
    '''
    Connects Virtual Host with id `vh_id` to the Mapping with ID
    `mapping_id`.\n Returns True if the operation was successful
    and False if one of the provided IDs was not found.
    '''
    data = {
        "data": [{
            "type": 'mapping',
            "id": mapping_id
        }]
    }
    path = f'/configuration/virtual-hosts/{vh_id}/relationships/mappings'
    res = patch(gw_session, path, data, [204, 404])
    return res.status_code == 204


def connect_map_to_beg(gw_session: GatewaySession, mapping_id: str,
                       beg_ids: list) -> bool:
    '''
    Connects Mapping with ID `mapping_id` to the Backend Groups
    with IDs in `beg_ids`.\n
    Returns True if the operation was successful and False if one of
    the provided IDs was not found.
    '''
    data = {
        "data": []
    }
    for beg_id in beg_ids:
        group = {
            "type": 'back-end-group',
            "id": beg_id
        }
        data['data'].append(group)
    map_id = mapping_id
    path = f'/configuration/mappings/{map_id}/relationships/back-end-groups'
    res = patch(gw_session, path, data, [204, 404])
    return res.status_code == 204


def disconnect_virtual_host_to_map(gw_session: GatewaySession, vh_id: str,
                                   mapping_id: str) -> bool:
    '''
    Disconnects Virtual Host with id `vh_id` to the Mapping with
    ID `mapping_id`.\n Returns True if the operation was successful
    and False if one of the provided IDs was not found.
    '''
    data = {
        "data": [{
            "type": 'mapping',
            "id": mapping_id
        }]
    }
    path = f'/configuration/virtual-hosts/{vh_id}/relationships/mappings'
    res = delete(gw_session, path, data, [204, 404])
    return res.status_code == 204


def disconnect_map_to_beg(gw_session: GatewaySession, mapping_id: str,
                          beg_ids: list) -> bool:
    '''
    Disconnects Mapping with ID `mapping_id` from the Backend Groups
    with IDs in `beg_ids`.\n Returns True if the operation was successful
    and False if one of the provided IDs was not found.
    '''
    data = {
        "data": []
    }
    for beg_id in beg_ids:
        group = {
            "type": 'back-end-group',
            "id": beg_id
        }
        data['data'].append(group)
    map_id = mapping_id
    path = f'/configuration/mappings/{map_id}/relationships/back-end-groups'
    res = delete(gw_session, path, data, [204, 404])
    return res.status_code == 204


def get_mapping_deny_rule_group(gw_session: GatewaySession, mapping_id: str,
                                denyrule_group_shortname: str) -> dict:
    '''
    Returns a dictionary object describing the deny rule group in the
    specified Mapping, or None if the mapping or shortname specified were not
    found.
    '''
    path = f'/configuration/mappings/{mapping_id}/deny-rule-groups/{denyrule_group_shortname}'
    res = get(gw_session, path, exp_code=[200, 404])
    return res.json().get('data')


def update_mapping_deny_rule_group(gw_session: GatewaySession, mapping_id: str,
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
    res = patch(gw_session, path, data, exp_code=[200, 404])
    return res.status_code == 200


def get_mapping_deny_rule(gw_session: GatewaySession, mapping_id: str,
                          denyrule_shortname: str) -> dict:
    '''
    Returns a dictionary object describing the deny rule in the specified
    Mapping, or None if the mapping or shortname specified were not found.
    '''
    path = f'/configuration/mappings/{mapping_id}/deny-rules/{denyrule_shortname}'
    res = get(gw_session, path, exp_code=[200, 404])
    return res.json().get("data")


def update_mapping_deny_rule(gw_session: GatewaySession, mapping_id: str,
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
    res = patch(gw_session, path, data, exp_code=[200, 404])
    return res.status_code == 200


def get_deny_rule_groups(gw_session: GatewaySession) -> dict:
    '''
    Returns a list of all deny rule groups on the Airlock Host.
    '''

    path = '/configuration/deny-rule-groups'
    res = get(gw_session, path, exp_code=200)
    return res.json().get("data")


def get_deny_rule_group(gw_session: GatewaySession, short_name: str) -> dict:
    '''
    Returns a dictionary object describing the specified deny rule group,
    or None if it does not exist.
    '''

    path = f'/configuration/deny-rule-groups/{short_name}'
    res = get(gw_session, path, exp_code=[200, 404])
    return res.json().get("data")


def get_deny_rules(gw_session: GatewaySession) -> list:
    '''
    Returns a list of all deny-rules on the Airlock Host.
    '''

    path = '/configuration/deny-rules'
    res = get(gw_session, path, exp_code=200)
    return res.json().get("data")


def get_deny_rule(gw_session: GatewaySession, short_name: str) -> dict:
    '''
    Returns a dictionary object describing the specified deny-rule, or None
    if it does not exist.
    '''
    path = f'/configuration/deny-rules/{short_name}'
    res = get(gw_session, path, exp_code=[200, 404])
    return res.json().get("data")


def load_config(gw_session: GatewaySession, config_id: int,
                host_name: str = None) -> bool:
    '''
    Loads the configuration with ID `config_id` on the Airlock Host.\n
    Returns True if the operation was successful and False if no configuration
    with ID `config_id` was found.
    '''
    data = {"hostname": host_name or gw_session.host_name}
    path = f"/configuration/configurations/{config_id}/load"
    res = post(gw_session, path, data, [204, 404])
    return res.status_code == 204


def load_empty_config(gw_session: GatewaySession, host_name: str = None):
    '''
    Loads the empty configuration on the Airlock Host.
    '''
    data = {"hostname": host_name or gw_session.host_name}
    path = "/configuration/configurations/load-empty-config"
    post(gw_session, path, data, 204)


def load_active_config(gw_session: GatewaySession):
    '''
    Loads the currently active configuration on the Airlock Host.
    '''
    post(gw_session, '/configuration/configurations/load-active', None, 204)


def load_initial_config(gw_session: GatewaySession):
    '''
    Loads the initial configuration on the Airlock Host.
    '''
    res = get(gw_session, '/configuration/configurations', exp_code=200)
    data = res.json()['data']
    init_cfg_id = [x['id'] for x in data
                   if x['attributes']['configType'] == 'INITIAL'][0]
    path = f'/configuration/configurations/{init_cfg_id}/load'
    post(gw_session, path, None, 204)


def _get_hostname_from_config_zip(cfg_zip: str):
    '''
    Returns the name of the Airlock Host from the config
    zip file located at `cfg_zip`.
    '''
    host_name = None
    with zipfile.ZipFile(cfg_zip) as zip_file:
        with zip_file.open('alec_full.xml') as config_xml:
            doc = ET.parse(config_xml)
            host_names = [n.text for n in doc.findall("./Nodes/*/HostName")]
            if host_names:
                host_name = host_names[0]
    return host_name


def import_config(gw_session: GatewaySession, cfg_zip: str):
    '''
    Imports the configuration zip file located at
    `cfg_zip` to the Airlock Host.
    '''
    with open(cfg_zip, 'rb') as file:
        cfg_host_name = _get_hostname_from_config_zip(cfg_zip)
        load_empty_config(gw_session, cfg_host_name)
        path = "/configuration/configurations/import"
        req_raw(gw_session, "PUT", path, "application/zip", file, 200)


def _export_current_config_data(gw_session: GatewaySession):
    '''
    Returns a zip file that describes the currently active configuration
    on Airlock Host.
    '''
    path = '/configuration/configurations/export'
    res = get(gw_session, path, exp_code=200)
    return res.content


def export_current_config_file(gw_session: GatewaySession, cfg_zip: str):
    '''
    Exports the currently active configuration to a
    zip file located at `cfg_zip`.
    '''
    data = _export_current_config_data(gw_session)
    with open(cfg_zip, 'wb') as file:
        file.write(data)


def get_error_page_settings(gw_session: GatewaySession) -> dict:
    '''
    Returns a dictionary object describing the current error page settings.
    '''
    path = '/configuration/error-pages'
    res = get(gw_session, path, exp_code=200)
    return res.json().get('data')


def set_error_page_settings(gw_session: GatewaySession, attributes: dict):
    '''
    Updates the error page settings with the given attributes.
    '''
    path = '/configuration/error-pages'
    data = {
        "data": {
            "type": "error-pages",
            "attributes": attributes
        }
    }
    patch(gw_session, path, data, exp_code=200)


def get_error_pages(gw_session: GatewaySession) -> Union[bytes, None]:
    '''
    Returns a zip file containing the error pages
    '''
    path = '/configuration/error-pages/content'
    res = get(gw_session, path, exp_code=[200, 404])
    if res.status_code == 404:
        return None
    return res.content


def set_error_pages(gw_session: GatewaySession, error_page_zip: str):
    '''
    Imports the error page zip-file located at `error_page_zip`.
    '''
    with open(error_page_zip, 'rb') as file:
        path = "/configuration/error-pages/content"
        req_raw(gw_session, "PUT", path, "application/zip", file, 200)


def delete_error_pages(gw_session: GatewaySession):
    '''
    Remove the custom error pages.
    '''
    path = '/configuration/error-pages/content'
    delete(gw_session, path, exp_code=200)


def get_default_error_pages(gw_session: GatewaySession) -> bytes:
    '''
    Returns a zip file containing the default error pages.
    '''
    path = '/configuration/error-pages/content/default'
    res = get(gw_session, path, exp_code=200)
    return res.content


def get_expert_settings(gw_session: GatewaySession) -> dict:
    '''
    Returns a dict containing the global expert settings for the Gateway as well as for Apache
    '''
    path = '/configuration/expert-settings'
    res = get(gw_session, path, exp_code=200)
    return res.json().get('data')


def set_expert_settings(gw_session: GatewaySession, attributes: dict) -> None:
    '''
    Updates the global expert settings with the given attributes.
    '''
    path = '/configuration/expert-settings'
    data = {
        "data": {
            "type": 'expert-settings',
            "attributes": attributes
        }
    }
    patch(gw_session, path, data, exp_code=200)
