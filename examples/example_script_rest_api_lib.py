#!/usr/bin/env python3

# This script is just for explanatory purposes. It shows a little bit
# how to work with the Airlock REST library. It will save a configuration
# after having added a virtual host, a backend group and 10 mappings,
# another one after having connected the VH and the BEG to one of those
# mappings and a last one after having deleted everything it has added. 
# It will never activate any changes and the configuration of
# your Airlock Gateway will remain unchanged.

# In order for this script to work, copy the directory 
# `src/airlock_gateway_rest_api_lib` in the same directory as this script.

# HINT: If you run this script with logging set to DEBUG, you can
# see the JSON payloads for many requests and copy the dictionary 
# objects that describe mappings, backends and virtual host from
# the logs.

import argparse
import logging

from ..src.rest_api_lib import airlock_gateway_rest_requests_lib as al
from .utils import setup_session

logging.basicConfig(level=logging.DEBUG, filename='last_run.log',
                    format='%(asctime)s %(levelname)s %(message)s', 
                    datefmt='%H:%M:%S')
HOST = "airlock-gateway.local"
PORT = 443


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--gateway', help="Host to activate config on", default=HOST)
    parser.add_argument('-p', '--port', help="Gateway MGT HTTPS port", default=PORT)
    parser.add_argument('-k', '--key', help="API Key for Airlock Host", required=True)
    args = parser.parse_args()

    gw_s = setup_session(args.gateway, args.key, args.port)

    # Save backup of original config file
    al.export_current_config_file(gw_s, "./config.zip")

    ids = []
    # Create a few test mappings
    for i in range(0,10):
        name = "ABCtest"+str(i)
        # Will automaticaly use the "New Mapping" template and the '/' entry path
        ids.append(al.add_mapping(gw_s, name))

    # Create a test backend group
    be_host = al.gen_backend_host("HTTP", "ABCtest_be", 80)
    # add_backend_group takes a list of back end hosts, not just a dictionary object.
    beg_id = al.add_backend_group(gw_s, "ABCtest_beg", [be_host])

    # add Virtual Host, we are going to provide no ssl certifiacate (we will fix this later)
    certificate = {"letsEncryptEnabled" : False}
    vh_id = al.add_virtual_host(gw_s, al.gen_standard_virtual_host_data("ABCtest_VH", "172.18.60.215/24", "INTERNAL", certificate))

    al.save_config(gw_s, "Save before connecting mapping")
    valid, errors = al.validate(gw_s)
    if valid:
        print("Something is wrong, this config should not be valid.")
    else:
        # validation will fail because no SSL/TLS certificate is present on the host
        print("Validation Error: " + errors[0])

        vh = al.get_virtual_host_by_id(gw_s, vh_id)
        attributes = vh["attributes"]
        attributes["tls"]["letsEncryptEnabled"] = True
        al.update_virtual_host_by_id(gw_s, vh_id, attributes)
        valid, errors = al.validate(gw_s)
        if valid:
            print("Validation successful")
        else:
            print(errors[0])

    #connects the first created mapping to the beg and the virtual host
    al.connect_virtual_host_to_map(gw_s, vh_id, ids[0])
    al.connect_map_to_beg(gw_s, ids[0], [beg_id])


    al.save_config(gw_s, "Save after connecting mappings")

    for mapping_id in ids:
        al.delete_mapping_by_id(gw_s, mapping_id)
    
    al.delete_backend_group_by_id(gw_s, beg_id)
    al.delete_virtual_host_by_id(gw_s, vh_id)

    al.save_config(gw_s, "Save after deleting mappings, virtual host and backend group")

    # This line doesn't do anything as we never activated any config,
    # but in general this is how you restore the backup that you stored
    # at the beginning of the script.
    al.import_config(gw_s, "./config.zip")

    al.terminate_session(gw_s)


if __name__ == "__main__":
    main()