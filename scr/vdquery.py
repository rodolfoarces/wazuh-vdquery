#!/usr/bin/env python3

# Query Vulnerability Detection module index pattern 

# Exit errors:
# 1 - Required parameter is missing
# 2 - Authentication error (Token)
# 3 - Error opening a log file

# Requirements
import sys
import argparse
import requests
import json
import logging
import time
import os
import configparser

# Disabling warning: /usr/lib/python3/dist-packages/urllib3/connectionpool.py:1100: InsecureRequestWarning: 
# Unverified HTTPS request is being made to host '10.1.1.3'. Adding certificate verification is strongly advised.
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Read parameters using argparse
## Initialize parser
parser = argparse.ArgumentParser()
## Adding optional argument
parser.add_argument("-iu", "--indexer-username", help = "Wazuh Indexer username, required for remote API connection", action="store", default="admin")
parser.add_argument("-ip", "--indexer-password", help = "Wazuh Indexer password, required for remote API connection", action="store", default="admin")
parser.add_argument("-ih", "--indexer-host", help = "Wazuh Indexer FQDN/IP, required for remote API connection", action="store", default="localhost")
parser.add_argument("-iP", "--indexer-port", help = "Wazuh Indexer port, required for remote API connection", action="store", default="9200")
parser.add_argument("-mu", "--manager-username", help = "Wazuh Manager username, required for remote API connection", action="store", default="wazuh")
parser.add_argument("-mp", "--manager-password", help = "Wazuh Manager password, required for remote API connection", action="store", default="wazuh")
parser.add_argument("-mh", "--manager-host", help = "Wazuh Manager FQDN/IP, required for remote API connection", action="store", default="localhost")
parser.add_argument("-mP", "--manager-port", help = "Wazuh Manager port, required for remote API connection", action="store", default="55000")
parser.add_argument("-o", "--output", help = "Log output to file", default="out.log")
parser.add_argument("-D", "--debug", help = "Enable debug", action="store_true")
## Read arguments from command line
args = parser.parse_args()

#Variables
manager_token = None
agent_list = []

## Log to file or stdout
# https://docs.python.org/3/howto/logging-cookbook.html#logging-cookbook
# create file handler which logs even debug messages

def apiAuthenticate(manager_url,manager_username, manager_password):
    auth_endpoint = manager_url + "/security/user/authenticate"
    logger.debug("Starting authentication process")
    # api-endpoint
    auth_request = requests.get(auth_endpoint, auth=(manager_username, manager_password), verify=False)
    r = auth_request.content.decode("utf-8")
    auth_response = json.loads(r)
    try:
        return auth_response["data"]["token"]
    except KeyError:
        # "title": "Unauthorized", "detail": "Invalid credentials"
        if auth_response["title"] == "Unauthorized":
            logger.error("Authentication error")
            return None

def getAgentList():
    # API processing
    msg_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + manager_token}
    msg_url = manager_url + "/agents?wait_for_complete=true" 
    agent_request = requests.get(msg_url, headers=msg_headers, verify=False)
    r = json.loads(agent_request.content.decode('utf-8'))
    # Check
    if agent_request.status_code != 200:
        logger.error("There were errors getting the agent list")
        exit(2)
    
    if r['data']['total_affected_items'] <= 1:
        logger.debug("No agents")
        exit(3)
    else:
        for agent in r['data']['affected_items']: 
            agent_list.append(agent)

    
if __name__ == "__main__":
    ## Log to file or stdout
    # https://docs.python.org/3/howto/logging-cookbook.html#logging-cookbook
    # create file handler which logs even debug messages
    logger = logging.getLogger("docker-output")

    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    # If file is set, everything goes there
    if args.output:
        # create console handler with a higher log level
        fh = logging.FileHandler(args.output)
        # Define log level
        if args.debug == True:
            fh.setLevel(logging.DEBUG)
            fh_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        else:
            fh.setLevel(logging.INFO)
            fh_formatter = logging.Formatter('%(message)s')
        
        fh.setFormatter(fh_formatter)
        # add the handlers to the logger
        logger.addHandler(fh)
    else:
        # create console handler with a higher log level
        fh = logging.StreamHandler()
        # Define log level
        if args.debug == True:
            fh.setLevel(logging.DEBUG)
            fh_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        else:
            fh.setLevel(logging.INFO)
            fh_formatter = logging.Formatter('%(message)s')
        
        fh.setFormatter(fh_formatter)
        # add the handlers to the logger
        logger.addHandler(fh)

    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
        
     # If output file is set, all messages go there
    if args.output:
        # create console handler with a higher log level
        fh = logging.FileHandler(args.output)
        # Define log level
        if args.debug == True:
            fh.setLevel(logging.DEBUG)
            fh_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        else:
            fh.setLevel(logging.INFO)
            fh_formatter = logging.Formatter('%(message)s')
        
        fh.setFormatter(fh_formatter)
        # add the handlers to the logger
        logger.addHandler(fh)
    else:
        # create console handler with a higher log level
        fh = logging.StreamHandler()
        # Define log level
        if args.debug == True:
            fh.setLevel(logging.DEBUG)
            fh_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        else:
            fh.setLevel(logging.INFO)
            fh_formatter = logging.Formatter('%(message)s')
        
        fh.setFormatter(fh_formatter)
        # add the handlers to the logger
        logger.addHandler(fh)
    
    # Configurations
    script_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
    config_filename = str(os.path.join(script_dir, "fim-report.conf"))
    # Load data from configuration file
    if os.path.isfile(config_filename):
        logger.debug("Opening configuration file")
        config = configparser.ConfigParser()
        config.read(config_filename)
        # Wazuh manager connection
        manager_username = config.get('manager', 'manager_username')
        manager_password = config.get('manager', 'manager_password')
        manager_host =  config.get('manager', 'manager_host')
        manager_port =  config.get('manager', 'manager_api_port')
        manager_url = "https://" + manager_host + ":" + manager_port
        
        # Wazuh indexer connection
        indexer_username = config.get('indexer', 'indexer_username')
        indexer_password = config.get('indexer', 'indexer_password')
        indexer_host =  config.get('indexer', 'indexer_host')
        indexer_port =  config.get('indexer', 'indexer_port')
        indexer_url = "https://" + indexer_host + ":" + indexer_port
    else:
        logger.debug("Error opening configuration file, taking default values")
        # Variables
        indexer_username = "admin"
        indexer_password = "admin"
        indexer_host = "localhost"
        indexer_port = "9200"
    
    ## Setting Wazuh Indexer authentication
    if args.indexer_username != "admin":
        logger.debug("Manually setting Wazuh Indexer username (overrides config file)")
        indexer_username = str(args.indexer_username)
    else:
        logger.debug("Wazuh Indexer username not set, using: %s" % indexer_username)

    if args.indexer_password != "admin":
        logger.debug("Manually setting Wazuh Indexer password (overrides config file)")
        indexer_password = str(args.indexer_password)
    else:
        logger.debug("Wazuh Indexer password not set, using default value")
        
    ## Setting Indexer host
    if args.indexer_host != "localhost":
        logger.debug("Manually setting Wazuh Indexer host/FQDN (overrides config file)")
        indexer_host = str(args.indexer_host)
    else:
        logger.debug("Wazuh Indexer host/FQDN not set, using: %s", indexer_host)

    ## Setting Indexer port
    if args.indexer_port != "9200":
        logger.debug("Manually setting Wazuh Indexer port (overrides config file)")
        indexer_port = str(args.indexer_port)
    else:
        logger.debug("Wazuh Indexer port not set, using: %s", indexer_port)
    # Indexer URL
    indexer_url = "https://" + indexer_host + ":" + indexer_port
    
    ## Setting Wazuh Manager authentication
    if args.manager_username != "wazuh":
        logger.debug("Manually setting Wazuh Manager username (overrides config file)")
        manager_username = str(args.manager_username)
    else:
        logger.debug("Wazuh Manager username not set, using: %s" % manager_username)

    if args.manager_password != "wazuh":
        logger.debug("Manually setting Wazuh Manager password (overrides config file)")
        manager_password_password = str(args.manager_password)
    else:
        logger.debug("Wazuh Manager password not set, using default value")
        
    ## Setting Manager host
    if args.manager_host != "localhost":
        logger.debug("Manually setting Wazuh Manager host/FQDN (overrides config file)")
        manager_host = str(args.manager_host)
    else:
        logger.debug("Wazuh Manager host/FQDN not set, using: %s", manager_host)

    ## Setting Manager port
    if args.manager_port != "55000":
        logger.debug("Manually setting Wazuh Manager port (overrides config file)")
        manager_port = str(args.manager_port)
    else:
        logger.debug("Wazuh Manager port not set, using: %s", manager_port)
    # Manager URL
    manager_url = "https://" + manager_host + ":" + manager_port
    
    # Connect to API
    manager_token = apiAuthenticate(manager_url, manager_username, manager_password)
    if manager_token == None:
        logger.debug("Error connecting to the API, exiting")
        exit(1)
    else:
        getAgentList()