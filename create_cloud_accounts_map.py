#
# Author: Sean Nicholson
# Purpose: Build a cloud account map to Qualys connectors for running perimeter scan script
#
#----------------------------------------------------------
#  Script logic flow
#  1 - load env variable and load config.yml
#  2 - Pull list of connectors from {AQualys API URL}/qps/rest/2.0/search/am/assetdataconnector
#      for connectors with VM module activated, not in disabled state, and type = AWS
#  3 - Parse list of connectors and create Cloud Account Map CSV
#      row['connectorId'] = connector['id']
#      row['name'] = connector['name']
#      row['accountId'] = connector['awsAccountId']
#      row['optionProfileId'] = str(args.optionprofile)
#      row['BU']=''  <-- ### user can add code to lookup or hard code this value
#      row['tagName']='' <-- ### user can add code to lookup or hard code this value
#      row['tagId']='' <-- ### user can add code to lookup or hard code this value
#  4 - file name set on line 59 -->  out_file = "cloud-accounts2.csv"
#----------------------------------------------------------
# Script Input parameters:
# --optionprofile 123456
#
#----------------------------------------------------------
# version: 1.0.0 - date: 9.17.2019 - initial release
#----------------------------------------------------------


import sys, requests, os, csv, yaml, json, base64, logging
import logging.config
import argparse


def setup_logging(default_path='./config/logging.yml',default_level=logging.INFO,env_key='LOG_CFG'):
    """Setup logging configuration"""
    if not os.path.exists("log"):
        os.makedirs("log")
    path = default_path
    value = os.getenv(env_key, None)
    if value:
        path = value
    if os.path.exists(path):
        with open(path, 'rt') as f:
            config = yaml.safe_load(f.read())
        logging.config.dictConfig(config)
    else:
        logging.basicConfig(level=default_level)



def query_connector_list(accountInfo, URL, headers):
    try:
        rURL = URL + "/qps/rest/2.0/run/am/assetdataconnector/"
        requestBody = "<ServiceRequest>\n\t<filters>\n\t\t<Criteria field=\"activation\" operator=\"IN\">VM</Criteria>\n\t\t<Criteria field=\"disabled\" operator=\"EQUALS\">false</Criteria>\n\t\t<Criteria field=\"type\" operator=\"EQUALS\">AWS</Criteria>\n\t</filters>\n</ServiceRequest>\n"
        rdata = requests.post(rURL, headers=headers, data=requestBody)
        row = {}
        logger.info("Retrieve Connector List - run status code {0}\n".format(str(rdata.status_code)))
        logger.debug("Retrieve Connector List - run status code {0}\n POST request response \n {1}".format(str(rdata.status_code), str(rdata.text)))
        runResult = json.loads(str(rdata.text))
        if str(runResult['ServiceResponse']['responseCode']) != "SUCCESS" or str(runResult['ServiceResponse']['responseCode']) == "NOT_FOUND":
            logger.error("Repsonse Error - API Response Message: {0}".format(str(rdata.text)))
        elif int(runResult['ServiceResponse']['count']) > 0:
            out_file = accountInfo
            ofile = open(out_file, "w")
            fieldnames = ['name','accountId','connectorId','BU','tagName','tagId','optionProfileId']
            writer = csv.DictWriter(ofile, fieldnames=fieldnames)
            writer.writeheader()
            for connector in runResult['ServiceResponse']['data']:
                row['connectorId'] = connector['AwsAssetDataConnector']['id']
                row['name'] = connector['AwsAssetDataConnector']['name']
                row['accountId'] = connector['AwsAssetDataConnector']['awsAccountId']
                row['optionProfileId'] = str(args.optionprofile)
                row['BU']=''
                row['tagName']=''
                row['tagId']=''
                writer.writerow(row)
            ofile.close()

    except IOError as e:
        logger.warning("Error {1}: {2}".format(e.errno, e.strerror))



def build_cloud_account_map():
    with open('./config/config.yml', 'r') as config_settings:
        config_info = yaml.load(config_settings)
        URL = str(config_info['defaults']['apiURL']).rstrip()
        accountInfo = str(config_info['defaults']['accountInfo']).rstrip()
        if URL == '':
            logger.error("Config information in ./config.yml not configured correctly. Exiting...")
            sys.exit(1)
    username = os.environ["QUALYS_API_USERNAME"]
    password = base64.b64decode(os.environ["QUALYS_API_PASSWORD"])
    logger.debug("Base64 password {0} and Base64decode: {1}".format(str(os.environ["QUALYS_API_PASSWORD"]), str(password)))
    usrPass = str(username)+':'+str(password)
    b64Val = base64.b64encode(str(usrPass).encode('ascii'))
    logger.debug("b64Val = {}".format(str(b64Val)))
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'text/xml',
        'Authorization': "Basic %s" % b64Val,
        'X-Requested-With': 'Python Requests'
    }

    query_connector_list(accountInfo, URL, headers)





parser = argparse.ArgumentParser()
parser.add_argument("--optionprofile", "-o", help="Specify the Option Profile ID for your cloud account map example: --optionprofile 123456")
args = parser.parse_args()
if not args.optionprofile:
    logger.error("optionprofile is required to run script, please run python create_cloud_map.py -h for required command syntax")
    sys.exit(1)


if __name__ == "__main__":
    setup_logging()
    logger = logging.getLogger(__name__)
    build_cloud_account_map()
