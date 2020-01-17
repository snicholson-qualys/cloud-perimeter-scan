#
# Author: Sean Nicholson
# Purpose: Run a cloud perimeter scan using Qualys external scanners
#
#----------------------------------------------------------
# Script scanFromFile logic flow
# 1 - process a CSV of account info (CSV columns name, accountId, connectorID, BU, optionProfileId).
# 2 - run the associated connectors for the defined scope
# 3 - Check for completion of the connector run
# 4 - Pull list of host assets and external IPs
# 5 - Pull IP List from Qualys VM Host Assets and compare list of external IPs
# 6 - Add external IPs not registered in Qualys VM Host Assets
# 7 - run a scan by IP list
# 8 - check scan status and fetch scan results when complete
# 9 - If csvreport option used, process scan results (lookup in exceptions tracking CSV if --exception options used) to create a CSV Report for the detected vulnerabilities for each AWS Account
#
# Script command line parameter logic flow
# 1 - run the specified connectorId
# 2 - Check for completion of the connector run
# 3 - Pull list of host assets and (internal or external) IPs
# 4 - Pull IP List from Qualys VM Host Assets and compare list of IPs
# 5 - Add IPs not registered in Qualys VM Host Assets
# 6 - run a scan by IP list
# 7 - check scan status and fetch scan results when complete
# 8 - If csvreport option used, process scan results (lookup in exceptions tracking CSV if --exception option used) to create a CSV Report for the detected vulnerabilities for specified AWS Account
#----------------------------------------------------------
#
# usage: run-perimeter-scan.py [-h] [--scan SCAN] [--scanFromFile] [--csvreport]
#                              [--exceptiontracking] [--tagScanAws]
#                              [--activateAssets] [--internal]
#                              [--scannerName SCANNERNAME] [--tagId TAGID]
#                              [--provider PROVIDER] [--accountId ACCOUNTID]
#                              [--connectorId CONNECTORID]
#                              [--optionProfileId OPTIONPROFILEID]
#
# optional arguments:
#   -h, --help            show this help message and exit
#   --scan SCAN, -s SCAN  Run perimeter scan per account for accounts in
#                         specified <scope>: python run-perimeter-scan.py -s
#                         <scope> or python logging.py --scan <scope> ***
#                         Acceptable scope parameters 'allAccounts', BU or
#                         accountId listed in cloud-accounts.csv
#   --scanFromFile, -sff  Scan from list of cloud accounts listed in file
#   --csvreport, -c       Create a CSV report for each accounts perimeter scan
#   --exceptiontracking, -e
#                         Process Exception Tracking CSV for creating CSV
#                         reports for accounts, used with -c/--csvreport
#   --tagScanAws, -t      Process AWS Perimeter Assets with specified Qualys Tag
#                         ID
#   --activateAssets, -a  Activate all IPs in scope of accounts in Qualys Vuln
#                         Mgmt Module
#   --internal, -i        Scan Internal IP with designated scannerName
#   --scannerName SCANNERNAME, -sn SCANNERNAME
#                         ScannerName for Internal/Private IP scans of AWS/aws,
#                         AZURE/azure, or GCP/gcp workloads
#   --tagId TAGID, -ti TAGID
#                         **Required if not using --scanFromFile/-sff** Tag ID
#                         for command line parameter
#   --provider PROVIDER, -p PROVIDER
#                         **Required if not using --scanFromFile/-sff** Specifiy
#                         cloud provider AWS, Azure, or GCP for command line
#                         parameter
#   --accountId ACCOUNTID, -ai ACCOUNTID
#                         **Required if not using --scanFromFile/-sff** Specify
#                         AWS Account ID, Azure Subscription UUID, or GCP
#                         Project ID for command line parameter
#   --connectorId CONNECTORID, -ci CONNECTORID
#                         **Required if not using --scanFromFile/-sff** Specify
#                         Qualys Connector ID for command line parameter
#   --optionProfileId OPTIONPROFILEID, -o OPTIONPROFILEID
#                         **Required if not using --scanFromFile/-sff** Specify
#                         Qualys Option Profile ID for command line parameter
#
#
#----------------------------------------------------------
# version: 1.0.1 - date: 09.10.2019
# version: 1.0.2 - date: 09.17.2019 - added some retry and data validations, additional debug logging, and code performance improvements
# version  1.0.3 - date: 09.18.2019 - fixed hostasset filter issue and removed some redundant debug logger statements.
# version  1.0.4 - date: 10.10.2019 - fixed check_ips_in_qualys from passing the wrong headers, and added pagination for assets and IPs
# version  1.0.5 - date: 10.11.2019 - Add Azure and GCP perimeter scan functionality based on Qualys tagID for cloud asset search publicIpAddress:*
# version  1.1.0 - date: 01.16.2020 - Added command line run of script with single scan command line Parameters
#                                     Added functionality for internal scan using private IP Addresses with specififed Qualys scanner
#----------------------------------------------------------

import sys, requests, os, time, csv, getopt, yaml, json, base64, socket, logging
from netaddr import *
import xml.etree.ElementTree as ET
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


def config():
    with open('./config/config.yml', 'r') as config_settings:
        config_info = yaml.load(config_settings)
        accountInfoCSV = str(config_info['defaults']['accountInfo']).rstrip()
        exceptionTracking = str(config_info['defaults']['exceptionTracking']).rstrip()
        elbLookup = str(config_info['defaults']['elbLookup']).rstrip()
        URL = str(config_info['defaults']['apiURL']).rstrip()
        throttle = config_info['defaults']['concurrentScans']
        csvHeaders = config_info['defaults']['csvHeaders']
        pageSize = config_info['defaults']['pageSize']
        if URL == '':
            logger.error("Config information in ./config.yml not configured correctly. Exiting...")
            sys.exit(1)
    return accountInfoCSV, exceptionTracking, elbLookup, URL, throttle, csvHeaders, pageSize


def run_connector(connectorId, URL, headers):
    try:
        rURL = URL + "/qps/rest/2.0/run/am/assetdataconnector/" + str(connectorId)
        rdata = requests.post(rURL, headers=headers)
        logger.info("ConnectorID {0} - run status code {1}\n".format(str(connectorId), rdata.status_code))
        logger.debug("ConnectorID {0} - run status code {1}\n Connector run response \n {2}".format(str(connectorId), rdata.status_code, rdata.text))
        runResult = json.loads(str(rdata.text))
        if str(runResult['ServiceResponse']['responseCode']) != "SUCCESS" or str(runResult['ServiceResponse']['responseCode']) == "NOT_FOUND":
            logger.error("Repsonse Error for Connector {0} \n API Response Message: {1}".format(str(connectorId), str(runResult)))
    except IOError as e:
        logger.warning("Error Running Connector Sync {0} with error {1}: {2}".format(connectorId, e.errno, e.strerror))
    #check_connector_status(connectorId, URL)

def check_connector_status(connectorId, URL, b64Val):
    headers = {
        'Accept': 'application/json',
        'X-Requested-With' : 'python requests',
        'Authorization': "Basic %s" % b64Val,
        'Content': 'text/xml'
       }
    counter = 0
    connector_run_completed = False
    while connector_run_completed != True:
        try:
            rURL = URL + "/qps/rest/2.0/get/am/assetdataconnector/" + str(connectorId)
            logger.info("Check Connector URL: \n {0}".format(str(rURL)))
            rdata = requests.get(rURL, headers=headers)
            logger.info("ConnectorID {0} - run status code {1}\n".format(str(connectorId), rdata.status_code))
            logger.debug("ConnectorID {0} - response\n {1}".format(str(connectorId), rdata.text))

            #print rdata.text
            connector_response_data = json.loads(rdata.text)
            logger.debug("Checking for response field responseCode = \"SUCCESS\", \n responCode = {}".format(str(connector_response_data['ServiceResponse']['responseCode'])))
            if str(connector_response_data['ServiceResponse']['responseCode']) == "SUCCESS":
                connector_status = connector_response_data['ServiceResponse']['data']
                if connector_status[0]['AssetDataConnector']['connectorState'] == "FINISHED_SUCCESS":
                    connector_run_completed = True
                elif connector_status[0]['AssetDataConnector']['connectorState'] == "FINISHED_ERRORS":
                    logger.warning("Account {0} Connector ID {1} sync completed with errors - \n ************************** \n {2} \n **************************".format(str(connector_status[0]['AssetDataConnector']['awsAccountId']), connectorId, str(connector_status[0]['AssetDataConnector']['lastError'])))
                    connector_run_completed = True
                else:
                    counter += 1
                    interval = int(60 * counter)
                    time.sleep(interval) #wait time for connector run to finish, increments +1 min for check iteration
                    if counter == 5:
                        logger.warning("Connector ID {} did not complete in allotted time - *** this may result in stale asset data ***".format(str(connectorId)))
                        connector_run_completed = True
            else:
                logger.error("Error Checking Connector {0} Status - \n {1}".format(connectorId, str(connector_response_data)))
                counter += 1
                interval = int(60 * counter)
                time.sleep(interval) #wait time for connector run to finish, increments +1 min for check iteration
                if counter == 5:
                    logger.warning("Connector ID {} did not complete in allotted time - *** this may result in stale asset data ***".format(str(connectorId)))
                    connector_run_completed = True
        except IOError as e:
            logger.error("Error Checking Connector {0} Status with error {1}: {2}".format(connectorId, e.errno, e.strerror))
            interval = int(60 * counter) #wait time for connector run to finish, increments +1 min for check iteration
            if counter == 5:
                logger.warning("Connector ID {} did not complete in allotted time - *** this may result in stale asset data ***".format(str(connectorId)))
                connector_run_completed = True
            counter +=1




def hostAssetLookup(AwsAccountId, URL, b64Val, pageSize):
    logger.info("Made it to hostAssetLookup")
    headers = {
        'X-Requested-With': 'Python Requests',
        'Accept': 'application/json',
        'Content-type': 'text/xml',
        'Cache-Control': "no-cache",
        'Authorization': "Basic %s" % b64Val
    }
    publicIpInstanceCount = 0
    privateIpInstanceCount = 0
    scanIpList = []
    pulledAllResults = False
    resultsIndex = 1
    #requestBody = "<ServiceRequest>\n    <filters>\n        <Criteria field=\"instanceState\" operator=\"EQUALS\">RUNNING<\/Criteria>\n        <Criteria field=\"accountId\" operator=\"EQUALS\">{0}<\/Criteria>\n    <\/filters>\n    <preferences>\n        <limitResults>100</limitResults>\n        <startFromOffset>1</startFromOffset>\n    </preferences>\n<\/ServiceRequest>".format(str(AwsAccountId))
    requestBody = "<ServiceRequest>\n\t<filters>\n\t\t<Criteria field=\"instanceState\" operator=\"EQUALS\">RUNNING</Criteria>\n\t\t<Criteria field=\"accountId\" operator=\"EQUALS\">{0}</Criteria>\n\t</filters>\n\t<preferences>\n\t\t<limitResults>{1}</limitResults>\n\t\t<startFromOffset>1</startFromOffset>\n\t</preferences>\n</ServiceRequest>\n".format(str(AwsAccountId),str(pageSize))
    logger.info("Host Asset request body \n {}".format(str(requestBody)))
    rURL = URL + "/qps/rest/2.0/search/am/hostasset"
    logger.debug("Host asset URL {}".format(str(rURL)))
    while pulledAllResults != True:
        rdata2 = requests.post(rURL, headers=headers, data=requestBody)
        logger.info("Request status code for host assets for Account ID {0} - {1}".format(str(AwsAccountId), str(rdata2.status_code)))
        #logger.debug("Request for AWS Account {0} for host assets \n {1}".format(str(AwsAccountId),str(rdata2.text)))
        jsonHostList = json.loads(rdata2.text)
        logger.debug("**** Count of host assets returned = {0} ****".format(str(jsonHostList['ServiceResponse']['count'])))
        if int(jsonHostList['ServiceResponse']['count']) > 0 and str(jsonHostList['ServiceResponse']['responseCode']) == "SUCCESS":
            logger.debug("Number of assets matching host asset lookup query {}".format(str(jsonHostList['ServiceResponse']['count'])))
            assetList = jsonHostList['ServiceResponse']['data']

            for instance in assetList:
                ec2Details = instance['HostAsset']['sourceInfo']['list']
                for ec2Detail in ec2Details:
                    #logger.debug("EC2 Host Asset info \n {}".format(str(ec2Detail)))
                    if "Ec2AssetSourceSimple" in ec2Detail:
                        #logger.debug("EC2 Asset metadata \n {}".format(str(ec2Detail['Ec2AssetSourceSimple'])))
                        if args.internal:
                            if "privateIpAddress" in ec2Detail['Ec2AssetSourceSimple']:
                                logger.info ("Instance Metadata InstanceId: {}  AccountId: {}  instanceState: {}".format(ec2Detail['Ec2AssetSourceSimple']['instanceId'],ec2Detail['Ec2AssetSourceSimple']['accountId'],ec2Detail['Ec2AssetSourceSimple']['instanceState']))
                                privateIpInstanceCount += 1
                                if ec2Detail['Ec2AssetSourceSimple']['privateIpAddress'] not in scanIpList and ec2Detail['Ec2AssetSourceSimple']['instanceState'] == "RUNNING" and ec2Detail['Ec2AssetSourceSimple']['accountId'] == str(AwsAccountId):
                                    scanIpList.append(str(ec2Detail['Ec2AssetSourceSimple']['privateIpAddress']))
                                    logger.info("Added internal IP to list: {0}\n".format(str(ec2Detail['Ec2AssetSourceSimple']['privateIpAddress'])))

                        else:
                            if "publicIpAddress" in ec2Detail['Ec2AssetSourceSimple']:
                                logger.info ("Instance Metadata InstanceId: {}  AccountId: {}  instanceState: {}".format(ec2Detail['Ec2AssetSourceSimple']['instanceId'],ec2Detail['Ec2AssetSourceSimple']['accountId'],ec2Detail['Ec2AssetSourceSimple']['instanceState']))
                                publicIpInstanceCount += 1
                                if ec2Detail['Ec2AssetSourceSimple']['publicIpAddress'] not in scanIpList and ec2Detail['Ec2AssetSourceSimple']['instanceState'] == "RUNNING" and ec2Detail['Ec2AssetSourceSimple']['accountId'] == str(AwsAccountId):
                                    scanIpList.append(str(ec2Detail['Ec2AssetSourceSimple']['publicIpAddress']))
                                    logger.info("Added external IP to list: {0}\n".format(str(ec2Detail['Ec2AssetSourceSimple']['publicIpAddress'])))
            if str(jsonHostList['ServiceResponse']['hasMoreRecords']) == 'true':
                resultsIndex+=100
                requestBody = "<ServiceRequest>\n\t<filters>\n\t\t<Criteria field=\"instanceState\" operator=\"EQUALS\">RUNNING</Criteria>\n\t\t<Criteria field=\"accountId\" operator=\"EQUALS\">{0}</Criteria>\n\t</filters>\n\t<preferences>\n\t\t<limitResults>{1}</limitResults>\n\t\t<startFromOffset>{2}</startFromOffset>\n\t</preferences>\n</ServiceRequest>\n".format(str(AwsAccountId), str(pageSize), str(resultsIndex))
                logger.debug("More records to pull iterate requestBody with preferences XML -- \n\n\n {0} \n\n\n".format(str(requestBody)))
            else:
                if args.internal:
                    logger.info("**** Private IPv4 count for AWS Account ID {0} = {1} ****".format(str(AwsAccountId),str(privateIpInstanceCount)))
                else:
                    logger.info("**** Public IPv4 count for AWS Account ID {0} = {1} ****".format(str(AwsAccountId),str(publicIpInstanceCount)))
                pulledAllResults = True
        else:
            logger.error("Host Asset List lookup returned no results or errored \n Response \n {0}".format(str(rdata2.text)))
    logger.info("Length of scanIpList = {}".format(len(scanIpList)))
    logger.info(str(scanIpList))
    return scanIpList

def hostTaggedAssetLookup(AccountId, tagId, provider, URL, b64Val, pageSize):
    logger.info("Made it to hostAssetLookup")
    headers = {
        'X-Requested-With': 'Python Requests',
        'Accept': 'application/json',
        'Content-type': 'text/xml',
        'Cache-Control': "no-cache",
        'Authorization': "Basic %s" % b64Val
    }
    publicIpInstanceCount = 0
    scanIpList = []
    pulledAllResults = False
    resultsIndex = 1
    #requestBody = "<ServiceRequest>\n    <filters>\n        <Criteria field=\"instanceState\" operator=\"EQUALS\">RUNNING<\/Criteria>\n        <Criteria field=\"accountId\" operator=\"EQUALS\">{0}<\/Criteria>\n    <\/filters>\n    <preferences>\n        <limitResults>100</limitResults>\n        <startFromOffset>1</startFromOffset>\n    </preferences>\n<\/ServiceRequest>".format(str(AwsAccountId))
    requestBody = "<ServiceRequest>\n\t<filters>\n\t\t<Criteria field=\"tagId\" operator=\"EQUALS\">{0}</Criteria>\n\t</filters>\n\t<preferences>\n\t\t<limitResults>{1}</limitResults>\n\t\t<startFromOffset>1</startFromOffset>\n\t</preferences>\n</ServiceRequest>\n".format(str(tagId),str(pageSize))
    logger.info("Tagged Host Asset request body \n {}".format(str(requestBody)))
    rURL = URL + "/qps/rest/2.0/search/am/hostasset"
    logger.debug("Host asset URL {}".format(str(rURL)))
    while pulledAllResults != True:
        rdata2 = requests.post(rURL, headers=headers, data=requestBody)
        logger.info("Request status code for host assets for Account ID {0} - {1}".format(str(AccountId), str(rdata2.status_code)))
        #logger.debug("Request for AWS Account {0} for host assets \n {1}".format(str(AwsAccountId),str(rdata2.text)))
        jsonHostList = json.loads(rdata2.text)
        logger.debug("**** Count of host assets returned = {0} ****".format(str(jsonHostList['ServiceResponse']['count'])))
        if int(jsonHostList['ServiceResponse']['count']) > 0 and str(jsonHostList['ServiceResponse']['responseCode']) == "SUCCESS":
            logger.debug("Number of assets matching host asset lookup query {}".format(str(jsonHostList['ServiceResponse']['count'])))
            assetList = jsonHostList['ServiceResponse']['data']
            if str(provider) == 'AZURE' or str(provider) == 'azure':
                metadataSearch = 'AzureAssetSourceSimple'
                instanceId = 'vmId'
                accountId = 'subscriptionId'
                state = "state"
            elif str(provider) == 'GCP' or str(provider) == 'gcp':
                metadataSearch = 'GcpAssetSourceSimple'
                instanceId = 'instanceId'
                accountId = 'projectId'
                state = "state"
            elif str(provider) == 'AWS' or str(provider) == 'aws':
                metadataSearch = 'Ec2AssetSourceSimple'
                instanceId = 'instanceId'
                accountId = 'accountId'
                state = "instanceState"
            else:
                logger.error("Provider field map mismatch - return NULL scanIpList")
                return scanIpList

            for instance in assetList:
                metadataDetails = instance['HostAsset']['sourceInfo']['list']
                for instanceDetail in metadataDetails:
                    #logger.debug("EC2 Host Asset info \n {}".format(str(ec2Detail)))
                    if metadataSearch in instanceDetail:
                        #logger.debug("EC2 Asset metadata \n {}".format(str(ec2Detail['Ec2AssetSourceSimple'])))
                        if args.internal == True:
                            if "privateIpAddress" in instanceDetail[str(metadataSearch)]:
                                logger.info ("Instance Metadata InstanceId: {}  AccountId: {}  instanceState: {}".format(instanceDetail[str(metadataSearch)][str(instanceId)],instanceDetail[str(metadataSearch)][accountId],instanceDetail[str(metadataSearch)][str(state)]))
                                #privateIpInstanceCount += 1
                                if instanceDetail[str(metadataSearch)]['privateIpAddress'] not in scanIpList and instanceDetail[str(metadataSearch)][str(state)] == "RUNNING" and instanceDetail[str(metadataSearch)][str(accountId)] == str(AccountId):
                                    if args.activateAssets:
                                        scanIpList.append(str(instanceDetail[str(metadataSearch)]['privateIpAddress']))
                                        logger.info("Added external IP to list: {0}\n".format(str(instanceDetail[str(metadataSearch)]['privateIpAddress'])))
                                    elif str(instance['HostAsset']['trackingMethod']) == "QAGENT" and "VM" in str(instance['HostAsset']['agentInfo']['activatedModule']):
                                        scanIpList.append(str(instanceDetail[str(metadataSearch)]['privateIpAddress']))
                                        logger.info("Added external IP to list: {0}\n".format(str(instanceDetail[str(metadataSearch)]['privateIpAddress'])))
                                    else:
                                        logger.warning("IP Address {0} for Instance ID {1} not activated in VM".format(str(instanceDetail[str(metadataSearch)]['privateIpAddress']),str(instanceDetail[str(metadataSearch)][str(instanceId)])))
                        else:
                            if "publicIpAddress" in instanceDetail[str(metadataSearch)]:
                                logger.info ("Instance Metadata InstanceId: {}  AccountId: {}  instanceState: {}".format(instanceDetail[str(metadataSearch)][str(instanceId)],instanceDetail[str(metadataSearch)][accountId],instanceDetail[str(metadataSearch)][str(state)]))
                                publicIpInstanceCount += 1
                                if instanceDetail[str(metadataSearch)]['publicIpAddress'] not in scanIpList and instanceDetail[str(metadataSearch)][str(state)] == "RUNNING" and instanceDetail[str(metadataSearch)][str(accountId)] == str(AccountId):
                                    if args.activateAssets:
                                        scanIpList.append(str(instanceDetail[str(metadataSearch)]['publicIpAddress']))
                                        logger.info("Added external IP to list: {0}\n".format(str(instanceDetail[str(metadataSearch)]['publicIpAddress'])))
                                    elif str(instance['HostAsset']['trackingMethod']) == "QAGENT" and "VM" in str(instance['HostAsset']['agentInfo']['activatedModule']):
                                        scanIpList.append(str(instanceDetail[str(metadataSearch)]['publicIpAddress']))
                                        logger.info("Added external IP to list: {0}\n".format(str(instanceDetail[str(metadataSearch)]['publicIpAddress'])))
                                    else:
                                        logger.warning("IP Address {0} for Instance ID {1} not activated in VM".format(str(instanceDetail[str(metadataSearch)]['publicIpAddress']),str(instanceDetail[str(metadataSearch)][str(instanceId)])))

            if str(jsonHostList['ServiceResponse']['hasMoreRecords']) == 'true':
                resultsIndex+=100
                requestBody = "<ServiceRequest>\n\t<filters>\n\t\t<Criteria field=\"tagId\" operator=\"EQUALS\">{0}</Criteria>\n\t</filters>\n\t<preferences>\n\t\t<limitResults>{1}</limitResults>\n\t\t<startFromOffset>{2}</startFromOffset>\n\t</preferences>\n</ServiceRequest>\n".format(str(tagId), str(pageSize), str(resultsIndex))
                logger.debug("More records to pull iterate requestBody with preferences XML -- \n\n\n {0} \n\n\n".format(str(requestBody)))
            else:
                logger.info("**** Public IPv4 count for {0} Account ID {1} = {2} ****".format(str(provider),str(AccountId),str(publicIpInstanceCount)))
                pulledAllResults = True
        else:
            logger.error("Host Asset List lookup returned no results or errored \n Response \n {0}".format(str(rdata2.text)))
    logger.info("Length of scanIpList = {}".format(len(scanIpList)))
    logger.info(str(scanIpList))
    return scanIpList


def check_ips_in_qualys(hostList, URL, headers):
    logger.info("Made it to check_ips_in_qualys")
    logger.debug("hostList sent to check_ips_in_qualys \n {}".format(str(hostList)))
    logger.debug("URL sent to check_ips_in_qualys \n {}".format(str(URL)))
    addIps = []
    logger.debug("Printing Headers \n {0}".format(str(headers)))
    if len(hostList) > 0:
        rURL = URL + "/api/2.0/fo/asset/ip/?action=list"
        logger.debug("List IPs in Qualys URL {}".format(rURL))
        rdata = requests.get(rURL, headers=headers)
        logger.debug("Response data from requests get for IP List \n {}".format(str(rdata.text)))
        root = ET.fromstring(rdata.text)
        #logger.debug("XML Tag {0} -- XML Text {1}".format(root[0][1][0].tag, root[0][1][0].text))
        #logger.debug("IP List from Qualys \n {0}".format(list(root[0][1])))
        IPinQualys = []
        for host in hostList:
            hostInQualys = False
            for ip in root[0][1]:
                #print ip.tag + " " + ip.text
                logger.debug("checking host IP {}".format(host))
                logger.info("Comparing {0} to {1}".format(ip.text, host))
                if str(ip.tag) == 'IP' and str(ip.text) == str(host):
                    logger.info("Host already in Qualys Host Asset {}".format(str(host)))
                    hostInQualys = True
                    IPinQualys.append(str(host))
                    break
                elif ip.tag == 'IP_RANGE':
                    rangeBegin, rangeEnd = ip.text.split('-')
                    logger.info("Range Begin {} and Range End {}".format(rangeBegin, rangeEnd))
                    if IPAddress(host) >= IPAddress(rangeBegin) and IPAddress(host) <= IPAddress(rangeEnd):
                        logger.info("IP in IP Range: {0} in {1}".format(str(host), str(ip.text)))
                        IPinQualys.append(str(host))
                        hostInQualys = True
                        break
                    else:
                        logger.info("IP not in IPRange: {0} not in {1}".format(str(host), str(ip.text)))


            if host not in addIps and not hostInQualys:
                logger.debug("Host Does NOT Exist in Qualys IP Ranges")
                addIps.append(str(host))
        logger.debug("Hosts already in Qualys host assets \n {}".format(str(IPinQualys)))
        logger.debug("Hosts NOT in Qualys host assets \n {}".format(str(addIps)))
        if len(addIps) >= 1:
            return addIps
        else:
            logger.info("No IPs to add to Qualys")
            return False
    else:
        logger.warning("Host IP List was NULL, hostList = {0}".format(str(hostList)))
        return False

def addIpsToQualys(addIps, URL, headers):
    logger.debug("Made it to addIpsToQualys")
    logger.info("Adding {} to Qualys".format(str(addIps).encode('utf-8')))
    ips = str(addIps).strip('[]')
    ips = ips.replace(" ", "")
    ips = ips.replace("\'", "")
    logger.info("add IPs to Qualys \n {}".format(ips))
    rURL = URL + "/api/2.0/fo/asset/ip/?action=add&enable_vm=1&ips=" + str(ips)
    logger.debug(rURL)
    rdata = requests.post(rURL, headers=headers)
    logger.debug(rdata.status_code)
    logger.debug(rdata.text)

'''
#### NOT TESTED - Proof of Concept ONLY ###
def purgeIpsFromQualys(purgeIps, URL, headers):
    logger.debug("Made it to purgeIpsFromQualys")
    logger.info("Purging {} from Qualys".format(str(purgeIps).encode('utf-8')))
    ips = str(purgeIps).strip('[]')
    ips = ips.replace(" ", "")
    ips = ips.replace("\'", "")
    logger.info("purge IPs from Qualys \n {}".format(ips))
    #for ip in addIps:
        #if ips:
            #ips = ips + "," + str(ip)
        #else:
            #ips = str(ip)

    rURL = URL + "/api/2.0/fo/asset/ip/?action=purge&enable_vm=1&ips=" + str(ips)
    logger.debug(rURL)
    rdata = requests.post(rURL, headers=headers)
    logger.debug(rdata.status_code)
    logger.debug(rdata.text)
'''




def dnsLookup(accountId, hostList, elbLookup):
    with open(elbLookup,mode='r') as csv_file2:
        elbInfo = csv.DictReader(csv_file2)
        for row in elbInfo:
            logger.info("Processing row {}".format(str(row)))
            try:
                if str(row['accountId']) == accountId:
                    logger.info("DNS Lookup of {0} is {1}".format(str(row['elbDns']), str(socket.gethostbyname(row['elbDns']))))
                    if str(socket.gethostbyname(row['elbDns'])) not in hostList:
                        hostList.append(str(socket.gethostbyname(row['elbDns'])))
            except IOError as e:
                logger.warning("Invlaid ELB DNS Name {0} with error {1}: {2}".format(row['elbDns'], e.errno, e.strerror))
    return hostList


def externalPerimeterScan(ipList, accountId, optionProfileId, URL, b64Val):
    logger.info(ipList)

    headers = {
        'Accept': '*/*',
        'content-type': 'application/json',
        'Authorization': "Basic %s" % b64Val,
        'X-Requested-With': 'Python Requests'
    }

    ipList = ipList.replace(" ", "")
    ipList = ipList.replace("\'", "")
    logger.info("Fixed ipList {}".format(ipList))
    rURL = URL + "/api/2.0/fo/scan/?action=launch&target_from=assets&scan_title={0}_perimeter_scan&priority=5&option_id={1}&ip={2}".format(str(accountId), str(optionProfileId), str(ipList))
    logger.info(rURL)
    rdata = requests.post(rURL, headers=headers)
    logger.info(rdata.status_code)
    logger.info(rdata.text)
    root = ET.fromstring(rdata.text)
    logger.info(root[0][2][1][1].text)
    return root[0][2][1][1].text

def internalScan(ipList, accountId, tagId, scannerName, optionProfileId, URL, b64Val):
    logger.info(ipList)

    headers = {
        'Accept': '*/*',
        'content-type': 'application/json',
        'Authorization': "Basic %s" % b64Val,
        'X-Requested-With': 'Python Requests'
    }

    ipList = ipList.replace(" ", "")
    ipList = ipList.replace("\'", "")
    logger.info("Fixed ipList {}".format(ipList))
    rURL = URL + "/api/2.0/fo/scan/?action=launch&target_from=assets&scan_title={0}_{1}_internal_scan&priority=5&option_id={2}&ip={3}&iscanner_name={4}".format(str(accountId), str(tagId), str(optionProfileId), str(ipList), str(scannerName))
    logger.info(rURL)
    rdata = requests.post(rURL, headers=headers)
    logger.info(rdata.status_code)
    logger.info(rdata.text)
    root = ET.fromstring(rdata.text)
    logger.info(root[0][2][1][1].text)
    return root[0][2][1][1].text


def checkScanStatus(runningScansList, URL, headers):

    logger.info("Made it to checking scan status")
    logger.info("runningScanList = {}".format(runningScansList))
    logger.debug("checking for empty list -- len(runningScansList) = {}".format(len(runningScansList)))
    if len(runningScansList) == 0:
        return 1, runningScansList
    scanRunning = True
    loopCounter = 1
    waitInterval = len(runningScansList)
    while scanRunning:
        for scanRef in runningScansList:
            logger.info("Checking first scan in list {}".format(str(scanRef)))
            rURL = URL + "/api/2.0/fo/scan/?action=list&show_status=1&scan_ref={0}".format(str(scanRef))
            rdata = requests.post(rURL, headers=headers)
            rdata = requests.post(rURL, headers=headers)
            logger.info(rdata.status_code)
            logger.info(rdata.text)
            root = ET.fromstring(rdata.text)
            logger.info("Checking Scan {0} status {1}".format(scanRef, str(root[0][1][0][8][0].text)))
            if str(root[0][1][0][8][0].text) == "Finished":
                runningScansList.remove(scanRef)
                logger.info("Running Scan list is {}".format(runningScansList))
            logger.info("Loop Counter checking for running scans = {}".format(str(loopCounter)))
        logger.info("runningScansList = {}".format(len(runningScansList)))
        if len(runningScansList) == 0:
            scanRunning = False
        if len(runningScansList) > 0:
            interval = int(60 * loopCounter)
            time.sleep(interval)
        loopCounter += 1
        if loopCounter >= 15:
            logger.info("Perimeter scans for are running long \n Scan Refs: {}".format(str(runningScansList).strip("[]")))
        if loopCounter > 20:
            logger.warning("Perimeter scans for are running long \n Scan Refs: {}".format(str(runningScansList).strip("[]")))
            return len(runningScansList), runningScansList
    return 1, runningScansList




def createCsvReport(createReport, csvHeaders, URL, b64Val, exceptionTracking):
    try:
        logger.info("Made it to run CSV report for {}".format(str(createReport)))
        headers = {
            'Authorization': "Basic %s" % b64Val,
            'X-Requested-With': 'Python Requests'
        }

        for accountId, scanRef in createReport.items():
            logger.debug("Account {0} - Processing scanRef {1} results for CSV report".format(str(accountId), str(scanRef)))
            out_file = "reports/" + str(accountId) + "_" "Perimeter_Report_" + time.strftime("%Y%m%d-%H%M%S") + ".csv"
            ofile = open(out_file, "w")
            writer = csv.DictWriter(ofile, fieldnames=csvHeaders)
            writer.writeheader()
            row = {}
            rURL = URL + "/api/2.0/fo/scan/"
            logger.info("Sending post to {}".format(str(rURL)))
            params = {"action": "fetch","scan_ref":str(scanRef),"mode":"extended","output_format":"json_extended"}
            logger.info("Fetch Scan Results Parameters = {}".format(str(params)))
            logger.debug("Fetch scan URL is {}".format(rURL))
            rdata = requests.post(rURL, headers=headers, params=params)
            logger.debug("Fetch scan results response code {}".format(str(rdata.status_code)))
            logger.debug("Type of rdata.text = {}".format(type(rdata.text)))
            logger.debug("Response Data of rdata.text = {}".format(str(rdata.text)))
            #logger.debug("Fetch scan results response body \n {}".format(str(rdata.text)))
            counter = 0
            scanResults = json.loads(str(rdata.text))
            logger.debug("JSON loads list result type \n {}".format(type(scanResults)))
            logger.debug("JSON loads list result length \n {}".format(len(scanResults)))
            if len(scanResults) < 3:
                logger.info("No scan findings for CSV report for Account ID {0} for scanRef {1}".format(str(accountId), str(scanRef)))
            else:
                for finding in scanResults:
                    if counter > 1 and counter < (len(scanResults) - 1):
                        #parsedData = json.loads(finding)
                        for header in csvHeaders:
                            if str(header) in finding.keys():
                                row[header] = finding[header]
                            else:
                                logger.error("CSV Column Header not in finding keys -- {}".format(str(header)))
                                logger.error("Please update csvHeaders with API Response key values only".format(str(header)))
                        if args.exceptiontracking:
                            exceptionDict = {}
                            with open (exceptionTracking, mode='r') as exception_csv_file:
                                exceptionList = csv.DictReader(exception_csv_file)
                                #exceptionDict = exceptionList
                                logger.debug("exceptionList type = {}".format(type(exceptionList)))
                                logger.debug("Read exception list \n {}".format(str(exceptionList)))
                                logger.debug("Initiate Exceptions Processing for {}".format(str(exceptionTracking)))
                                for exception in exceptionList:
                                    logger.debug("Read exception list \n {}".format(str(exception)))
                                    if str(accountId) in exception.itervalues():
                                        if str(finding['qid']) not in exception['QID']:
                                            logger.debug("No Exception for Account {0} and QID {1}".format(str(accountId), str(finding['qid'])))
                                            writer.writerow(row)
                                        else:
                                            logger.debug("****Exception for Account {0} and QID {1}****".format(str(accountId), str(finding['qid'])))
                                    else:
                                        logger.debug("Exception processing - No Exception for Account {0}".format(str(accountId)))
                                        logger.debug("Exception processing - writing row to csv \n {0}".format(str(row)))
                                        writer.writerow(row)
                        else:
                            logger.debug("Writing row to csv \n {0}".format(str(row)))
                            writer.writerow(row)
                    counter += 1
            ofile.close()
        if args.exceptiontracking:
            exception_csv_file.close()
    except IOError as e:
        logger.error("Encountered error in requesting scan results - error # {}".format(str(e.errno)))
        logger.error("Encountered error in requesting scan results - error message \n {}".format(str(e.strerror)))

def scanFromCLA(scannerName, tagId, provider, accountId, connectorId, optionProfileId, internal):
    if provider == "AWS" or provider == "Aws" or provider == "aws":
        provider == "AWS"
    elif provider == "AZURE" or provider == "Azure" or provider == "azure":
        provider == "AZURE"
    elif provider == "GCP" or provider == "Gcp" or provider == "gcp":
        provider == "GCP"
    accountInfoCSV, exceptionTracking, elbLookup, URL, throttle, csvHeaders, pageSize = config()
    username = os.environ["QUALYS_API_USERNAME"]
    password = base64.b64decode(os.environ["QUALYS_API_PASSWORD"])
    usrPass = str(username)+':'+str(password)
    b64Val = base64.b64encode(str(usrPass).encode('ascii'))
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': "Basic %s" % b64Val,
        'X-Requested-With': 'Python Requests'
    }
    hostList = []
    runningScansList = []
    run_connector(connectorId, URL, headers)
    check_connector_status(connectorId, URL, b64Val)
    if not tagId:
        hostList = hostTaggedAssetLookup(accountId, tagId, provider, URL, b64Val, pageSize)
    else:
        hostList = hostAssetLookup(accountId, URL, b64Val, pageSize)
    hostList = dnsLookup(accountId, hostList, elbLookup)
    addIps = check_ips_in_qualys(hostList, URL, headers)
    if addIps:
        addIpsToQualys(addIps, URL, headers)
    if len(hostList) > 0 and len(hostList) < 1000:
        if internal:
            scanRefId = internalScan(str(hostList).strip('[]'), accountId, tagId, scannerName, optionProfileId,URL, b64Val)
        else:
            scanRefId = externalPerimeterScan(str(hostList).strip('[]'), accountId, optionProfileId, URL, b64Val)
    scannedAccounts = []
    scannedAccounts.append(accountId)
    runningScansList.append(scanRefId)
    if args.csvreport:
        logger.info("Adding scan Ref to list for CSV Report {}".format(scanRefId))
        createReport[accountId] = str(scanRefId)
    elif len(hostList) > 1000:
        logger.critical("Scan hostList {} > than 1000 IPs, you will need to modify script scan more than this amount".format(str(len(hostList))))
    else:
        logger.warning("Account {0} returned no targets for Tag {1} for Internal Scan".format(str(accountId), str(tagId)))

    while len(runningScansList) != 0:
        throttleCount, runningScansList = checkScanStatus(runningScansList, URL, headers)

    if args.csvreport:
        logger.debug("createReport: \n {}".format(str(createReport)))
        if len(createReport) > 0:
            createCsvReport(createReport, csvHeaders, URL, b64Val, exceptionTracking)
        else:
            logger.warning("No CVS Reports to create, length of createReport k:v pairing for accountID and scanRef == 0")



def scanFromFile(scope):
    accountInfoCSV, exceptionTracking, elbLookup, URL, throttle, csvHeaders, pageSize = config()
    username = os.environ["QUALYS_API_USERNAME"]
    password = base64.b64decode(os.environ["QUALYS_API_PASSWORD"])
    #logger.debug("Base64 password {0} and Base64decode: {1}".format(str(os.environ["QUALYS_API_PASSWORD"]), str(password)))
    usrPass = str(username)+':'+str(password)
    b64Val = base64.b64encode(str(usrPass).encode('ascii'))
    #logger.debug("b64Val = {}".format(str(b64Val)))
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': "Basic %s" % b64Val,
        'X-Requested-With': 'Python Requests'
    }

    logger.debug("headers value being sent with requests.put/get -- {}".format(str(headers)))
    with open(accountInfoCSV,mode='r') as csv_file:
        accountInfo = csv.DictReader(csv_file)
        runningScansList = []
        createReport = {}
        scanRefId = ''
        throttleCount = 1
        scannedAccounts = []
        if scope == "allAccounts":
            for row in accountInfo:
                hostList = []
                run_connector(row['connectorId'], URL, headers)
                check_connector_status(row['connectorId'], URL, b64Val)
                if row['provider'] == 'AWS' and not args.tagScanAws:
                    hostList = hostAssetLookup(row['accountId'], URL, b64Val, pageSize)
                else:
                    hostList = hostTaggedAssetLookup(row['accountId'], row['tagId'], row['provider'], URL, b64Val, pageSize)

                hostList = dnsLookup(row['accountId'], hostList, elbLookup)
                addIps = check_ips_in_qualys(hostList, URL, headers)
                if addIps:
                    addIpsToQualys(addIps, URL, headers)
                if len(hostList) > 0 and len(hostList) < 1000:
                    if row['accountId'] not in scannedAccounts:
                        if args.internal:
                            scanRefId = internalScan(str(hostList).strip('[]'), row['accountId'], row['tagId'], str(args.scannerName), row['optionProfileId'],URL, b64Val)
                        else:
                            scanRefId = externalPerimeterScan(str(hostList).strip('[]'), row['accountId'], row['optionProfileId'],URL, b64Val)
                        scannedAccounts.append(row['accountId'])
                    runningScansList.append(scanRefId)
                    if args.csvreport:
                        logger.info("Adding scan Ref to list for CSV Report {}".format(scanRefId))
                        createReport[str(row['accountId'])] = str(scanRefId)
                    throttleCount += 1
                elif len(hostList) > 1000:
                    logger.critical("Scan hostList {} > than 1000 IPs, you will need to modify script scan more than this amount".format(str(len(hostList))))
                else:
                    logger.warning("Account {0} returned no targets for Perimeter Scan".format(str(row['accountId'])))
                while throttleCount % throttle == 0:
                    throttleCount, runningScansList = checkScanStatus(runningScansList, URL, headers)


        else:
            for row in accountInfo:
                hostList = []
                if row['accountId'] == scope:
                    #run_connector(row['connectorId'], URL, headers)
                    #check_connector_status(row['connectorId'], URL, b64Val)
                    if row['provider'] == 'AWS' and not args.tagScanAws:
                        hostList = hostAssetLookup(row['accountId'], URL, b64Val, pageSize)
                    else:
                        hostList = hostTaggedAssetLookup(row['accountId'], row['tagId'], row['provider'], URL, b64Val, pageSize)

                    hostList = dnsLookup(row['accountId'], hostList, elbLookup)
                    addIps = check_ips_in_qualys(hostList, URL, headers)
                    if addIps:
                        addIpsToQualys(addIps, URL, headers)
                    if len(hostList) > 0 and len(hostList) < 1000:
                        if args.internal:
                            scanRefId = internalScan(str(hostList).strip('[]'), row['accountId'], row['tagId'], str(args.scannerName), row['optionProfileId'],URL, b64Val)
                        else:
                            scanRefId = externalPerimeterScan(str(hostList).strip('[]'), row['accountId'], row['optionProfileId'],URL, b64Val)
                        runningScansList.append(scanRefId)
                        if args.csvreport:
                            logger.info("Adding scan Ref to list for CSV Report {}".format(scanRefId))
                            createReport[str(row['accountId'])] = str(scanRefId)
                    elif len(hostList) > 1000:
                        logger.critical("Scan hostList {} > than 1000 IPs, you will need to modify script scan more than this amount".format(str(len(hostList))))
                    else:
                        logger.warning("Account {0} returned no targets for Perimeter Scan".format(str(row['accountId'])))

                    break
                elif row['BU'] == scope:
                    run_connector(row['connectorId'], URL, headers)
                    check_connector_status(row['connectorId'], URL, b64Val)
                    if row['provider'] == 'AWS' and not args.tagScanAws:
                        hostList = hostAssetLookup(row['accountId'], URL, b64Val, pageSize)
                    else:
                        hostList = hostTaggedAssetLookup(row['accountId'], row['tagId'], row['provider'], URL, b64Val, pageSize)
                    hostList = dnsLookup(row['accountId'], hostList, elbLookup)
                    logger.info("Host List - \n {}".format(hostList))
                    addIps = check_ips_in_qualys(hostList, URL, headers)
                    if addIps:
                        addIpsToQualys(addIps, URL, headers)
                    if len(hostList) > 0 and len(hostList) <= 1000:
                        if row['accountId'] not in scannedAccounts:
                            if args.internal:
                                scanRefId = internalScan(str(hostList).strip('[]'), row['accountId'], row['tagId'], str(args.scannerName), row['optionProfileId'],URL, b64Val)
                            else:
                                scanRefId = externalPerimeterScan(str(hostList).strip('[]'), row['accountId'], row['optionProfileId'],URL, b64Val)
                            scannedAccounts.append(row['accountId'])
                        if scanRefId not in runningScansList:
                            runningScansList.append(scanRefId)
                        if args.csvreport:
                            logger.info("Adding scan Ref to list for CSV Report {}".format(scanRefId))
                            createReport[str(row['accountId'])] = str(scanRefId)
                        throttleCount += 1
                    elif len(hostList) > 1000:
                        logger.critical("Scan hostList {} > than 1000 IPs, you will need to modify script scan more than this amount".format(str(len(hostList))))
                    else:
                        logger.warning("Account {0} returned no targets for Perimeter Scan".format(str(row['accountId'])))
                    while throttleCount % throttle == 0:
                        throttleCount, runningScansList = checkScanStatus(runningScansList, URL, headers)

        while len(runningScansList) != 0:
            throttleCount, runningScansList = checkScanStatus(runningScansList, URL, headers)
        if args.csvreport:
            logger.debug("createReport: \n {}".format(str(createReport)))
            if len(createReport) > 0:
                createCsvReport(createReport, csvHeaders, URL, b64Val, exceptionTracking)
            else:
                logger.warning("No CVS Reports to create, length of createReport k:v pairing for accountID and scanRef == 0")


parser = argparse.ArgumentParser()
parser.add_argument("--scan", "-s", help="Run perimeter scan per account for accounts in specified <scope>: \n python run-perimeter-scan.py -s <scope> or python logging.py --scan <scope> *** Acceptable scope parameters 'allAccounts', BU or accountId listed in cloud-accounts.csv")
parser.add_argument("--scanFromFile", "-sff", help="Scan from list of cloud accounts listed in file", action="store_true")
parser.add_argument("--csvreport", "-c", help="Create a CSV report for each accounts perimeter scan", action="store_true")
parser.add_argument("--exceptiontracking", "-e", help="Process Exception Tracking CSV for creating CSV reports for accounts, used with -c/--csvreport", action="store_true")
parser.add_argument("--tagScanAws", "-t", help="Process AWS Perimeter Assets with specified Qualys Tag ID", action="store_true")
parser.add_argument("--activateAssets", "-a", help="Activate all IPs in scope of accounts in Qualys Vuln Mgmt Module", action="store_true")
parser.add_argument("--internal", "-i", help="Scan Internal IP with designated scannerName", action="store_true")
parser.add_argument("--scannerName", "-sn", help="ScannerName for Internal/Private IP scans of AWS/aws, AZURE/azure, or GCP/gcp workloads")
parser.add_argument("--tagId", "-ti", help="**Required if not using --scanFromFile/-sff** Tag ID for command line parameter")
parser.add_argument("--provider", "-p", help="**Required if not using --scanFromFile/-sff** Specifiy cloud provider AWS, Azure, or GCP for command line parameter")
parser.add_argument("--accountId", "-ai", help="**Required if not using --scanFromFile/-sff** Specify AWS Account ID, Azure Subscription UUID, or GCP Project ID for command line parameter")
parser.add_argument("--connectorId", "-ci", help="**Required if not using --scanFromFile/-sff** Specify Qualys Connector ID for command line parameter")
parser.add_argument("--optionProfileId", "-o", help="**Required if not using --scanFromFile/-sff** Specify Qualys Option Profile ID for command line parameter")

args = parser.parse_args()
if not args.scan and args.scanFromFile:
    logger.error("Scope is required to run script, please run python run-perimeter-scan.py -h for required command syntax")
    sys.exit(1)
if args.csvreport:
    if not os.path.exists("reports"):
            os.makedirs("reports")
if args.internal and not args.scannerName:
    logger.error("ScannerName is required for internal scan jobs, please re-run with --scannerName={scannerName}")
    sys.exit(1)

if args.internal and not args.scannerName and not rgs.scanFromFile and not args.connectorId and not args.provider and not args.accountId and not args.optionProfileId:
    logger.error("Missing command line argument for command line scan, python run-perimeter-scan.py -h for required command syntax")
    sys.exit(1)

if __name__ == "__main__":
    setup_logging()
    logger = logging.getLogger(__name__)
    if not args.scanFromFile:
        scanFromCLA(str(args.scannerName), str(args.tagId), str(args.provider), str(args.accountId), str(args.connectorId), str(args.optionProfileId), args.internal)
    else:
        scanFromFile(args.scan)
