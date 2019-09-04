#
# Author: Sean Nicholson
# Purpose: Run a cloud perimeter scan using Qualys external scanners
#
#----------------------------------------------------------
#  Script logic flow
#  1 - process a CSV of account info (CSV columns name, accountId, connectorID, BU, optionProfileId).
#  2 - run the associated connectors for the defined scope
#  3 - Check for completion of the connector run
#  4 - Pull list of host assets and external IPs
#  5 - Pull IP List from Qualys VM Host Assets and compare list of external IPs
#  6 - Add external IPs not registered in Qualys VM Host Assets
#  7 - run a scan by IP list
#  8 - (coming soon) check scan status and fetch scan results when complete
#  9 - (coming soon) process scan results and lookup in exceptions tracking CSV to create a CSV
#      for each BU of their detected vulnerabilities
#  10 - (coming soon) Output CSV Columns: accountId, IP, QID, Severity, CVEs, CVSS
#----------------------------------------------------------
# Script Input parameters:
# --scan allAccounts
# --scan <BU>
# --scan <accountId>
#
#----------------------------------------------------------
# version: 1.0.0
# date: 9.4.2019
#----------------------------------------------------------

import sys, requests, os, time, csv, getopt, yaml, json, base64, socket
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
        throttle = config_info['defaults']['throttle']
        if URL == '':
            print "Config information in ./config.yml not configured correctly. Exiting..."
            sys.exit(1)
    return accountInfoCSV, exceptionTracking, elbLookup, URL, throttle


def run_connector(connectorId, URL, headers):
    try:
        rURL = URL + "/qps/rest/2.0/run/am/assetdataconnector/" + str(connectorId)
        rdata = requests.post(rURL, headers=headers)
        logger.info("ConnectorID {0} - run status code {1}\n".format(str(connectorId), rdata.status_code))
        logger.debug("ConnectorID {0} - run status code {1}\n Connector run response \n {2}".format(str(connectorId), rdata.status_code, rdata.text))
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
        rURL = URL + "/qps/rest/2.0/get/am/assetdataconnector/" + str(connectorId)
        logger.info("Check Connector URL: \n {0}".format(str(rURL)))
        rdata = requests.get(rURL, headers=headers)
        logger.info("ConnectorID {0} - run status code {1}\n".format(str(connectorId), rdata.status_code))
        logger.info("ConnectorID {0} - response\n {1}".format(str(connectorId), rdata.text))
        #print rdata.text
        connector_response_data = json.loads(rdata.text)
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
                logger.warning("Connector ID {} did not complete in allotted time - *** this may result in stale asset data ***".format(connectorId))
                connector_run_completed = True

def hostAssetLookup(AwsAccountId, URL, b64Val):
    logger.info("Made it to hostAssetLookup")
    headers = {
        'X-Requested-With': 'Python Requests',
        'Accept': 'application/json',
        'Content-type': 'text/xml',
        'Authorization': "Basic %s" % b64Val
    }

    scanIpList = []
    requestBody = "<ServiceRequest>     \n<filters>\n<Criteria field=\"instanceState\" operator=\"EQUALS\">RUNNING<\/Criteria>\n<Criteria field=\"accountId\" operator=\"EQUALS\">{0}<\/Criteria>\n<\/filters> \n<\/ServiceRequest>".format(str(AwsAccountId))
    #print requestBody
    rURL = URL + "/qps/rest/2.0/search/am/hostasset"
    #print rURL
    rdata2 = requests.post(rURL, headers=headers, data=requestBody)
    #print rdata2.text
    jsonHostList = json.loads(rdata2.text)
    #print rdata2.status_code
    assetList = jsonHostList['ServiceResponse']['data']
    for instance in assetList:
        ec2Details = instance['HostAsset']['sourceInfo']['list']
        for ec2Detail in ec2Details:
            #print ec2Detail
            if "Ec2AssetSourceSimple" in ec2Detail:
                #print ec2Detail['Ec2AssetSourceSimple']
                if "publicIpAddress" in ec2Detail['Ec2AssetSourceSimple']:
                    logger.info ("Instance Metadata InstanceId: {}  AccountId: {}  instanceState: {}".format(ec2Detail['Ec2AssetSourceSimple']['instanceId'],ec2Detail['Ec2AssetSourceSimple']['accountId'],ec2Detail['Ec2AssetSourceSimple']['instanceState']))
                    if ec2Detail['Ec2AssetSourceSimple']['publicIpAddress'] not in scanIpList and ec2Detail['Ec2AssetSourceSimple']['instanceState'] == "RUNNING":
                        scanIpList.append(str(ec2Detail['Ec2AssetSourceSimple']['publicIpAddress']))
                        #print "Added external IP to list: {0}".format(str(ec2Detail['Ec2AssetSourceSimple']['publicIpAddress']))
                        logger.info("Added external IP to list: {0}\n".format(str(ec2Detail['Ec2AssetSourceSimple']['publicIpAddress'])))

    logger.info(str(scanIpList))
    return scanIpList

def check_ips_in_qualys(hostList, URL, headers):
    logger.info("Made it to check_ips_in_qualys")
    addIps = []
    username = os.environ["QUALYS_API_USERNAME"]
    password = base64.b64decode(os.environ["QUALYS_API_PASSWORD"])
    #accountInfoCSV, exceptionTracking, URL, throttle = config()
    usrPass = str(username)+':'+str(password)
    b64Val = base64.b64encode(usrPass)
    headers = {
        'Accept': 'application/json',
        'X-Requested-With' : 'python requests',
        'Authorization': "Basic %s" % b64Val
    }
    rURL = URL + "/api/2.0/fo/asset/ip/?action=list"
    logger.debug("Llist IPs in Qualys URL {}".format(rURL))
    rdata = requests.get(rURL, headers=headers)
    logger.debug("Response data from requests get for IP List".format(rdata.text))
    root = ET.fromstring(rdata.text)
    logger.debug("XML Tag {0} -- XML Text {1}".format(root[0][1][0].tag, root[0][1][0].text))

    IPinQualys = []
    for host in hostList:
        hostInQualys = False
        for ip in root[0][1]:
            #print ip.tag + " " + ip.text
            logger.debug("checking host IP {}".format(host))
            logger.debug("Comparing {0} to {1}".format(ip.text, host))
            if str(ip.tag) == 'IP' and str(ip.text) == str(host):
                logger.info("Host already in Qualys Host Asset {}".format(str(host)))
                hostInQualys = True
                IPinQualys.append(str(host))
                break
            elif ip.tag == 'IP_RANGE':
                rangeBegin, rangeEnd = ip.text.split('-')
                logger.debug("Range Begin {} and Range End {}".format(rangeBegin, rangeEnd))
                hostAddr = host.split('.')
                if int(hostAddr[0]) >= int(rangeBegin[0]) and int(hostAddr[0]) <= int(rangeEnd[0]) and int(hostAddr[1]) >= int(rangeBegin[1]) and int(hostAddr[1]) <= int(rangeEnd[1]) and int(hostAddr[2]) >= int(rangeBegin[2]) and int(hostAddr[2]) <= int(rangeEnd[2]) and int(hostAddr[3]) >= int(rangeBegin[3]) and int(hostAddr[3]) <= int(rangeEnd[3]):
                    logger.debug("Host exists in Qualys")
                    logger.debug("IP Compare Works!!!")
                    IPinQualys.append(str(host))
                    hostInQualys = True
                    break

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
    #for child in root.iter('IP_SET'):
    #    print child.attrib




def addIpsToQualys(addIps, URL, headers):
    logger.debug("Made it to addIpsToQualys")
    logger.info("Adding {} to Qualys".format(str(addIps).encode('utf-8')))
    ips = str(addIps).strip('[]')
    ips = ips.replace(" ", "")
    ips = ips.replace("\'", "")
    logger.info("add IPs to Qualys \n {}".format(ips))
    #for ip in addIps:
        #if ips:
            #ips = ips + "," + str(ip)
        #else:
            #ips = str(ip)

    rURL = URL + "/api/2.0/fo/asset/ip/?action=add&enable_vm=1&ips=" + str(ips)
    logger.debug(rURL)
    rdata = requests.post(rURL, headers=headers)
    logger.debug(rdata.status_code)
    logger.debug(rdata.text)


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
    return 0

def external_scan(scope):
    accountInfoCSV, exceptionTracking, elbLookup, URL, throttle = config()
    username = os.environ["QUALYS_API_USERNAME"]
    password = base64.b64decode(os.environ["QUALYS_API_PASSWORD"])
    usrPass = str(username)+':'+str(password)
    b64Val = base64.b64encode(usrPass)
    headers = {
        'Accept': 'application/json',
        'content-type': 'application/json',
        'Authorization': "Basic %s" % b64Val,
        'X-Requested-With': 'Python Requests'
    }

    with open(accountInfoCSV,mode='r') as csv_file:
        accountInfo = csv.DictReader(csv_file)
        throttleCount = 1
        if scope == "allAccounts":
            for row in accountInfo:
                if throttleCount % throttle != 0:
                    run_connector(row['connectorId'], URL, headers)
                    check_connector_status(row['connectorId'], URL, b64Val)
                    hostList = hostAssetLookup(row['accountId'], URL, b64Val)
                    hostList = dnsLookup(row['accountId'], hostList, elbLookup)
                    #print hostList
                    addIps = check_ips_in_qualys(hostList, URL, headers)
                    if addIps:
                        addIpsToQualys(addIps, URL, headers)
                    externalPerimeterScan(str(hostList).strip('[]'), row['accountId'], row['optionProfileId'],URL, b64Val)
                    throttleCount += 1


        else:
            for row in accountInfo:
                if row['accountId'] == scope:
                    run_connector(row['connectorId'], URL, headers)
                    check_connector_status(row['connectorId'], URL, b64Val)
                    hostList = hostAssetLookup(row['accountId'], URL, b64Val)
                    hostList = dnsLookup(row['accountId'], hostList, elbLookup)
                    addIps = check_ips_in_qualys(hostList, URL, headers)
                    if addIps:
                        addIpsToQualys(addIps, URL, headers)
                    externalPerimeterScan(str(hostList).strip('[]'), row['accountId'], row['optionProfileId'],URL, b64Val)
                    throttleCount += 1
                    break
                elif row['BU'] == scope:
                    if throttleCount % throttle != 0:
                        run_connector(row['connectorId'], URL, headers)
                        check_connector_status(row['connectorId'], URL, b64Val)
                        hostList = hostAssetLookup(row['accountId'], URL, b64Val)
                        hostList = dnsLookup(row['accountId'], hostList, elbLookup)
                        #print hostList
                        addIps = check_ips_in_qualys(hostList, URL, headers)
                        if addIps:
                            addIpsToQualys(addIps, URL, headers)
                        externalPerimeterScan(str(hostList).strip('[]'), row['accountId'], row['optionProfileId'],URL, b64Val)
                        throttleCount += 1
                    else:
                        throttleCount += 1
                        #coming soon - put in code for checking scan IDs and checking for scan status completed.


parser = argparse.ArgumentParser()
parser.add_argument("--scan", "-s", help="Run report for accounts in specified <scope>: \n python run-perimeter-scan.py -s <scope> or python logging.py --scan <scope> *** Acceptable scope parameters 'allAccounts', BU or accountId listed in cloud-accounts.csv")
args = parser.parse_args()
if not args.scan:
    logger.error("Scope is required to run script, please run python run-perimeter-scan.py -h for required command syntax")
    sys.exit(1)

if __name__ == "__main__":
    setup_logging()
    logger = logging.getLogger(__name__)
    external_scan(args.scan)
