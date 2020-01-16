# cloud-perimeter-scan
version 1.1.0

# License
THIS SCRIPT IS PROVIDED TO YOU "AS IS."  TO THE EXTENT PERMITTED BY LAW, QUALYS HEREBY DISCLAIMS ALL WARRANTIES AND LIABILITY FOR THE PROVISION OR USE OF THIS SCRIPT.  IN NO EVENT SHALL THESE SCRIPTS BE DEEMED TO BE CLOUD SERVICES AS PROVIDED BY QUALYS

# Summary
Python script for running AWS Cloud Perimeter Scan via Qualys API. Script will process a CSV of AWS Accounts and then iterate that CSV for the specified scope.

Script scanFromFile logic flow
1 - process a CSV of account info (CSV columns name, accountId, connectorID, BU, optionProfileId).
2 - run the associated connectors for the defined scope
3 - Check for completion of the connector run
4 - Pull list of host assets and external IPs
5 - Pull IP List from Qualys VM Host Assets and compare list of external IPs
6 - Add external IPs not registered in Qualys VM Host Assets
7 - run a scan by IP list
8 - check scan status and fetch scan results when complete
9 - If csvreport option used, process scan results (lookup in exceptions tracking CSV if --exception options used) to create a CSV Report for the detected vulnerabilities for each AWS Account

Script command line parameter logic flow
1 - run the specified connectorId
3 - Check for completion of the connector run
4 - Pull list of host assets and (internal or external) IPs
5 - Pull IP List from Qualys VM Host Assets and compare list of IPs
6 - Add IPs not registered in Qualys VM Host Assets
7 - run a scan by IP list
8 - check scan status and fetch scan results when complete
9 - If csvreport option used, process scan results (lookup in exceptions tracking CSV if --exception option used) to create a CSV Report for the detected vulnerabilities for specified AWS Account

# Worflow examples
1. Process a CSV file listed in .config/config.yml with list of accounts/subscriptions/projects which contains the accounts/subscriptions/projects, connectorID's, optionProfileId's, tagId's to perform an external perimeter non-authenticated VM scan. Any IP that is not activated in the VM application should be activated. Create a CSV report for each account with exceptions listed in an exceptions.csv file
> python run-perimeter-scan.py -sff -s allAccounts -e -c -a

2. Process a CSV file listed in .config/config.yml with list of accounts/subscriptions/projects which contains the accounts/subscriptions/projects, connectorID's, optionProfileId's, tagId's to perform an external perimeter non-authenticated VM scan. Any IP that is not activated in the VM application should be excluded from the scan scope. Create a CSV report for each account with exceptions listed in an exceptions.csv file
> python run-perimeter-scan.py -sff -s allAccounts -e -c

3. Process a CSV file listed in .config/config.yml with list of accounts/subscriptions/projects which contains the accounts/subscriptions/projects, connectorID's, optionProfileId's, tagId's to perform an external perimeter non-authenticated VM scan. Any IP that is not activated in the VM application should be activated. Create a CSV report for each account
> python run-perimeter-scan.py -sff -s allAccounts -c -a

4. Process a CSV file listed in .config/config.yml with list of accounts/subscriptions/projects which contains the accounts/subscriptions/projects, connectorID's, optionProfileId's, tagId's to perform an internal VM scan. Any IP that is not activated in the VM module should be activated. Create a CSV report for each account with exceptions listed in an exceptions.csv file
> python run-perimeter-scan.py -sff -s allAccounts -e -c -a -i -sn Example-Qualys-Scanner_name

5. Create a internal private IP address target scan job for an Azure Account, with specified optionProfileId and tagId scope. Activate all asset IPs within scope that not already activated in the VM module
> python run-perimeter-scan.py -a -i -sn Example-Qualys-Scanner_name -ci 123456 -ai d9cce66b-0407-4fd2-a3e6-7421e54bc156 -ti 12345678

6. Create a internal private IP address target scan job for an Azure Account, with specified optionProfileId and tagId scope. Activate all asset IPs within scope that not already activated in the VM module. Create a CSV report of scan results.
> python run-perimeter-scan.py -a -i -sn Example-Qualys-Scanner_name -ci 123456 -ai d9cce66b-0407-4fd2-a3e6-7421e54bc156 -ti 12345678 -c

# Configure Script
To run the script you will need:

1. Credentials for the Qualys user name and password - stored in the form of environment variables

The Script is configured to read environmental variables for user name and password
$QUALYS_API_USERNAME
$QUALYS_API_PASSWORD

> QUALYS_API_USERNAME stores the Qualys API User Name

> QUALYS_API_PASSWORD stores the base64 encoded password for Qualys API
to encode the password using base64 encoding execute the following command substituting the API Account Password for "APIpassword" - make sure the password is in '' or ""

export $QUALYS_API_PASSWORD=\`echo -n "APIpassword" | base64\`


in ./config/config.yml set the values for:

1. Qualys API endpoint URL for your Qualys Platform

2. CSV file accountInfo  - Requirements defined below, default value set to ./cloud-accounts.csv

3. CSV file elbLookup - Requirements defined below, default value set to ./elb-dns.csv

4. CSV file exceptionTracking - Requirement defined below, default value set to ./exception-tracking.csv

5. concurrentScans - set to less than your Qualys concurrent scans limit

6. csvHeaders - List of CSV column headers for AWS Account CSV Report. Must be list type entry ['example', 'example2']. Value MUST be congruent to the response keys list in the API response for an API call to fetch scan results.

# Prerequisites
This script is written in Python 2.7.
The script relies on the following Python modules to execute: sys, requests, os, time, csv, getopt, logging, yaml, json, base64, logging.config, argparse, xml.etree.ElementTree, and netaddr

For module missing warnings/errors use PIP to install modules
> for Linux

`pip install pyyaml`

> for Windows

`python -m pip install pyyaml`


# Parameters:
>./config/config.yml
  apiURL:

    Default: Qualys API URL for API endpoint. See https://www.qualys.com/docs/qualys-api-vmpc-user-guide.pdf page 8    

  accountInfo:

    File location of the Cloud Account map. This provide the information for the script to send CloudView CSA Reports to the specified Slack Channel for each Cloud account. Default value is specified as "./cloud-accounts.csv"

    *CSV File Requirements*
    *CSV columns* - name,accountId,connectorId,BU,optionProfileId
    The script uses the columns name, accountId, connectorId, BU, and optionProfileId by those column names. If the columns headers for *columns name, accountId, connectorId, BU, and optionProfileId are not included in the CSV*, the script will *error* and not execute.

    >name: Descriptive / Friendly name for account

    >accountId: AWS Account ID

    >connectorId: specify the Qualys AssetView AWS Connector ID. Can be found by viewing the properties of the connector or listing out all the connectors via an API call. See https://www.qualys.com/docs/qualys-asset-management-tagging-api-v2-user-guide.pdf page 139

    >BU: Business Unit for the specified account. Used if wanting to perform a perimeter scan of multiple accounts for a particular Business Unit.

    >optionProfileId: specify the Qualys VM Option Profile ID to use for the perimeter scan.

  elbLookup:

    File location of the ELB DNS and AWS Accounts CSV. This will provide the information for the ELB DNS for the script to perform a DNS lookup, and specify the scope for the ELB DNS.

    *CSV File Requirements*
    *CSV columns* - elbDns,accountId
    *Example Data* - example.region.elb.amazonaws.com,123456789012
    This script uses columns elbDns and accountId by column name, if these are not present in the file, the script will log errors on ELB DNS lookups

  cloud-accounts.csv helper file:

    A helper file is provided for creating the ./cloud-accounts.csv file from the Qualys AssetView Connectors list for all connectors
    that have

    1. Activation for VM module
    2. disabled=false
    3. type=AWS

    This helper file will not provide BU, tagId, or tagName fields. The helper file can be modified to populate this values as needed.
    helper file provides the data for name, accountId, and connectorId from the Qualys AssetView Connector list and takes one input
    "--optionprofile 123456"
    To run the helper file run: python create_cloudAccounts_map.py --optionprofile 123456

  exceptionTracking:

    File location of the exception tracking for creating CSV for each AWS Accounts CSV. This will provide the information for the for QID exceptions tracked per AWS Account.

    *CSV File Requirements*
    *CSV columns* - Description of Account,accountId,QID
    *Example Data* - Testing Exceptions,123456789012,['123456','234567']
    This script uses columns accountId and QID by column name, if these are not present in the file and you have specified the exception tracking in the CSV report, the script will error.


# Running run-perimeter-scan.py
This script is written in Python 2.7. It requires a command line argument to run and can be executeed using the following command
    > python run-perimeter-scan.py -s <scope>

or

    > python run-perimeter-scan.py --scan <scope>

Command line Parameters:

usage: run-perimeter-scan.py [-h] [--scan SCAN] [--scanFromFile] [--csvreport]
                             [--exceptiontracking] [--tagScanAws]
                             [--activateAssets] [--internal]
                             [--scannerName SCANNERNAME] [--tagId TAGID]
                             [--provider PROVIDER] [--accountId ACCOUNTID]
                             [--connectorId CONNECTORID]
                             [--optionProfileId OPTIONPROFILEID]

                             optional arguments:
                               -h, --help            show this help message and exit
                               --scan SCAN, -s SCAN  Run perimeter scan per account for accounts in
                                                     specified <scope>: python run-perimeter-scan.py -s
                                                     <scope> or python logging.py --scan <scope> ***
                                                     Acceptable scope parameters 'allAccounts', BU or
                                                     accountId listed in cloud-accounts.csv
                               --scanFromFile, -sff  Scan from list of cloud accounts listed in file
                               --csvreport, -c       Create a CSV report for each accounts perimeter scan
                               --exceptiontracking, -e
                                                     Process Exception Tracking CSV for creating CSV
                                                     reports for accounts, used with -c/--csvreport
                               --tagScanAws, -t      Process AWS Perimeter Assets with specified Qualys Tag
                                                     ID
                               --activateAssets, -a  Activate all IPs in scope of accounts in Qualys Vuln
                                                     Mgmt Module
                               --internal, -i        Scan Internal IP with designated scannerName
                               --scannerName SCANNERNAME, -sn SCANNERNAME
                                                     ScannerName for Internal/Private IP scans of AWS/aws,
                                                     AZURE/azure, or GCP/gcp workloads
                               --tagId TAGID, -ti TAGID
                                                     **Required if not using --scanFromFile/-sff** Tag ID
                                                     for command line parameter
                               --provider PROVIDER, -p PROVIDER
                                                     **Required if not using --scanFromFile/-sff** Specifiy
                                                     cloud provider AWS, Azure, or GCP for command line
                                                     parameter
                               --accountId ACCOUNTID, -ai ACCOUNTID
                                                     **Required if not using --scanFromFile/-sff** Specify
                                                     AWS Account ID, Azure Subscription UUID, or GCP
                                                     Project ID for command line parameter
                               --connectorId CONNECTORID, -ci CONNECTORID
                                                     **Required if not using --scanFromFile/-sff** Specify
                                                     Qualys Connector ID for command line parameter
                               --optionProfileId OPTIONPROFILEID, -o OPTIONPROFILEID
                                                     **Required if not using --scanFromFile/-sff** Specify
                                                     Qualys Option Profile ID for command line parameter



# Logging
Logging configuration files is located in ./config/logging.yml. To change logging behavior, make changes in this file. For information on Python 2.7 logging visit https://docs.python.org/2/library/logging.html
Logging configuration
File Handler writes to ./log/cloudviewreports.log
Maximum Log size = 10 MB ( logging.yml line 18 - maxBytes: 10485760 # 10MB)
Backup file count = 5 (logging.yml line 19 - backupCount: 5)
Log Level = INFO (Change to WARNING or higher for production - logging.yml line 15 - level: INFO)
