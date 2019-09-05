# cloud-perimeter-scan


# License
THIS SCRIPT IS PROVIDED TO YOU "AS IS."  TO THE EXTENT PERMITTED BY LAW, QUALYS HEREBY DISCLAIMS ALL WARRANTIES AND LIABILITY FOR THE PROVISION OR USE OF THIS SCRIPT.  IN NO EVENT SHALL THESE SCRIPTS BE DEEMED TO BE CLOUD SERVICES AS PROVIDED BY QUALYS

# Summary
Python script for running AWS Cloud Perimeter Scan via Qualys API. Script will process a CSV of AWS Accounts and then iterate that CSV for the specified scope.

Script logic flow
1 - process a CSV of account info (CSV columns name, accountId, connectorID, BU, optionProfileId).
2 - run the associated connectors for the defined scope
3 - Check for completion of the connector run
4 - Pull list of host assets and external IPs
5 - Pull IP List from Qualys VM Host Assets and compare list of external IPs
6 - Add external IPs not registered in Qualys VM Host Assets
7 - run a scan by IP list
8 - (coming soon) check scan status and fetch scan results when complete
9 - (coming soon) process scan results and lookup in exceptions tracking CSV to create a CSV for each BU of their detected vulnerabilities
10 - (coming soon) Output CSV Columns: accountId, IP, QID, Severity, CVEs, CVSS

#Configure Script
To run the script you will need:

1. Credentials for the Qualys user name and password - stored in the form of environment variables

The Script is configured to read environmental variables for user name and password
$QUALYS_API_USERNAME
$QUALYS_API_PASSWORD

> QUALYS_API_USERNAME stores the Qualys API User Name

> QUALYS_API_PASSWORD stores the base64 encoded password for Qualys API
to encode the password using base64 encoding execute the following command substituting the API Account Password for "APIpassword" - make sure the password is in '' or ""

export $QUALYS_API_PASSWORD = \`echo -n "APIpassword" | base64\`

in ./config/config.yml set the values for:

1. Qualys API endpoint URL for your Qualys Platform

2. CSV file accountInfo  - Requirements defined below, default value set to ./cloud-accounts.csv

3. CSV file elbLookup - Requirements defined below, default value set to ./elb-dns.csv

4. exceptionTracking, cleanUp, and throttle will be added soon.

# Prerequisites
This script is written in Python 2.7.
The script relies on the following Python modules to execute: sys, requests, os, time, csv, getopt, logging, yaml, json, base64, logging.config, argparse, and xml.etree.ElementTree

For module missing warnings/errors use PIP to install modules
> for Linux

`pip install pyyaml`

> for Windows

`python -m pip install pyyaml`



# Parameters:

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
    This script uses columns elbDns and accountId by column name, if these are not present in the file, the script will log errors on ELB DNS lookups


# Running run-perimeter-scan.py
This script is written in Python 2.7. It requires a command line argument to run and can be executeed using the following command
    > python run-perimeter-scan.py -s <scope>

or

    > python run-perimeter-scan.py --scan <scope>

scope - accepts one of three input types

allAccount (case sensitive) - run perimeter scan for each account listed in cloud_accounts.csv

BU - run perimeter scan for each account listed for the specified Business Unit defined in cloud_accounts.csv

accountId - run perimeter scan for the account ID specified in cloud_accounts.csv


# Logging
Logging configuration files is located in ./config/logging.yml. To change logging behavior, make changes in this file. For information on Python 2.7 logging visit https://docs.python.org/2/library/logging.html
Logging configuration
File Handler writes to ./log/cloudviewreports.log
Maximum Log size = 10 MB ( logging.yml line 18 - maxBytes: 10485760 # 10MB)
Backup file count = 5 (logging.yml line 19 - backupCount: 5)
Log Level = INFO (Change to WARNING or higher for production - logging.yml line 15 - level: INFO)
