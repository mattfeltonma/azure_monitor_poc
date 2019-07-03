import json
import logging
import re
import csv
import boto3
import os
import hmac
import base64
import hashlib
import datetime

from io import StringIO
from datetime import datetime
from botocore.vendored import requests

# Parse the IAM User ARN to extract the AWS account number
def parse_arn(arn_string):
    acct_num = re.findall(r'(?<=:)[0-9]{12}',arn_string)
    return acct_num[0]
    
# Convert timestamp to one more compatible with Azure Monitor
def transform_datetime(awsdatetime):
    transf_time = awsdatetime.strftime("%Y-%m-%dT%H:%M:%S")
    return transf_time
    
# Query for a list of AWS IAM Users
def query_iam_users():
    
    todaydate = (datetime.now()).strftime("%Y-%m-%d")
    users = []
    client = boto3.client(
        'iam'
    )

    paginator = client.get_paginator('list_users')
    response_iterator = paginator.paginate()
    for page in response_iterator:
        for user in page['Users']:
            user_rec = {'loggedDate':todaydate,'username':user['UserName'],'account_number':(parse_arn(user['Arn']))}
            users.append(user_rec)
    return users

# Query for a list of access keys and information on access keys for an AWS IAM User
def query_access_keys(user):
    keys = []
    client = boto3.client(
        'iam'
    )
    paginator = client.get_paginator('list_access_keys')
    response_iterator = paginator.paginate(
        UserName = user['username']
    )

    # Get information on access key usage
    for page in response_iterator:
        for key in page['AccessKeyMetadata']:
            response = client.get_access_key_last_used(
                AccessKeyId = key['AccessKeyId']
            )
            # Santize key before sending it along for export

            sanitizedacctkey = key['AccessKeyId'][:4] + '...' + key['AccessKeyId'][-4:]
            # Create new dictonionary object with access key information
            if 'LastUsedDate' in response.get('AccessKeyLastUsed'):

                key_rec = {'loggedDate':user['loggedDate'],'user':user['username'],'account_number':user['account_number'],
                'AccessKeyId':sanitizedacctkey,'CreateDate':(transform_datetime(key['CreateDate'])),
                'LastUsedDate':(transform_datetime(response['AccessKeyLastUsed']['LastUsedDate'])),
                'Region':response['AccessKeyLastUsed']['Region'],'Status':key['Status'],
                'ServiceName':response['AccessKeyLastUsed']['ServiceName']}
                keys.append(key_rec)
            else:
                key_rec = {'loggedDate':user['loggedDate'],'user':user['username'],'account_number':user['account_number'],
                'AccessKeyId':sanitizedacctkey,'CreateDate':(transform_datetime(key['CreateDate'])),'Status':key['Status']}
                keys.append(key_rec)
    return keys

def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")  
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization
    
def post_data(customer_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri,data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        print("Accepted")
    else:
        print("Response code: {}".format(response.status_code))


def lambda_handler(event, context):

    # Enable logging to console
    logging.basicConfig(level=logging.INFO,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    try:

        # Initialize empty records array
        #
        key_records = []
        
        # Retrieve list of IAM Users
        logging.info("Retrieving a list of IAM Users...")
        users = query_iam_users()

        # Retrieve list of access keys for each IAM User and add to record
        logging.info("Retrieving a listing of access keys for each IAM User...")
        for user in users:
            key_records.extend(query_access_keys(user))
        # Prepare data for sending to Azure Monitor HTTP Data Collector API
        body = json.dumps(key_records)
        post_data(os.environ['WorkspaceId'], os.environ['WorkspaceKey'], body, os.environ['LogName'])

    except Exception as e:
        logging.error("Execution error",exc_info=True)
