# Azure Monitor Proof of Concept with 3rd Party Cloud Provider
This solution demonstrates how data and metrics collected from a third-party cloud provider can be delivered to a Log Analytics Workspace for analysis using Azure Monitor's HTTP Data Collector API.

## What problem does this solve?
Organizations strive to achieve a single pane of glass for monitoring across cloud services.  Many of times this data is spread across cloud services making it challenging for operations to monitor the environment.  The Azure Monitor HTTP Data Collector API provides a mechanism to deliver data from 3rd party cloud services or on-premises services to an Azure Log Analytics Workspace.  Rich visualizations can then be created using Azure Monitor Log Analytics to achieve a single pane of glass view of an enterprise's environment.

The solution uses an AWS Lambda to gather information about access key usage and delivers that data to a Log Analytics Workspace in an Azure subscription.  The data can then be visualized using Azure Monitor's Log Analytics.

## Requirements

### Python Runtime and Modules
* [Python 3.6](https://www.python.org/downloads/release/python-360/)
* [AWS Boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html?id=docs_gateway)
** Boto3 - 1.9.188
** Bootcore - 1.12.188

### AWS Permissions Requirement
* IAM:ListUsers
* IAM:ListGroups
* IAM:ListRoles
* IAM:GenerateServiceLastAccessedDetails
* IAM:GetServiceLastAccessedDetails

## Setup
Ensure the appropriate version of Boto3 and Botocore are installed. A sample parameters file is provided with the repository.

python service_last_accessed.py --parameterfile parameters.json [--logfile]
