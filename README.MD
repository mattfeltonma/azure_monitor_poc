# Azure Monitor Proof of Concept with AWS
This solution demonstrates how data and metrics collected from AWS can be delivered to a Log Analytics Workspace using Azure Monitor's HTTP Data Collector API.

## What problem does this solve?
Organizations strive to achieve a single pane of glass for monitoring across cloud services.  Many of times this data is spread across cloud services making it challenging for operations to monitor the environment.  The Azure Monitor HTTP Data Collector API provides a mechanism to deliver data from 3rd party cloud services or on-premises services to an Azure Log Analytics Workspace.  Rich visualizations can then be created using Azure Monitor Log Analytics to achieve a single pane of glass view of an enterprise's environment.

The solution uses an AWS Lambda to gather information about access key usage and delivers that data to a Log Analytics Workspace in an Azure subscription.  The data can then be visualized using Azure Monitor's Log Analytics.

## Requirements

### Python Runtime and Modules
* [Python 3.6](https://www.python.org/downloads/release/python-360/)
* [AWS Boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html?id=docs_gateway)

### AWS Permissions Requirement
* IAM:ListUsers
* IAM:ListAccessKeys
* IAM:GetAccessKeyLastUsed
* KMS:Decrypt and KMS:Encrypt for KMS key used to secure Lambda environment variables

## Setup
The can be pushed using the provided CloudFormation template.  The code must be placed into a ZIP file and placed on an S3 bucket the user creating the CloudFormation stack.  The CloudFormation template requires the Workspace ID and Workspace Key from a Log Analytics Workspace in Azure.

