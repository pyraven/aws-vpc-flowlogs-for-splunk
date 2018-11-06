import boto3
import json
from botocore.exceptions import ClientError
import sys

"""
author: pyraven
comments:
> This script can be used to set up VPC Flow Logs for the AWS Splunk App. I'm hoping this script
> handles the cloudwatch/kinesis configuration. All that should be left is the set up the inputs.

> Huge kudos to @Ahmed Kira - https://www.youtube.com/watch?v=qlHruXd3eYs
> Pretty much helping automate this video ^
"""

names_dictionary = {
    "log_group_name": "Splunk-VPC-Logs",
    "kinesis_stream_name": "Splunk-VPC-Kinesis-Stream",
    "number_of_shards": 1,
    "cloudwatch_role": "flowlogsRole",
    "inline-policy-name": "flowlogsRole-policy",
    "vpc-account-number": "", #aws_account number used in setting up kinesis to cloudwatch
    "vpc-id": "", #vpc to enable flow logs
    "trust-role": "splunk-vpc-cloudwatch-role",
    "trust-policy-inline": "splunk-vpc-cloudwatch-policy",
    "aws-region": "us-east-2"
}

if __name__ == '__main__':

    # Create Log Group
    print("[+] Creating log group stream...")

    try:
        log_client = boto3.client('logs')
        log_response = log_client.create_log_group(logGroupName=names_dictionary['log_group_name'])
    except ClientError as log_error:
        if log_error.response['Error']['Code'] == 'ResourceAlreadyExistsException':
            print("-->[X] group already exists... skipping")
        else:
            sys.exit(log_error)

    # Create Flow Log Role
    print("[+] Creating cloudwatch flow logs role...")
    cloudwatch_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
            "Action": "sts:AssumeRole"}
    }
    )
    cloudwatch_inline_policy = json.dumps({
        "Statement": [
            {
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams",
                    "logs:PutLogEvents"
                ],
                "Effect": "Allow",
                "Resource": "*"
            }
        ]
    })
    try:
        cloudwatch_flow_logs = boto3.resource('iam')
        inline_client = boto3.client('iam')
        cloudwatch_response = cloudwatch_flow_logs.create_role(RoleName=names_dictionary['cloudwatch_role'],
                                                               AssumeRolePolicyDocument=cloudwatch_policy)
        inline_response = inline_client.put_role_policy(
            RoleName=names_dictionary['cloudwatch_role'],
            PolicyName=names_dictionary['inline-policy-name'],
            PolicyDocument=cloudwatch_inline_policy
        )
    except ClientError as cloudwatch_error:
        if cloudwatch_error.response['Error']['Code'] == 'EntityAlreadyExists':
            print("-->[X] role already exists... skipping")
        else:
            sys.exit(cloudwatch_error)

    # Create Kinesis Stream
    print("[+] Creating kinesis stream...")
    try:
        kinesis_client = boto3.client('kinesis')
        kinesis_response = kinesis_client.create_stream(
            StreamName=names_dictionary['kinesis_stream_name'],
            ShardCount=names_dictionary['number_of_shards']
        )
    except ClientError as kinesis_error:
        if kinesis_error.response['Error']['Code'] == 'ResourceInUseException':
            print("-->[X] kinesis stream already exists... skipping")
        else:
            sys.exit(kinesis_error)

    # Create VPC Flow Logs
    print("[+] Creating vpc flowlogs stream...")
    try:
        ec2 = boto3.client('ec2')
        flowlogs_response = ec2.create_flow_logs(
            DeliverLogsPermissionArn=f"arn:aws:iam::{names_dictionary['vpc-account-number']}:role/{names_dictionary['cloudwatch_role']}",
            LogGroupName=names_dictionary['log_group_name'],
            ResourceIds=[names_dictionary['vpc-id']],  # vpc_id, update this, must be in a list
            ResourceType='VPC',
            TrafficType='ALL',
        )
    except ClientError as vpc_error:
        if vpc_error.response['Error']['Code'] == 'FlowLogAlreadyExists':
            print("-->[X] flow already exists... skipping")
        else:
            sys.exit(vpc_error)

    # Create Trust Role and Policy
    print("Creating trust policy...")
    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Principal": {"Service": f"logs.{names_dictionary['aws-region']}.amazonaws.com"},
            "Action": "sts:AssumeRole"}
    })
    try:
        tp = boto3.resource('iam')
        tp_response = tp.create_role(RoleName=names_dictionary['trust-role'],
                                     AssumeRolePolicyDocument=trust_policy)
    except ClientError as tp_error:
        if tp_error.response['Error']['Code'] == 'EntityAlreadyExists':
            print("-->[X] user already exists... skipping")
        else:
            sys.exit(tp_error)

    # Attach Policy
    print("[+] Attaching inline policy...")
    tp_inline_flowlog_policy = json.dumps({
        "Statement": [
            {"Effect": "Allow",
             "Action": "kinesis:PutRecord",
             "Resource": f"arn:aws:kinesis:{names_dictionary['aws-region']}:{names_dictionary['vpc-account-number']}:stream/{names_dictionary['kinesis_stream_name']}"
             },
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": f"arn:aws:iam::{names_dictionary['vpc-account-number']}:role/{names_dictionary['trust-role']}"
            }]
    })
    try:
        tp_inline_client = boto3.client('iam')
        tp_inline_response = tp_inline_client.put_role_policy(
            RoleName=names_dictionary['trust-role'],
            PolicyName=names_dictionary['trust-policy-inline'],
            PolicyDocument=tp_inline_flowlog_policy
        )

    except ClientError as inline_error:
        if inline_error.response['Error']['Code'] == 'EntityAlreadyExists':
            print("-->[X] policy attached already...skipping")
        else:
            sys.exit(inline_error)

    # Subscripter Filter Mapper:
    print("[+] Mapping kinesis stream to cloudwatch...")
    try:
        map_client = boto3.client('logs')
        map_response = map_client.put_subscription_filter(
            logGroupName=names_dictionary['log_group_name'],
            filterName="send-all",
            filterPattern="",
            destinationArn=f"arn:aws:kinesis:{names_dictionary['aws-region']}:{names_dictionary['vpc-account-number']}:stream/{names_dictionary['kinesis_stream_name']}",
            roleArn=f"arn:aws:iam::{names_dictionary['vpc-account-number']}:role/{names_dictionary['trust-role']}"
        )
        print()
        print("...Done.")
    except ClientError as map_error:
        if map_error.response['Error']['Code'] == 'EntityAlreadyExists':
            print("-->[X] role already exists... skipping")
        else:
            sys.exit(map_error)