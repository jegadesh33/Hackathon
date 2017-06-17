{\rtf1\ansi\ansicpg1252\cocoartf1504\cocoasubrtf810
{\fonttbl\f0\fswiss\fcharset0 Helvetica;}
{\colortbl;\red255\green255\blue255;}
{\*\expandedcolortbl;;}
\paperw11900\paperh16840\margl1440\margr1440\vieww10800\viewh8400\viewkind0
\pard\tx566\tx1133\tx1700\tx2267\tx2834\tx3401\tx3968\tx4535\tx5102\tx5669\tx6236\tx6803\pardirnatural\partightenfactor0

\f0\fs24 \cf0 import boto3\
import json \
import logging\
import gzip\
from StringIO import StringIO\
\
client = boto3.client('ec2')\
s3client = boto3.client('s3')\
dynamodb = boto3.resource('dynamodb')\
snsclient = boto3.client('sns')\
rdsclient = boto3.client('rds')\
\
REQUIRED_PERMISSIONS = \{\
    "IpProtocol" : "tcp",\
    "FromPort" : 80,\
    "ToPort" : 80,\
    "UserIdGroupPairs" : [],\
    "IpRanges" : [\{"CidrIp" : "0.0.0.0/0"\}],\
    "PrefixListIds" : []\
\}\
\
#Function to check the access control list of the s3 bucket\
def s3_check_function(event):\
    print "Inside S3 Function"\
    s3_data = \{\}\
    table = dynamodb.Table('jarvis_aclopenaccess_logs')\
    arn = "arn:aws:sns:us-east-1:213925681271:Lambda_Notification_Topic"\
    s3_data["bucketName"] = event["requestParameters"]["bucketName"]\
    s3_data["eventType"] = event["eventType"]\
    s3_data["awsRegion"] = event["awsRegion"]\
    s3_data["eventName"] = event["eventName"]\
    s3_data["creationDate"] = event["userIdentity"]["sessionContext"]["attributes"]["creationDate"]\
    s3_data["arn"] = event["userIdentity"]["arn"]\
    s3_data["userAgent"] = event["userAgent"]\
    bucket_acl = s3client.get_bucket_acl(Bucket = s3_data["bucketName"])\
    policies = bucket_acl["Grants"]\
    for policy in policies:\
        s3_data["aclAccessType"] = policy["Grantee"]["Type"]\
        s3_data["aclPermission"] = policy["Permission"]\
        if policy["Grantee"]["Type"] == 'Group' and policy["Permission"] == 'FULL_CONTROL' and policy["Grantee"]["URI"] == 'http://acs.amazonaws.com/groups/global/AllUsers':\
            s3_data["accessType"] = "Global[Open Access]"\
        else:\
            s3_data["accessType"] = "Restricted[Acceptable]"\
	response = table.put_item(Item=s3_data)\
	print(json.dumps(response, indent=4))\
	subject_content = "Security Notification from AWS for S3 Bucket"\
	message_content = "S3 Bucket " + s3_data["bucketName"] +  " has been created with Global ACL Access (Open Access)"\
	snsmessage = snsclient.publish(TargetArn=arn, Subject=subject_content, Message=message_content,MessageStructure='String')\
	return True\
\
#Function to check the EBS volume encryption\
def ebs_check_function(event):\
    print "Inside EBS Function"\
    ebs_data = \{\}\
    arn = "arn:aws:sns:us-east-1:213925681271:Lambda_Notification_Topic"\
    table = dynamodb.Table('jarvis_ebscheck_logs')\
    ebs_data["accountarn"] = event["userIdentity"]["arn"]\
    ebs_data["accountId"] = event["userIdentity"]["accountId"]\
    ebs_data["creationDate"] = event["userIdentity"]["sessionContext"]["attributes"]["creationDate"]\
    ebs_data["eventName"] = event["eventName"]\
    ebs_data["awsRegion"] = event["awsRegion"]\
    ebs_data["encrypted"] = event["requestParameters"]["encrypted"]\
    ebs_data["volumeType"] = event["requestParameters"]["volumeType"]\
    ebs_data["zone"] = event["requestParameters"]["zone"]\
    ebs_data["volumeId"] = event["responseElements"]["volumeId"]\
    ebs_data["eventType"] = event["eventType"]\
    if ebs_data["encrypted"] == 0:\
        print ebs_data   \
        response = table.put_item(Item=ebs_data)\
        print(json.dumps(response, indent=4))\
        subject_content = "Security Notification from AWS for EBS Volume"\
        message_content = "Volume" + ebs_data["volumeId"] +  " has been created without encryption in the " + ebs_data["zone"] + " Zone"\
        snsmessage = snsclient.publish(TargetArn=arn, Subject=subject_content, Message=message_content,MessageStructure='String')\
        return True\
    else:\
        response = table.put_item(Item=ebs_data)\
        print(json.dumps(response, indent=4))\
\
#Function to check the RDS instance encryption    \
def rds_check_function(event):\
    print "Inside RDS Function"\
    rds_data = \{\}\
    arn = "arn:aws:sns:us-east-1:213925681271:Lambda_Notification_Topic"\
    table = dynamodb.Table('jarvis_rdscheck_logs')\
    rds_data["accountarn"] = event["userIdentity"]["arn"]\
    rds_data["accountId"] = event["userIdentity"]["accountId"]\
    rds_data["eventName"] = event["eventName"]\
    rds_data["awsRegion"] = event["awsRegion"]\
    rds_data["dBInstanceIdentifier"] = event["requestParameters"]["dBInstanceIdentifier"]\
    rds_data["InstanceDBType"] = event["requestParameters"]["engine"]\
    rds_data["multiAZ"] = event["requestParameters"]["multiAZ"]\
    rds_data["dBInstanceArn"] = event["responseElements"]["dBInstanceArn"]\
    rds_data["storageEncrypted"] = event["responseElements"]["storageEncrypted"]\
    rds_data["dBInstanceArn"] = event["responseElements"]["dBInstanceArn"]\
    rds_data["vpcId"] = event["responseElements"]["dBSubnetGroup"]["vpcId"]\
    rds_data["eventType"] = event["eventType"]\
    if rds_data["storageEncrypted"] == 0:\
        response = table.put_item(Item=rds_data)\
        print(json.dumps(response, indent=4))\
        subject_content = "Security Notification from AWS for RDS Instance"\
        message_content = "RDS Instance " + rds_data["dBInstanceIdentifier"] +  " has been created without encryption"\
        snsmessage = snsclient.publish(TargetArn=arn, Subject=subject_content, Message=message_content,MessageStructure='String')\
        return True\
    else:\
        response = table.put_item(Item=rds_data)\
        print(json.dumps(response, indent=4))\
\
#Function to check the security Group protocol and port (TCP & 80)     \
def sg_check_function(event):\
    print "Inside SG Function"\
    sg_data = \{\}\
    table = dynamodb.Table('jarvis_sgcheck_logs')\
    arn = "arn:aws:sns:us-east-1:213925681271:Lambda_Notification_Topic"\
    sg_data["accountarn"] = event["userIdentity"]["arn"]\
    sg_data["accountId"] = event["userIdentity"]["accountId"]\
    sg_data["eventName"] = event["eventName"]\
    sg_data["creationDate"] = event["userIdentity"]["sessionContext"]["attributes"]["creationDate"]\
    sg_data["awsRegion"] = event["awsRegion"]\
    sg_data["sgroupId"] = event["responseElements"]["groupId"]\
    sg_data["eventType"] = event["eventType"]\
    security_groups = client.describe_security_groups(GroupIds=[sg_data["sgroupId"]])\
    for group in range(len(security_groups["SecurityGroups"])):\
        ip_permissions = security_groups["SecurityGroups"][group]["IpPermissions"]\
        for permission in range(len(ip_permissions)):\
            sg_data["GroupName"] = security_groups["SecurityGroups"][group]["GroupName"]\
            sg_data["OwnerId"] = security_groups["SecurityGroups"][group]["OwnerId"]\
            sg_data["Description"] = security_groups["SecurityGroups"][group]["Description"]\
            sg_data["VpcId"] = security_groups["SecurityGroups"][group]["VpcId"]\
            sg_data["IpPermissions_ingress"] = security_groups["SecurityGroups"][group]["IpPermissions"][permission]\
            if ip_permissions[permission] != REQUIRED_PERMISSIONS:\
                sg_data["Regulated"] = False\
                print sg_data\
                response = table.put_item(Item=sg_data)\
                print(json.dumps(response, indent=4))\
                subject_content = "Security Notification from AWS for Security Group"\
                message_content = "Security Group " + sg_data["sgroupId"] +  " has been created with TCP open ports"\
                snsmessage = snsclient.publish(TargetArn=arn, Subject=subject_content, Message=message_content,MessageStructure='String')\
                return True\
            else:\
                sg_data["Regulated"] = True\
                print sg_data\
                response = table.put_item(Item=sg_data)\
                print(json.dumps(response, indent=4))\
\
#Main Function\
def lambda_handler(event, context):\
    outevent = str(event['awslogs']['data'])\
    outevent = gzip.GzipFile(fileobj=StringIO(outevent.decode('base64','strict'))).read()\
    cleanevent = json.loads(outevent)\
    message_data = json.loads(cleanevent["logEvents"][0]["message"])\
    if message_data["eventName"] == "CreateSecurityGroup":\
        print "Calling the SG Function"\
        sg_check_function(message_data)\
    elif message_data["eventName"] == "CreateDBInstance":\
        print "Calling the RDS Function"\
        rds_check_function(message_data)\
    elif message_data["eventName"] == "CreateVolume":\
        print "Calling the EBS Function"\
        ebs_check_function(message_data)\
    elif message_data["eventName"] == "CreateBucket":\
        print "Calling he S3 Function"\
        s3_check_function(message_data)\
    else:\
        print "Ending the Lambda Function as there is no need to check"\
        return True\
}