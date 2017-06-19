import boto3
import json 
import logging
import gzip
from StringIO import StringIO
import sys
import logging
import pymysql

client = boto3.client('ec2')
s3client = boto3.client('s3')
sesclient = boto3.client('ses')
rdsclient = boto3.client('rds')

#Mail Info parameters for SES
email_from = 'jegadesh33@gmail.com'
email_to = 'prabhucv@ymail.com'
email_cc = 'jegadesh.thirumeni@verizon.com'

#DB Connection variables
rds_host = "jarvislogsinstance.cluster-ckizxfucbee6.us-east-1.rds.amazonaws.com"
db_name = "jarvislogsinstancedb"
name = 'root'
password = 'rootroot'
port = 3306

logger = logging.getLogger()
logger.setLevel(logging.INFO)

#Intiating Connection for Aurora DB
try:
    conn = pymysql.connect(rds_host, user=name, passwd=password, db=db_name, connect_timeout=5)
except:
    logger.error("ERROR: Unexpected error: Could not connect to MySql instance.")
    sys.exit()
logger.info("SUCCESS: Connection to RDS mysql instance succeeded")

#Dict for TCP 80 port
REQUIRED_PERMISSIONS = {
    "IpProtocol" : "tcp",
    "FromPort" : 80,
    "ToPort" : 80,
    "UserIdGroupPairs" : [],
    "IpRanges" : [{"CidrIp" : "0.0.0.0/0"}],
    "PrefixListIds" : []
}

#Function for SQL Insert Operation
def sql_action(data,table_name):
    item_count = 0
    with conn.cursor() as cur:
        placeholders = ', '.join(['%s'] * len(data))
        columns = ', '.join(data.keys())
        sql = "INSERT INTO %s ( %s ) VALUES ( %s )" % (table_name, columns, placeholders)
        cur.execute(sql, data.values())
        conn.commit()
        sql1 = "select * from %s" % (table_name)
        cur.execute(sql1)
        for row in cur:
            item_count += 1
            logger.info(row)
    return "Added %d items to RDS MySQL table" %(item_count)


#Function to check the access control list of the s3 bucket
def s3_check_function(event):
    s3_data = {}
    s3_data["bucketName"] = event["requestParameters"]["bucketName"]
    s3_data["eventType"] = event["eventType"]
    s3_data["awsRegion"] = event["awsRegion"]
    s3_data["eventName"] = event["eventName"]
    s3_data["creationDate"] = event["userIdentity"]["sessionContext"]["attributes"]["creationDate"]
    s3_data["arn"] = event["userIdentity"]["arn"]
    s3_data["userAgent"] = event["userAgent"]
    bucket_acl = s3client.get_bucket_acl(Bucket = s3_data["bucketName"])
    policies = bucket_acl["Grants"]
    for policy in policies:
        s3_data["aclAccessType"] = policy["Grantee"]["Type"]
        s3_data["aclPermission"] = policy["Permission"]
        if policy["Grantee"]["Type"] == 'Group' and policy["Permission"] == 'FULL_CONTROL' and policy["Grantee"]["URI"] == 'http://acs.amazonaws.com/groups/global/AllUsers':
            s3_data["accessType"] = "Global[Open Access]"
        else:
            s3_data["accessType"] = "Restricted[Acceptable]"
    emaiL_subject = "AWS Lambda Security Notification: S3 Bucket with open ACL"
    email_body = '<html><head><title>Alert from Jarvis</title></head><body><p>Hi CloudUser,</p><p>your are receiving notification for the below event:</p><table border="1"><tr><th>Resource</th><th>Name</th><th>Created by</th><th>Alert Event</th></tr><tr><td>S3 Bucket</td><td>' + s3_data["bucketName"] + '</td><td>' + s3_data["arn"] + '</td><td><font color="rgb(0,0,0)">Created S3 Bucket with Global Access</font></td></tr></table><p>Please act on fixing this security event immediately. If you need technical assistance, reach out to our security team.</p><p>Thanks,</p><p>Jarvis</p><br><p>PROTECT YOUR NETWORK AS IF IT WOULD BE A HOTEL AND NOT AS IF IT WOULD BE A CASTLE</p></body></html>'
    response = sesclient.send_email(Source = email_from,Destination={'ToAddresses': [email_to,],'CcAddresses': [email_cc,]},Message={'Subject': {'Data': emaiL_subject},'Body': {'Html': {'Data': email_body}}})
    table_name = "jarvis_s3_data"
    sql_action(s3_data,table_name)
    
#Function to check the encryption of s3 bucket object
def s3object_check_function(event):
    s3object_data = {}
    s3object_data["bucketName"] = event["requestParameters"]["bucketName"]
    s3object_data["objectName"] = event["requestParameters"]["key"]
    s3object_data["eventType"] = event["eventType"]
    s3object_data["awsRegion"] = event["awsRegion"]
    s3object_data["eventName"] = event["eventName"]
    s3object_data["creationDate"] = event["userIdentity"]["sessionContext"]["attributes"]["creationDate"]
    s3object_data["arn"] = event["userIdentity"]["arn"]
    s3object_data["userAgent"] = event["userAgent"]
    if "x-amz-server-side-encryption" in event["responseElements"].keys():
        s3object_data["Encryption"] = True
    else:
        s3object_data["Encryption"] = False
    emaiL_subject = "AWS Lambda Security Notification: S3 Bucket Object without Server Side Encryption"
    email_body = '<html><head><title>Alert from Jarvis</title></head><body><p>Hi CloudUser,</p><p>your are receiving notification for the below event:</p><table border="1"><tr><th>Resource</th><th>Bucket Name</th><th>Object Name</th><th>Created by</th><th>Alert Event</th></tr><tr><td>S3 Object</td><td>' + s3object_data["bucketName"] + '</td><td>' + s3object_data["objectName"] + '</td><td>' + s3object_data["arn"] + '</td><td><font color="rgb(0,0,0)">Created S3 Bucket Object without Server Side Encryption</font></td></tr></table><p>Please act on fixing this security event immediately. If you need technical assistance, reach out to our security team.</p><p>Thanks,</p><p>Jarvis</p><br><p>PROTECT YOUR NETWORK AS IF IT WOULD BE A HOTEL AND NOT AS IF IT WOULD BE A CASTLE</p></body></html>'
    response = sesclient.send_email(Source = email_from,Destination={'ToAddresses': [email_to,],'CcAddresses': [email_cc,]},Message={'Subject': {'Data': emaiL_subject},'Body': {'Html': {'Data': email_body}}})
    table_name = "jarvis_s3object_data"
    sql_action(s3object_data,table_name)


#Function to check the EBS volume encryption
def ebs_check_function(event):
    ebs_data = {}
    ebs_data["accountarn"] = event["userIdentity"]["arn"]
    ebs_data["accountId"] = event["userIdentity"]["accountId"]
    ebs_data["eventName"] = event["eventName"]
    ebs_data["creationDate"] = event["userIdentity"]["sessionContext"]["attributes"]["creationDate"]
    ebs_data["awsRegion"] = event["awsRegion"]
    ebs_data["encrypted"] = event["requestParameters"]["encrypted"]
    ebs_data["volumeType"] = event["requestParameters"]["volumeType"]
    ebs_data["zone"] = event["requestParameters"]["zone"]
    ebs_data["volumeId"] = event["responseElements"]["volumeId"]
    ebs_data["eventType"] = event["eventType"]
    if ebs_data["encrypted"] == 0:
        emaiL_subject = "AWS Lambda Security Notification: EBS Volume created without Encryption"
        email_body = '<html><head><title>Alert from Jarvis</title></head><body><p>Hi CloudUser,</p><p>your are receiving notification for the below event:</p><table border="1"><tr><th>Resource</th><th>Volume ID</th><th>Created by</th><th>Region</th><th>Alert Event</th></tr><tr><td>EBS Volume</td><td>' + ebs_data["volumeId"]  + '</td><td>' + ebs_data["accountarn"] + '</td><td>' + ebs_data["awsRegion"]  + '</td><td><font color="rgb(0,0,0)">Created EBS Volume without encryption</font></td></tr></table><p>Please act on fixing this security event immediately. If you need technical assistance, reach out to our security team.</p><p>Thanks,</p><p>Jarvis</p><br><p>PROTECT YOUR NETWORK AS IF IT WOULD BE A HOTEL AND NOT AS IF IT WOULD BE A CASTLE</p></body></html>'
        response = sesclient.send_email(Source = email_from,Destination={'ToAddresses': [email_to,],'CcAddresses': [email_cc,]},Message={'Subject': {'Data': emaiL_subject},'Body': {'Html': {'Data': email_body}}})
    table_name = "jarvis_ebs_data"
    sql_action(ebs_data,table_name)

#Function to check the RDS instance encryption    
def rds_check_function(event):
    rds_data = {}
    rds_data["accountarn"] = event["userIdentity"]["arn"]
    rds_data["accountId"] = event["userIdentity"]["accountId"]
    rds_data["eventName"] = event["eventName"]
    rds_data["creationDate"] = event["userIdentity"]["sessionContext"]["attributes"]["creationDate"]
    rds_data["awsRegion"] = event["awsRegion"]
    rds_data["dBInstanceIdentifier"] = event["requestParameters"]["dBInstanceIdentifier"]
    rds_data["InstanceDBType"] = event["requestParameters"]["engine"]
    rds_data["multiAZ"] = event["requestParameters"]["multiAZ"]
    rds_data["dBInstanceArn"] = event["responseElements"]["dBInstanceArn"]
    rds_data["storageEncrypted"] = event["responseElements"]["storageEncrypted"]
    rds_data["vpcId"] = event["responseElements"]["dBSubnetGroup"]["vpcId"]
    rds_data["eventType"] = event["eventType"]
    if rds_data["storageEncrypted"] == 0:
        emaiL_subject = "AWS Lambda Security Notification: RDS Instance created without Encryption"
        email_body = '<html><head><title>Alert from Jarvis</title></head><body><p>Hi CloudUser,</p><p>your are receiving notification for the below event:</p><table border="1"><tr><th>Resource</th><th>InstanceName</th><th>Created by</th><th>Region</th><th>Alert Event</th></tr><tr><td>RDS Instance</td><td>' + rds_data["dBInstanceIdentifier"]  + '</td><td>' + rds_data["accountarn"] + '</td><td>' + rds_data["awsRegion"]  + '</td><td><font color="rgb(0,0,0)">Created RDS Instance without encryption</font></td></tr></table><p>Please act on fixing this security event immediately. If you need technical assistance, reach out to our security team.</p><p>Thanks,</p><p>Jarvis</p><br><p>PROTECT YOUR NETWORK AS IF IT WOULD BE A HOTEL AND NOT AS IF IT WOULD BE A CASTLE</p></body></html>'
        response = sesclient.send_email(Source = email_from,Destination={'ToAddresses': [email_to,],'CcAddresses': [email_cc,]},Message={'Subject': {'Data': emaiL_subject},'Body': {'Html': {'Data': email_body}}})
    table_name = "jarvis_rds_data"
    sql_action(rds_data,table_name)

#Function to check the security Group protocol and port (TCP & 80)     
def sg_check_function(event):
    sg_data = {}
    sg_data["accountarn"] = event["userIdentity"]["arn"]
    sg_data["accountId"] = event["userIdentity"]["accountId"]
    sg_data["eventName"] = event["eventName"]
    sg_data["creationDate"] = event["userIdentity"]["sessionContext"]["attributes"]["creationDate"]
    sg_data["awsRegion"] = event["awsRegion"]
    sg_data["sgroupId"] = event["responseElements"]["groupId"]
    sg_data["eventType"] = event["eventType"]
    security_groups = client.describe_security_groups(GroupIds=[sg_data["sgroupId"]])
    for group in range(len(security_groups["SecurityGroups"])):
        ip_permissions = security_groups["SecurityGroups"][group]["IpPermissions"]
        for permission in range(len(ip_permissions)):
            sg_data["GroupName"] = security_groups["SecurityGroups"][group]["GroupName"]
            sg_data["OwnerId"] = security_groups["SecurityGroups"][group]["OwnerId"]
            sg_data["Description"] = security_groups["SecurityGroups"][group]["Description"]
            sg_data["VpcId"] = security_groups["SecurityGroups"][group]["VpcId"]
            sg_data["IpPermissions_ingress"] = json.dumps(security_groups["SecurityGroups"][group]["IpPermissions"][permission])
            if ip_permissions[permission] != REQUIRED_PERMISSIONS:
                sg_data["Regulated"] = False
                emaiL_subject = "AWS Lambda Security Notification: Security Group created with non-regulated Ingress ports"
                email_body = '<html><head><title>Alert from Jarvis</title></head><body><p>Hi CloudUser,</p><p>your are receiving notification for the below event:</p><table border="1"><tr><th>Resource</th><th>GroupID</th><th>Created by</th><th>Region</th><th>Alert Event</th></tr><tr><td>Security Group</td><td>' + sg_data["sgroupId"]  + '</td><td>' + sg_data["accountarn"] + '</td><td>' + sg_data["awsRegion"]  + '</td><td><font color="rgb(0,0,0)">Created Security Groups without regulation</font></td></tr></table><p>Please act on fixing this security event immediately. If you need technical assistance, reach out to our security team.</p><p>Thanks,</p><p>Jarvis</p><br><p>PROTECT YOUR NETWORK AS IF IT WOULD BE A HOTEL AND NOT AS IF IT WOULD BE A CASTLE</p></body></html>'
                response = sesclient.send_email(Source = email_from,Destination={'ToAddresses': [email_to,],'CcAddresses': [email_cc,]},Message={'Subject': {'Data': emaiL_subject},'Body': {'Html': {'Data': email_body}}})
            else:
                sg_data["Regulated"] = True
        table_name = "jarvis_sg_data"
        sql_action(sg_data,table_name)

#Main Function
def lambda_handler(event, context):
    outevent = str(event['awslogs']['data'])
    outevent = gzip.GzipFile(fileobj=StringIO(outevent.decode('base64','strict'))).read()
    cleanevent = json.loads(outevent)
    message_data = json.loads(cleanevent["logEvents"][0]["message"])
    if message_data["eventName"] == "CreateSecurityGroup":
        sg_check_function(message_data)
    elif message_data["eventName"] == "CreateDBInstance":
        rds_check_function(message_data)
    elif message_data["eventName"] == "CreateVolume":
        ebs_check_function(message_data)
    elif message_data["eventName"] == "CreateBucket":
        s3_check_function(message_data)
    elif message_data["eventName"] == "PutObject":
        s3object_check_function(message_data)
    else:
        return True
