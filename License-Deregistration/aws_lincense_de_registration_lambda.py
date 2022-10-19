import os
import re
import io
import sys
import time
import json
import boto3
import base64
import logging
import requests
import argparse
from decimal import Decimal
from datetime import date
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)
# Accept runtime arguments

thisAcctBotoSession = boto3.session.Session()

## Аdded additional parameter that allows turning off SSL certificate verification so script would work on the API endpoint with self-signed certificates
## This parameter is added to each request.post call as 'verify=not cmd_args.ignore_ssl'
# parser.add_argument('-i', '--ignore-ssl', action='store_true', help='ignore verifying the SSL certificate and turn off warnings')
#
# cmd_args = parser.parse_args()
#
# if cmd_args.ignore_ssl:
#     requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)  # Disabled by default during the tests

today = date.today()
d1 = today.strftime("%Y_%m_%d")


def get_secret():
    secret_name = "secret_name"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS key.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            return json.loads(get_secret_value_response['SecretString'])
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])


# Connection details

secret_credentials = get_secret()

url = os.environ['API_URL']
user = secret_credentials['Username']
password = secret_credentials['Password']

second_url = os.environ['SECOND_API_URL']
user_b = secret_credentials['Username_B']
password_b = secret_credentials['Password_B']


def lambda_handler(event, context):
    def filter_dynamodb_instance(db_instance):
        key_collection = ("InstanceId", "State", "PrivateIpAddress", "TerminationTime", "Account")
        current_instance = {}
        for key in key_collection:
            current_instance[key] = item.get(key)

        return current_instance

    def filter_instance(some_item):
        key_collection = (
            "UniqueId", "OnlineStatus", "DeviceName", "Version", "Os", "Deleted", "LastPollUtc", "InstanceId",
            "State",
            "PrivateIpAddress", "TerminationTime", "Account")
        current_instance = {}
        for key in key_collection:
            current_instance[key] = some_item.get(key)

        return current_instance

    def cross_check_dic_info(api_list, ec2_list):
        result = []

        list_of_all_values = [value for elem in ec2_list
                              for value in elem.values()]

        for a in api_list:
            if a['UniqueId'] in list_of_all_values:
                temp_result = filter_instance(a)
                result.append(temp_result)

        return result


    def convert_list_to_dic(my_list):
        instanceDetailMap = dict()
        for index, value in enumerate(my_list):
            instanceDetailMap[index] = value
        return instanceDetailMap

    def ec2InfoToCSV(asset_manual_list):
        import csv
        try:
            writeToS3 = False
            if 'S3_BUCKET' in os.environ and 'S3_OBJECT_KEY' in os.environ:
                writeToS3 = True

            if writeToS3:
                reportPayload = io.StringIO()
                csvwriter = csv.writer(reportPayload, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
            else:
                csvfile = open('cleanup_report.csv', 'w', newline='')
                csvwriter = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
            csvHeaders = ["Instance", "UniqueId", "OnlineStatus", "DeviceName", "Version", "Os", "Deleted",
                          "LastPollUtc", "InstanceId", "State", "PrivateIpAddress", "TerminationTime",
                          "Account"]
            csvwriter.writerow(csvHeaders)
            instanceDetailMap = convert_list_to_dic(asset_manual_list)
            for instanceId in instanceDetailMap.keys():
                instInfo = instanceDetailMap[instanceId]
                instanceAttribs = instInfo.keys()
                instData = []
                for header in csvHeaders:
                    if header in instanceAttribs:
                        instData.append(instInfo[header])
                    else:
                        instData.append('N/A')
                csvwriter.writerow(instData)
                log.debug(instData)
            if writeToS3:
                s3Client = thisAcctBotoSession.client('s3')
                s3Client.put_object(Bucket=os.environ['S3_BUCKET'],
                                    Body=reportPayload.getvalue(),
                                    Key=os.environ['S3_OBJECT_KEY_RESULTS'] + d1 + ".csv",
                                    )  # Key=os.environ['S3_OBJECT_KEY']
            else:
                csvfile.flush()
                csvfile.close()
        except Exception as err:
            print(err)
            # log.error('SIC-EC2-904: Error trying to write csv report (%s)', err)
            # log.error(traceback.format_exc())

    def get_information(user, password, url):
        headers = {  # session headers information
            'content-type': 'application/json',
            'accept': 'application/json'
        }
        auth_payload = {
            'UserName': '{}'.format(user),
            'Password': '{}'.format(password)
        }

        s = requests.Session()  # create a session
        r = s.post(
            (url + '/api/auth/credentials?'),
            data=json.dumps(auth_payload),
            headers=headers,
            verify=False
        )
        autheticationresult = r.status_code
        if autheticationresult != 200:
            print(
                "\nToken Generation Failed. Please check if the REST API is enabled and User name and password is correct\n")
            exit()

        # Get total assets information

        event_payload = {
            "pageSize": 1,
            "take": 1,
            "page": 1
        }
        event_response = s.post(
            (url + '/api/agentsRanked'),
            data=json.dumps(event_payload),
            headers=headers,
            verify=False
        )

        initial_resp = event_response.json()
        total_assets_count = int(initial_resp['Total'])

        event_payload = {
            "DeviceFilter": {"GroupNames": [], "AgentDeviceIds": [], "ExcludeProxiedDevices": False,
                             "OnlineStatuses": []},
            "GetAgentGroupDetails": True,
            "pageSize": total_assets_count,
            "take": total_assets_count,
            "page": 1
        }

        event_response = s.post(
            (url + '/api/agentsRanked'),
            data=json.dumps(event_payload),
            headers=headers,
            verify=False
        )
        resp = event_response.json()
        # print(f"API raw response {resp}")  # Used during the tests.

        temp_counter = 0
        filtered_assets = []
        instance_name = "N/A"
        # Add here the information for all endpoints so the script will return proper name for endpoint
        if url == "https://hristo1.com":
            instance_name = "Hristo_1"
        elif url == "https://hristo2.com":
            instance_name = "Hristo_2"
        elif url == "https://hristo3.com":
            instance_name = "Hristo_3"

        for agent in resp["Agents"]:
            try:
                filtered_assets.append({"Instance": instance_name,
                                            "UniqueId": agent["UniqueId"],
                                            "OnlineStatus": agent["OnlineStatus"],
                                            "DeviceName": agent["DeviceName"],
                                            "Version": agent["Version"],
                                            "Os": agent["Os"],
                                            "Deleted": agent["Deleted"],
                                            "LastPollUtc": agent["LastPollUtc"]
                                        })

            except KeyError:
                pass  # update with the appropriate keyerrors
            temp_counter += 1

        print(f"Total assets: {temp_counter}")

        return filtered_assets

    print(json.dumps(event))

    aws_account_id = context.invoked_function_arn.split(":")[4]
    print("the account id is:", aws_account_id)

    # Get a list if all available DynamoDB tables responsible for keeping the EC2 data
    logTblRegex = re.compile('(^hristo.*-instanceLogTable-.*)')
    dynamodbClient = thisAcctBotoSession.client('dynamodb')
    resp = dynamodbClient.list_tables()
    tableMap = {}
    tableNameList = []
    for tableName in resp['TableNames']:
        if logTblRegex.match(tableName):
            tableNameList.append(tableName)
            accountType = tableName.split('-')[0].replace('hristo', '').upper()
            if accountType:
                tableMap[accountType] = tableName
            else:
                tableMap['ALL'] = tableName

    dynamodb = boto3.resource('dynamodb')
    # dynamodb = thisAcctBotoSession.resource('dynamodb', region_name=os.environ['REGION']) # in case region needs to be included as parameter
    all_db_instances_details = []
    for t in tableNameList:
        table = dynamodb.Table(t)
        response = table.scan()
        items = response['Items']

        while True:
            # print(f"Retreived DynamoDB Items: {len(response['Items'])}")  # Used during tests
            if response.get('LastEvaluatedKey'):
                response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
                items += response['Items']
            else:
                break
        all_db_instances_details += items

    all_filtered_db_ec2 = []

    for item in all_db_instances_details:
        filtered_items = filter_dynamodb_instance(item)
        all_filtered_db_ec2.append(filtered_items)

    print(f"This is the response from the Filtered DynamoDB Items {all_filtered_db_ec2}")  # Test

    # Get agent information
    first_query = get_information(user, password, url)
    second_query = get_information(user_b, password_b, second_url)
    all_filtered_assets = first_query + second_query  # In case there is another query it needs to be added

    print(f"This is the response from the Filtered DynamoDB Items {all_filtered_db_ec2}")
    print(f"This is the response from the Filtered API request {all_filtered_assets}")

    manual_check_list = []
    verify_list = []
    prefix = ["016", "017"]    # Update with the relevant prefix for the target endpoint
    for instance in all_filtered_assets:
        instance_id = instance['UniqueId']
        match = [True for y in prefix if y in instance['DeviceName']]
        if match:
            for item in all_filtered_db_ec2:
                if instance_id in item.values():
                    z = instance.copy()
                    z.update(item)
                    manual_check_list.append(z)
                    verify_list.append(instance_id)
                    break
            if instance_id not in verify_list:
                manual_check_list.append(instance)
        else:
            pass

    print(f"assetcleanup:{manual_check_list}")

    ec2InfoToCSV(manual_check_list)