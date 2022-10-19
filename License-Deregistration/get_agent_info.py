import requests
import json

url = '...'
headers = {  # session headers information
    'content-type': 'application/json',
    'accept': 'application/json'
}
user = "hristo"
passw = "pass"
urlToken = url + '/api/auth/credentials?'

auth_payload = {  # authentication request payload
    'UserName': '{}'.format(user),
    'Password': '{}'.format(passw)
}

s = requests.Session()  # create a session
r = s.post(
    (url + '/api/auth/credentials?'),
    data=json.dumps(auth_payload),
    headers=headers
)
autheticationresult = r.status_code
# print(autheticationresult)
if autheticationresult != 200:
    print(
        "\nToken Generation Failed. Please check if the REST API is enabled and User name and password is correct\n")
    exit()
r_dict = r.json()
token = r_dict['BearerToken']
session_id = r_dict['SessionId']
# print(token)
# print(session_id)+

event_payload = {
    "DeviceFilter": {"GroupNames": [], "AgentDeviceIds": [], "ExcludeProxiedDevices": False, "OnlineStatuses": []},
    "GetAgentGroupDetails": True,
}

event_response = s.post(
    (url + '/api/agentsRanked'),
    data=json.dumps(event_payload),
    headers=headers
)
resp = event_response.json()
# print(resp)

temp_counter = 0
all_filtered_assets = []

for agent in resp["Agents"]:
    print(agent["DeviceName"] + ": " + agent["UniqueId"] + " -> " + agent["OnlineStatus"])
    all_filtered_assets.append(agent["DeviceName"]["UniqueId"]["OnlineStatus"])
    temp_counter += 1

print(f"Total assets: {temp_counter}")