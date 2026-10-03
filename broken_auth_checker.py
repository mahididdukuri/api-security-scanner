import requests
from findings import scan_func
from config import TIMEOUT
import config
def broken_auth(endpoint):
    finding=[]
    #token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InJpeWFAZXhhbXBsZS5jb20iLCJleHAiOjE3ODk4MzM1NjZ9.tdHl6WPRx55XFddQ8_nytao6gW0Bwxa-U1HFD1oe_YY"
    #headers={"authorization":f"Bearer {token}"}
    #response=requests.post("{config.BASE_URL}/login/alogorithm=none")

    #print(response.status_code)
    #print(response.text)

    data={
        "email": "abcd@example.com",
        "password": "password"
    }
    if endpoint['path']!='/register':
        return[]
    if endpoint['parameters'] ==None:
        return[]
    for parameter in endpoint['parameters']:
        if parameter['in']=='query':
            response=requests.post(f"{config.BASE_URL}{endpoint['path']}",params=data,timeout=TIMEOUT)
    #print(response.status_code)
    #print(response.text)
            if response.status_code == 200:
                name="weak password accepted"
                status="FAIL"
                severity="HIGH"
                description="password was accepted"
            else:
                name = " weak password not accepted"
                status = "PASS"
                severity = "HIGH"
                description = "password was not accepted"

            finding.append(scan_func(name,status,severity,description,100))
    return finding

# for checking wrong credentials
def broken_login():
    email = input("enter email:")
    data={
        "email":email,
        "password":"password"
    }

    response=requests.post(f"{config.BASE_URL}/login",params=data,timeout=TIMEOUT)
    #print(response.status_code)
    #print(response.text)
# for automating the above task

def broken_auto(endpoint):
    email1="test999@example.com"
    data1={
        "email":email1,
        "password":"dgshbxh@134"
    }
    if endpoint['path']!='/login':
        return[]
    if endpoint['parameters'] ==None:
        return[]
    email2="abcd@example.com"
    data2 = {
        "email": email2,
        "password": "dgshbxh@134"
    }
    for parameter in endpoint['parameters']:
        if parameter['in']=='query':
            response1=requests.post(f"{config.BASE_URL}{endpoint['path']}",params=data1,timeout=TIMEOUT)
            response2=requests.post(f"{config.BASE_URL}{endpoint['path']}",params=data2,timeout=TIMEOUT)
    #print(response2.text)
    if response1.status_code == response2.status_code and response1.text == response2.text:
        return[(
            scan_func(
                "login error consistency",
                "PASS",
                "LOW",
                "Login returns the same error for unregistered email and wrong password",
                100
            )
        )]
    else:
        return[(
            scan_func(
                "login error consistency",
                "FAIL",
                "HIGH",
                "Login responses reveal whether an email is registered",
                100
            )
        )]

def Invalid_token(endpoint):
    token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InJpeWFAZXhhbXBsZS5jb20iLCJleHAiOjE3ODk4MzM1NjZ9.tdHl6WPRx55XFddQ8_nytao6gW0Bwxa-U1HFD1oe_YY"
    headers={"authorization":f"Bearer {token}"}
    parameter_name=None
    if endpoint['parameters'] == None:
        return []
    for parameter in endpoint['parameters']:
        if parameter['in']!='path':
            continue
        else:
            parameter_name=parameter['name']
            response=requests.get(f"{config.BASE_URL}{endpoint['path'].replace('{'+parameter_name+'}','1')}", headers=headers,timeout=TIMEOUT)
        if response.status_code == 401:
            return [scan_func(
                "Invalid token rejected",
                "PASS",
                "HIGH",
                "API rejected the invalid token",
                100
            )]
        else:
            return [scan_func(
                "Invalid token rejected",
                "FAIL",
                "HIGH",
                "API accepted the invalid token",
                100
            )]
    return []
def Expired_token(endpoint):
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFiY0BleGFtcGxlLmNvbSIsImV4cCI6MTc5MDI2NzkyNX0.v3Wx44zzOZuovs2eBR8uwOrnagxJnf1LUoX8x0iQu7k"
    headers = {"authorization": f"Bearer {token}"}
    parameter_name = None
    if endpoint['parameters'] == None:
        return []
    for parameter in endpoint['parameters']:
        if parameter['in'] != 'path':
            continue
        else:
            parameter_name = parameter['name']
            response=requests.get(f"{config.BASE_URL}{endpoint['path'].replace('{'+parameter_name+'}','1')}", headers=headers,timeout=TIMEOUT)
        if response.status_code == 401:
            return [scan_func(
                "Expired token rejected",
                "PASS",
                "HIGH",
                "API rejected the Expired token",
                100
            )]
        else:
            return [scan_func(
                "Expired token rejected",
                "FAIL",
                "HIGH",
                "API accepted the Expired token",
                100
            )]
    return []