import requests
from findings import scan_func
import config
from config import TIMEOUT
def Check_bola(endpoint):
    findings=[]
    token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFiY0BleGFtcGxlLmNvbSIsImV4cCI6MTc4OTg4NzUyOH0.Gvgd7NW9g2DlxjLaBg8opCh5u336sl2-1yvMGMIGgmg"

    headers={"authorization": f"Bearer {token}"}
    #response=requests.get("http://127.0.0.1:8004/users",headers=headers)

    #print(response.status_code)
    parameters=endpoint['parameters']
    location=None
    parameter_name=None
    if parameters is None:
        return []
    for parameter in parameters:
        if parameter['in']=='path': #or parameter['in']=='query':
            location=parameter['in']
            parameter_name=parameter['name']
            break
    else:
        return[]
    for id in range(1,4):
        #if endpoint['path']=='/'or endpoint['path']=='/register' or endpoint['path']=='/login':
        if location=='path':
            url=f"{config.BASE_URL}{endpoint['path'].replace('{'+parameter_name+'}',str(id))}"
            response=requests.get(url,headers=headers,timeout=TIMEOUT)
        #print(id,response.status_code,response.text)
        else:
            url = f"{config.BASE_URL}{endpoint['path']}"
            response = requests.get(url, params={parameter_name: id}, headers=headers,timeout=TIMEOUT)

        if response.status_code==200:
            name="BOLA"
            status="FAIL"
            severity="low"
            description="you are authorized"
        else:
            name = "BOLA"
            status = "PASS"
            severity = "high"
            description = "you are not authorized"

        finding=scan_func(name,status,severity,description,100)
        findings.append(finding)
    return findings

