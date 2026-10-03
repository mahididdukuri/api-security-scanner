import requests
from findings import scan_func
from config import TIMEOUT
import config
security_headers=[
     "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy"
]
token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFiY0BleGFtcGxlLmNvbSIsImV4cCI6MTc5MDA0NjY5Nn0.QK14o5PPANCSuKn1GgcEY6YNQupKFsuWGkivtCr5tZs"
origin="https://evil.com"
headers={
    "Origin":origin,
    "authorization": f"Bearer {token}"
 }
def security_headers_check(endpoint):
    findings=[]
    if endpoint['method'] not in ('get', 'post'):
        return []
    if endpoint['method']=='get':
        response=requests.get(f"{config.BASE_URL}{endpoint['path'].replace('{id}','1')}", headers=headers,timeout=TIMEOUT)
        #print(response.headers)
    elif endpoint['method'] == 'post':
        data = {"email": "abc@example.com", "password": "Abc@123"}
        response = requests.post(f"{config.BASE_URL}{endpoint['path']}", params=data, headers=headers,timeout=TIMEOUT)

    allow_origin=response.headers.get("access-control-allow-origin")
    #print(response.headers.get("access-control-allow-origin"))
    if allow_origin=="*" or allow_origin==origin:
        findings.append(scan_func(
            "CORS",
            "FAIL",
            "MEDIUM",
            "API allows requests from any origin",
            100
        ))
    else:
        findings.append(scan_func(
            "CORS",
            "PASS",
            "LOW",
            "API doesn't allow requests from any origin",
            100
        ))

    for header in security_headers:
        if response.headers.get(header):
            findings.append(scan_func(
                "Security Header - " + header,
                "PASS",
                "LOW",
                header + " is present",
                100
            ))

        else:
            findings.append(scan_func(
                "Security Header - " + header,
                "FAIL",
                "MEDIUM",
                header + " is missing",
                100
            ))

    return findings

#security_headers_check()
