import requests
from vulnerable_api import users
from findings import scan_func
from config import TIMEOUT
import config
sensitive_terms=[
        "token",
        "password",
        "api_key",
        "secret_key",
        "access_token"

    ]
def sensitive_data(endpoint):
    findings=[]

    # --- check /users/{id} ---
    if endpoint['path']=='/users/{id}':
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFiY0BleGFtcGxlLmNvbSIsImV4cCI6MTc4OTk5OTY0N30.jl1RXePHfjPnANGQvRSguj-VD7NpdOF9dnnVkChRONw"
        headers = {
            "Authorization": f"Bearer {token}"
        }
        found = False
        for i in users:
            response = requests.get(f"{config.BASE_URL}{endpoint['path'].replace('{id}', str(i))}",
                                    headers=headers,timeout=TIMEOUT)
            # print(response.headers.get("X-Content-Type-Option"))
            # print(response.status_code)
            # print(response.json())
            # print(scan_func("sensitive data exposure","PASS","HIGH","No sensitive dats was exposed"))

            data = response.json()
            # print(i,data)
            for term in sensitive_terms:
                if term in data:
                    found = True
        if found:
            findings.append(scan_func(
                "Sensitive Data Exposure - /users/{id}",
                "FAIL",
                "HIGH",
                "Sensitive data was exposed",
                100
            ))
        else:
            findings.append(scan_func(
                "Sensitive Data Exposure - /users/{id}",
                "PASS",
                "HIGH",
                "No sensitive data was exposed",
                100
            ))
        # --- check error response ---
        response = requests.get(f"{config.BASE_URL}{endpoint['path'].replace('{id}', str('999'))}",timeout=TIMEOUT)
        # print(response.text)
        error_terms = [
            "Traceback",
            "File \"",
            "C:\\",
            "/home/"
        ]

        found = False

        for term in error_terms:
            if term in response.text:
                found = True

        if found:
            findings.append(scan_func(
                "Sensitive Data Exposure - Error Response",
                "FAIL",
                "HIGH",
                "Error response exposes internal information",
                100
            ))
        else:
            findings.append(scan_func(
                "Sensitive Data Exposure - Error Response",
                "PASS",
                "LOW",
                "Error response does not expose internal information",
                100
            ))
    elif endpoint['path'] =='/register':
        # --- check /register ---
        data = {
            "email": "abc@example.com",
            "password": "Abc@123"
        }
        response = requests.post(f"{config.BASE_URL}{endpoint['path']}", params=data,timeout=TIMEOUT)
        found = False
        for term in sensitive_terms:
            if term in response.text:
                found = True
        if found:
            findings.append(scan_func(
                "Sensitive Data Exposure",
                "FAIL",
                "HIGH",
                "Sensitive data was exposed-/register",
                100
            ))
        else:
            findings.append(scan_func(
                "Sensitive Data Exposure",
                "PASS",
                "LOW",
                "Sensitive data was not exposed-/register",
                100
            ))

    elif endpoint['path'] == '/login':
         # --- check /login ---
        data = {
            "email": "abc@example.com",
            "password": "Abc@123"
        }
        response = requests.post(f"{config.BASE_URL}{endpoint['path']}", params=data,timeout=TIMEOUT)
        found = False
        for term in sensitive_terms:
            if term in response.text:
                found = True
        if found:
            findings.append(scan_func(
                "Sensitive Data Exposure",
                "FAIL",
                "HIGH",
                "Sensitive data was exposed/-login",
                100

            ))
        else:
            findings.append(scan_func(
                "Sensitive Data Exposure",
                "PASS",
                "LOW",
                "Sensitive data was not exposed/-login",
                100
            ))

    return findings