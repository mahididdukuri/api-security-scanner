import requests
from findings import scan_func
import config 
from config import TIMEOUT
def rate_limit_found(endpoint):
    data={
        "email": "abc@example.com",
        "password": "wrongpassword"
    }
    if endpoint['path']=='/login':
        rate_limit=False
        for i in range(10):
            response=requests.post(f"{config.BASE_URL}{endpoint['path']}",params=data,timeout=TIMEOUT)
            print(i+1,response.status_code)
            if response.status_code==429:
                rate_limit=True
        if rate_limit:
            return[scan_func(
                "rate_limit -/login",
                "PASS",
                "HIGH",
                "rate limiting was detected",
                100
            )]
        else:
            return [scan_func(
                "rate_limit -/login",
                "FAIL",
                "HIGH",
                "No rate limiting was detected",
                100
            )]
    elif endpoint['path']=='/users/{id}':
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFiY0BleGFtcGxlLmNvbSIsImV4cCI6MTc5MDMzNTE2OX0._JQU2xnHy6sl0gm9lcUCl-gVskM72vrVSvMkD4ZU5t8"
        headers = {"authorization": f"Bearer {token}"}
        rate_limit1 = False
        for i in range(10):
            response = requests.get(f"{config.BASE_URL}{endpoint['path'].replace('{id}','1')}",headers=headers,timeout=TIMEOUT)
            print(i + 1, response.status_code)
            if response.status_code == 429:
                rate_limit1 = True
        if rate_limit1:
            return [scan_func(
                "rate_limit -/users{id}",
                "PASS",
                "HIGH",
                "rate limiting was detected",
                100
            )]
        else:
            return [scan_func(
                "rate_limit -/users{id}",
                "FAIL",
                "HIGH",
                "No rate limiting was detected",
                100
            )]

    return[]