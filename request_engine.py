import requests

def send_request(endpoint,url,headers=None,params=None):
    method=endpoint['method'].lower()
    if method == "get":
        return requests.get(url, headers=headers, params=params)

    elif method == "post":
        return requests.post(url, headers=headers, params=params)

    else:
        return None
endpoint = {
        'method': 'get'
    }
#print(endpoint['method'])
response=send_request(endpoint, "http://127.0.0.1:8004/")
print(response)