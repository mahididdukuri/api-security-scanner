
import requests
import config
#print(response.text)
"""endpoints={
    "paths":"paths",
    #"methods":"methods"
}
findings=[]
for terms in endpoints:
    if terms in response.json():
        findings.append(response.json()[terms])
#print(findings)
for path in findings[0]:
    print(path)"""    # this is alternate method
def get_endpoints():
    response = requests.get(f"{config.BASE_URL}/openapi.json")
    endpoints=[]
    data=response.json()
    paths=data["paths"]
    #print(paths)

    for path in paths:
        details=paths[path]
        for method in details:
            endpoints.append({
                "path":path,
                "method":method,
                "parameters":details[method].get("parameters")
            })
    return endpoints


