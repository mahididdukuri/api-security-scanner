

def score(findings):
    Score=0
    for each_finding in findings:
        status=each_finding['status']
        severity=each_finding['severity'].lower()
        if status=='FAIL':
            if severity=='high':
                Score+=5
            elif severity=='medium':
                Score+=3
            else:
                Score+=1
    return Score