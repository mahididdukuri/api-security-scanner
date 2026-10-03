from checker import Check_bola
from sensitive_data_checker import sensitive_data
import json
from rate_limit_checker import rate_limit_found
from datetime import datetime
from security_headers_checker import security_headers_check
from broken_auth_checker import broken_auth,broken_auto,Invalid_token,Expired_token
from openapi_parser import get_endpoints
from config import ENABLED_CHECKS
import config

from db import SessionLocal
from db_models import Scan, Finding
from risk_score import score

checks = [
    ("checker", Check_bola),
    ("broken_auth_checker", broken_auth),
    ("sensitive_data_checker", sensitive_data),
    ("rate_limit_checker", rate_limit_found),
    ("broken_auto", broken_auto),
    ("security_headers_checker", security_headers_check),
    ("invalid_token", Invalid_token),
    ("expired_token", Expired_token),
]
""" bola_result=Check_bola()
finding.extend(bola_result)

auth_result=broken_auth()
finding.append(auth_result)"""

def run_scan(scan_id):
    endpoints=get_endpoints()
    # print(endpoints)
    finding=[]
    for name,check in checks:
        print("running:",name)
        if not ENABLED_CHECKS.get(name):
            continue
        for endpoint in endpoints:
            result=check(endpoint)
            finding.extend(result)
    db = SessionLocal()

    for item in finding:
        finding_record = Finding(
            scan_id=scan_id,
            name=item["name"],
            status=item["status"],
            severity=item["severity"],
            description=item["description"],
            confidence=item["confidence"]
        )

        db.add(finding_record)
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        print("Scan not found:", scan_id)
        db.close()
        return finding
    risk_score = score(finding)
    # scan = db.query(Scan).filter(Scan.id == scan_id).first()
    scan.risk_score = risk_score
    scan.status = 'completed'
    db.commit()
    db.close()
    print("Risk Score:", risk_score)

    for i in finding:
        #print(i)
        print("name :", i["name"])
        print("status :", i["status"])
        print("severity :", i["severity"])
        print("description :", i["description"])
        print( )
    print("Total findings=",len(finding))
    PASS=0
    FAIL=0
    for i in finding:
        if i['status']=="PASS":
            PASS+=1
        else:
            FAIL+=1
    high,medium,low=0,0,0
    for i in finding:
        if i['severity'].lower()=='high':
            high+=1
        elif i["severity"].lower()=='medium':
            medium+=1
        else:
            low+=1
    print(f"PASS:{PASS}\nFAIL:{FAIL}\nhigh={high}\nmedium={medium}\nlow={low}\n")

    report={
        "scan_time":str(datetime.now()),
        "total_findings":len(finding),
        "findings": finding,
        "risk_score": risk_score,
    }

    with open("report.json","w") as file:
        json.dump(report,file,indent=4)

    return finding



