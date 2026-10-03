import json
import os
import config
from db import SessionLocal
from db_models import Scan
from scanner import run_scan


def test_report():
    config.BASE_URL = "http://127.0.0.1:8004"

    db = SessionLocal()

    scan = Scan(
        target_url=config.BASE_URL,
        status="running"
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    scan_id = scan.id
    db.close()

    run_scan(scan_id)

    assert os.path.exists("report.json")

    with open("report.json", "r") as file:
        report = json.load(file)

    assert "scan_time" in report
    assert "total_findings" in report
    assert "risk_score" in report
    assert "findings" in report