from risk_score import score


def test_risk_score():
    findings = [
        {
            "status": "FAIL",
            "severity": "high"
        },
        {
            "status": "FAIL",
            "severity": "medium"
        },
        {
            "status": "PASS",
            "severity": "high"
        }
    ]

    result = score(findings)

    assert result == 8