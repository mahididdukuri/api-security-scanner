from findings import scan_func


def test_scan_func():
    result = scan_func(
        "BOLA",
        "FAIL",
        "high",
        "Authorization check failed",
        100
    )

    assert result["name"] == "BOLA"
    assert result["status"] == "FAIL"
    assert result["severity"] == "high"
    assert result["description"] == "Authorization check failed"
    assert result["confidence"] == 100