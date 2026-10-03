import config
from checker import Check_bola


def test_bola_checker():
    config.BASE_URL = "http://127.0.0.1:8004"

    endpoint = {
        "path": "/users/{user_id}",
        "method": "get",
        "parameters": [
            {
                "name": "user_id",
                "in": "path"
            }
        ]
    }

    result = Check_bola(endpoint)

    assert isinstance(result, list)
    assert len(result) > 0

    finding = result[0]

    assert "name" in finding
    assert "status" in finding
    assert "severity" in finding
    assert "description" in finding
    assert "confidence" in finding