import config
from openapi_parser import get_endpoints


def test_get_endpoints():
    config.BASE_URL = "http://127.0.0.1:8004"

    endpoints = get_endpoints()

    assert len(endpoints) > 0
    assert "path" in endpoints[0]
    assert "method" in endpoints[0]