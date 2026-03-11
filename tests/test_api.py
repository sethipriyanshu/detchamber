from fastapi.testclient import TestClient

from backend.main import app


client = TestClient(app)


def test_health() -> None:
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_analyze_security_engine_blocks_open() -> None:
    code = "open('somefile.txt', 'w')"
    res = client.post("/analyze", json={"code": code, "engines": ["security"]})
    assert res.status_code == 200
    body = res.json()
    assert body["security"]["violations"]


def test_analyze_complexity_engine_returns_results() -> None:
    code = """
def linear(items):
    total = 0
    for x in items:
        total += x
    return total
"""
    res = client.post("/analyze", json={"code": code, "engines": ["complexity"]})
    assert res.status_code == 200
    body = res.json()
    assert body["complexity"] is not None
    assert isinstance(body["complexity"], list)
