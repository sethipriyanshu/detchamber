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
