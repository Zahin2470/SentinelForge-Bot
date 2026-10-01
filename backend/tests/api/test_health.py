from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_liveness() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# Readiness (/health/ready) is covered by an integration test against a real
# Postgres + Redis (see tests/api/test_health_ready.py, added once the
# docker-compose test profile lands) rather than here, since it depends on
# live infrastructure by design.
