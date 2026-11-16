import pytest

from app import create_app
from app.config import TestConfig
from app.extensions import db

API_KEY = {"X-API-Key": "test-key"}


@pytest.fixture()
def app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


# ---------- helper pembuat data lewat API ----------
def make_user(client, username="analyst1", role="analyst", **extra):
    payload = {"username": username, "email": f"{username}@example.test",
               "password": "Password123!", "role": role, **extra}
    resp = client.post("/api/users", json=payload, headers=API_KEY)
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()["data"]


def make_asset(client, name="web-server-01", **extra):
    payload = {"name": name, "asset_type": "server", "ip_address": "192.0.2.10",
               "criticality": "high", **extra}
    resp = client.post("/api/assets", json=payload, headers=API_KEY)
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()["data"]


def make_incident(client, reporter_id, **extra):
    payload = {"title": "Percobaan brute force SSH", "incident_type": "unauthorized_access",
               "severity": "high", "reporter_id": reporter_id, **extra}
    resp = client.post("/api/incidents", json=payload, headers=API_KEY)
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()["data"]
