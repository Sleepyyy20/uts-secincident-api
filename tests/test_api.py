from .conftest import API_KEY, make_asset, make_incident, make_user


# ---------------- umum & keamanan ----------------
def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"


def test_unknown_route_returns_json_error(client):
    resp = client.get("/api/tidak-ada")
    assert resp.status_code == 404
    assert resp.get_json()["error"]["code"] == "not_found"


def test_write_without_api_key_is_rejected(client):
    resp = client.post("/api/users", json={"username": "x"})
    assert resp.status_code == 401
    assert resp.get_json()["error"]["code"] == "unauthorized"


def test_invalid_json_body(client):
    resp = client.post("/api/users", data="bukan json", headers=API_KEY)
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == "invalid_json"


# ---------------- users ----------------
def test_create_user_success_hides_password(client):
    user = make_user(client)
    assert user["username"] == "analyst1"
    assert "password" not in user and "password_hash" not in user


def test_create_user_validation_error(client):
    resp = client.post("/api/users", headers=API_KEY,
                       json={"username": "ab", "email": "bukan-email", "password": "pendek"})
    assert resp.status_code == 422
    details = resp.get_json()["error"]["details"]
    assert {"username", "email", "password"} <= set(details)


def test_duplicate_username_conflict(client):
    make_user(client)
    resp = client.post("/api/users", headers=API_KEY,
                       json={"username": "analyst1", "email": "lain@example.test", "password": "Password123!"})
    assert resp.status_code == 409


def test_user_list_filter_and_pagination(client):
    make_user(client, "admin1", "admin")
    make_user(client, "analyst1", "analyst")
    make_user(client, "analyst2", "analyst")
    resp = client.get("/api/users?role=analyst&per_page=1&page=2&sort=username")
    body = resp.get_json()
    assert resp.status_code == 200
    assert body["meta"] == {"page": 2, "per_page": 1, "total": 2, "pages": 2}
    assert body["data"][0]["username"] == "analyst2"


def test_invalid_sort_parameter(client):
    assert client.get("/api/users?sort=password_hash").status_code == 400


# ---------------- assets ----------------
def test_asset_crud_flow(client):
    asset = make_asset(client)
    aid = asset["id"]
    assert client.get(f"/api/assets/{aid}").status_code == 200
    resp = client.patch(f"/api/assets/{aid}", json={"criticality": "critical"}, headers=API_KEY)
    assert resp.get_json()["data"]["criticality"] == "critical"
    assert client.delete(f"/api/assets/{aid}", headers=API_KEY).status_code == 204
    assert client.get(f"/api/assets/{aid}").status_code == 404


def test_asset_invalid_ip_and_unknown_owner(client):
    resp = client.post("/api/assets", headers=API_KEY,
                       json={"name": "srv", "asset_type": "server", "ip_address": "999.1.1.1", "owner_id": 999})
    assert resp.status_code == 422
    assert "ip_address" in resp.get_json()["error"]["details"]


def test_asset_search_and_filter(client):
    make_asset(client, "web-server-01")
    make_asset(client, "db-server-01", asset_type="database", ip_address="192.0.2.20")
    resp = client.get("/api/assets?q=web")
    assert resp.get_json()["meta"]["total"] == 1
    resp = client.get("/api/assets?asset_type=database")
    assert resp.get_json()["data"][0]["name"] == "db-server-01"


# ---------------- incidents ----------------
def test_incident_lifecycle_and_stats(client):
    reporter = make_user(client, "reporter1", "reporter")
    analyst = make_user(client, "analyst1", "analyst")
    asset = make_asset(client)
    inc = make_incident(client, reporter["id"], assignee_id=analyst["id"])
    assert inc["status"] == "open"

    resp = client.post(f"/api/incidents/{inc['id']}/assets", headers=API_KEY,
                       json={"asset_id": asset["id"], "impact_note": "Target serangan"})
    assert resp.status_code == 201
    assert resp.get_json()["data"]["affected_assets"][0]["name"] == "web-server-01"

    for status in ("investigating", "resolved"):
        resp = client.patch(f"/api/incidents/{inc['id']}", json={"status": status}, headers=API_KEY)
        assert resp.status_code == 200
    assert resp.get_json()["data"]["resolved_at"] is not None

    stats = client.get("/api/incidents/stats").get_json()["data"]
    assert stats["total"] == 1 and stats["by_status"] == {"resolved": 1}


def test_incident_invalid_status_transition(client):
    reporter = make_user(client, "reporter1", "reporter")
    inc = make_incident(client, reporter["id"])
    resp = client.patch(f"/api/incidents/{inc['id']}", json={"status": "resolved"}, headers=API_KEY)
    assert resp.status_code == 409
    assert resp.get_json()["error"]["code"] == "invalid_transition"


def test_incident_assignee_must_be_analyst(client):
    reporter = make_user(client, "reporter1", "reporter")
    resp = client.post("/api/incidents", headers=API_KEY,
                       json={"title": "Uji", "incident_type": "malware", "severity": "low",
                             "reporter_id": reporter["id"], "assignee_id": reporter["id"]})
    assert resp.status_code == 422
    assert "assignee_id" in resp.get_json()["error"]["details"]


def test_incident_filter_by_severity(client):
    reporter = make_user(client, "reporter1", "reporter")
    make_incident(client, reporter["id"], severity="low")
    make_incident(client, reporter["id"], severity="critical")
    resp = client.get("/api/incidents?severity=critical")
    assert resp.get_json()["meta"]["total"] == 1


# ---------------- vulnerabilities ----------------
def test_vulnerability_severity_derived_from_cvss(client):
    asset = make_asset(client)
    resp = client.post("/api/vulnerabilities", headers=API_KEY,
                       json={"asset_id": asset["id"], "title": "OpenSSH lama", "cve_id": "CVE-2024-6387", "cvss_score": 9.8})
    assert resp.status_code == 201
    assert resp.get_json()["data"]["severity"] == "critical"


def test_vulnerability_cvss_out_of_range(client):
    asset = make_asset(client)
    resp = client.post("/api/vulnerabilities", headers=API_KEY,
                       json={"asset_id": asset["id"], "title": "Uji", "cvss_score": 12})
    assert resp.status_code == 422


def test_cannot_delete_asset_with_vulnerability(client):
    asset = make_asset(client)
    client.post("/api/vulnerabilities", headers=API_KEY,
                json={"asset_id": asset["id"], "title": "Uji kerentanan", "cvss_score": 5})
    resp = client.delete(f"/api/assets/{asset['id']}", headers=API_KEY)
    assert resp.status_code == 409


# ---------------- audit log ----------------
def test_audit_log_records_actions_and_requires_key(client):
    user = make_user(client)
    resp = client.post("/api/assets", headers={**API_KEY, "X-User-Id": str(user["id"])},
                       json={"name": "srv-audit", "asset_type": "server"})
    assert resp.status_code == 201
    assert client.get("/api/audit-logs").status_code == 401
    logs = client.get("/api/audit-logs?entity_type=asset", headers=API_KEY).get_json()
    assert logs["meta"]["total"] == 1
    assert logs["data"][0]["user_id"] == user["id"]
    assert logs["data"][0]["action"] == "create"
