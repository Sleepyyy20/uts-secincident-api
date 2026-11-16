"""Data simulasi untuk demo. Semua data fiktif (IP dari rentang dokumentasi RFC 5737)."""
from .extensions import db
from .models import Asset, AuditLog, Incident, IncidentAsset, User, Vulnerability


def seed_data():
    if db.session.query(User).first():
        return False

    users = []
    for username, email, role in [("admin", "admin@example.test", "admin"),
                                  ("analyst1", "analyst1@example.test", "analyst"),
                                  ("reporter1", "reporter1@example.test", "reporter")]:
        u = User(username=username, email=email, role=role)
        u.set_password("Password123!")
        users.append(u)
    db.session.add_all(users)
    db.session.flush()
    admin, analyst, reporter = users

    assets = [
        Asset(name="web-server-01", asset_type="server", ip_address="192.0.2.10", criticality="critical", owner_id=admin.id),
        Asset(name="db-mysql-01", asset_type="database", ip_address="192.0.2.20", criticality="critical", owner_id=admin.id),
        Asset(name="fw-edge-01", asset_type="network_device", ip_address="192.0.2.1", criticality="high", owner_id=analyst.id),
        Asset(name="hr-laptop-07", asset_type="workstation", ip_address="198.51.100.7", criticality="medium", owner_id=reporter.id),
        Asset(name="cctv-gateway-02", asset_type="iot_device", ip_address="198.51.100.40", criticality="low", owner_id=analyst.id),
    ]
    db.session.add_all(assets)
    db.session.flush()

    incidents = [
        Incident(title="Email phishing meniru HRD", description="Beberapa staf menerima email berisi tautan palsu.",
                 incident_type="phishing", severity="medium", status="investigating",
                 reporter_id=reporter.id, assignee_id=analyst.id),
        Incident(title="Percobaan login brute force ke web-server-01", description="Ratusan percobaan login SSH gagal dari satu IP.",
                 incident_type="unauthorized_access", severity="high", status="open", reporter_id=analyst.id),
        Incident(title="Malware terdeteksi pada laptop HR", incident_type="malware", severity="high",
                 status="contained", reporter_id=reporter.id, assignee_id=analyst.id),
        Incident(title="Konfigurasi bucket backup terbuka", incident_type="misconfiguration", severity="low",
                 status="open", reporter_id=admin.id),
    ]
    db.session.add_all(incidents)
    db.session.flush()

    db.session.add_all([
        IncidentAsset(incident_id=incidents[0].id, asset_id=assets[3].id, impact_note="Laptop penerima email"),
        IncidentAsset(incident_id=incidents[1].id, asset_id=assets[0].id, impact_note="Target brute force SSH"),
        IncidentAsset(incident_id=incidents[2].id, asset_id=assets[3].id, impact_note="Terinfeksi, diisolasi dari jaringan"),
        Vulnerability(asset_id=assets[0].id, title="OpenSSH versi lama", cve_id="CVE-2024-6387", cvss_score=8.1, severity="high"),
        Vulnerability(asset_id=assets[1].id, title="Privilege escalation pada MySQL", cve_id="CVE-2023-21980", cvss_score=7.1, severity="high"),
        Vulnerability(asset_id=assets[2].id, title="Firmware firewall belum diperbarui", cvss_score=9.3, severity="critical"),
        Vulnerability(asset_id=assets[4].id, title="Kredensial default pada gateway CCTV", cvss_score=9.8, severity="critical"),
        Vulnerability(asset_id=assets[3].id, title="Patch OS tertunda", cvss_score=5.4, severity="medium", status="mitigated"),
    ])
    db.session.add(AuditLog(user_id=admin.id, action="seed", entity_type="system", detail='{"note": "data simulasi"}'))
    db.session.commit()
    return True
