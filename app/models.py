"""Model (M pada MVC) - SQLAlchemy ORM. 6 tabel:
users, assets, incidents, incident_assets (M:N), vulnerabilities, audit_logs.
"""
from datetime import datetime, timezone

from sqlalchemy import event
from sqlalchemy.engine import Engine
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db

ROLES = ("admin", "analyst", "reporter")
ASSET_TYPES = ("server", "workstation", "network_device", "application", "database", "iot_device")
CRITICALITY = ("low", "medium", "high", "critical")
ASSET_STATUS = ("active", "inactive", "decommissioned")
INCIDENT_TYPES = ("phishing", "malware", "unauthorized_access", "data_leak", "ddos", "misconfiguration", "other")
SEVERITIES = ("low", "medium", "high", "critical")
INCIDENT_STATUS = ("open", "investigating", "contained", "resolved", "closed")
VULN_STATUS = ("open", "mitigated", "patched", "accepted_risk")


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _in(column, values):
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


@event.listens_for(Engine, "connect")
def _enable_sqlite_fk(dbapi_connection, _record):
    """SQLite tidak menegakkan foreign key secara default."""
    if dbapi_connection.__class__.__module__.startswith("sqlite3"):
        cur = dbapi_connection.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="reporter")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    __table_args__ = (db.CheckConstraint(_in("role", ROLES), name="ck_users_role"),)

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)


class Asset(db.Model):
    __tablename__ = "assets"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    asset_type = db.Column(db.String(20), nullable=False)
    ip_address = db.Column(db.String(45))
    criticality = db.Column(db.String(10), nullable=False, default="medium")
    status = db.Column(db.String(15), nullable=False, default="active")
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="RESTRICT"))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    owner = db.relationship("User", backref="assets")
    incident_links = db.relationship("IncidentAsset", back_populates="asset")

    __table_args__ = (
        db.CheckConstraint(_in("asset_type", ASSET_TYPES), name="ck_assets_type"),
        db.CheckConstraint(_in("criticality", CRITICALITY), name="ck_assets_criticality"),
        db.CheckConstraint(_in("status", ASSET_STATUS), name="ck_assets_status"),
    )


class Incident(db.Model):
    __tablename__ = "incidents"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    incident_type = db.Column(db.String(25), nullable=False)
    severity = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(15), nullable=False, default="open")
    reporter_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="RESTRICT"))
    detected_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    resolved_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    reporter = db.relationship("User", foreign_keys=[reporter_id])
    assignee = db.relationship("User", foreign_keys=[assignee_id])
    links = db.relationship("IncidentAsset", back_populates="incident", cascade="all, delete-orphan")

    __table_args__ = (
        db.CheckConstraint(_in("incident_type", INCIDENT_TYPES), name="ck_incidents_type"),
        db.CheckConstraint(_in("severity", SEVERITIES), name="ck_incidents_severity"),
        db.CheckConstraint(_in("status", INCIDENT_STATUS), name="ck_incidents_status"),
    )


class IncidentAsset(db.Model):
    """Tabel relasi M:N antara incidents dan assets (aset yang terdampak)."""

    __tablename__ = "incident_assets"
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id", ondelete="RESTRICT"), primary_key=True)
    impact_note = db.Column(db.String(255))
    linked_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    incident = db.relationship("Incident", back_populates="links")
    asset = db.relationship("Asset", back_populates="incident_links")


class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    cve_id = db.Column(db.String(20))
    cvss_score = db.Column(db.Float, nullable=False)
    severity = db.Column(db.String(10), nullable=False)  # diturunkan otomatis dari cvss_score
    status = db.Column(db.String(15), nullable=False, default="open")
    discovered_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    asset = db.relationship("Asset", backref="vulnerabilities")

    __table_args__ = (
        db.CheckConstraint("cvss_score >= 0 AND cvss_score <= 10", name="ck_vuln_cvss"),
        db.CheckConstraint(_in("severity", SEVERITIES), name="ck_vuln_severity"),
        db.CheckConstraint(_in("status", VULN_STATUS), name="ck_vuln_status"),
        db.UniqueConstraint("asset_id", "cve_id", name="uq_vuln_asset_cve"),
    )


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="RESTRICT"))
    action = db.Column(db.String(20), nullable=False)
    entity_type = db.Column(db.String(30), nullable=False)
    entity_id = db.Column(db.Integer)
    detail = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    user = db.relationship("User")
