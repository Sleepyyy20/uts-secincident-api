"""View (V pada MVC) untuk REST API: representasi JSON dari model.
password_hash TIDAK PERNAH diserialisasi."""
import json


def iso(dt):
    return dt.isoformat() + "Z" if dt else None


def user_out(u):
    return {"id": u.id, "username": u.username, "email": u.email, "role": u.role,
            "is_active": u.is_active, "created_at": iso(u.created_at)}


def asset_out(a):
    return {"id": a.id, "name": a.name, "asset_type": a.asset_type, "ip_address": a.ip_address,
            "criticality": a.criticality, "status": a.status, "owner_id": a.owner_id,
            "created_at": iso(a.created_at)}


def incident_out(i):
    return {"id": i.id, "title": i.title, "description": i.description,
            "incident_type": i.incident_type, "severity": i.severity, "status": i.status,
            "reporter_id": i.reporter_id, "assignee_id": i.assignee_id,
            "detected_at": iso(i.detected_at), "resolved_at": iso(i.resolved_at),
            "created_at": iso(i.created_at), "updated_at": iso(i.updated_at),
            "affected_assets": [{"asset_id": l.asset_id, "name": l.asset.name,
                                 "impact_note": l.impact_note} for l in i.links]}


def vuln_out(v):
    return {"id": v.id, "asset_id": v.asset_id, "title": v.title, "cve_id": v.cve_id,
            "cvss_score": v.cvss_score, "severity": v.severity, "status": v.status,
            "discovered_at": iso(v.discovered_at), "created_at": iso(v.created_at)}


def audit_out(a):
    try:
        detail = json.loads(a.detail) if a.detail else None
    except ValueError:
        detail = a.detail
    return {"id": a.id, "user_id": a.user_id, "action": a.action, "entity_type": a.entity_type,
            "entity_id": a.entity_id, "detail": detail, "ip_address": a.ip_address,
            "created_at": iso(a.created_at)}
