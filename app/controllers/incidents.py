from flask import Blueprint, request
from sqlalchemy import func, or_, select

from ..extensions import db
from ..models import (INCIDENT_STATUS, INCIDENT_TYPES, SEVERITIES, Asset, Incident, IncidentAsset,
                      User, utcnow)
from ..utils import (APIError, apply_sort, choice_arg, exists, get_or_404, int_arg, like_pattern,
                     log_action, no_content, ok, paginate, parse, require_ref)
from ..views.serializers import incident_out

bp = Blueprint("incidents", __name__, url_prefix="/api/incidents")

RULES = {
    "title": {"type": "str", "required": True, "min_len": 3, "max_len": 200},
    "description": {"type": "str", "nullable": True, "allow_empty": True, "max_len": 5000},
    "incident_type": {"type": "str", "required": True, "choices": INCIDENT_TYPES},
    "severity": {"type": "str", "required": True, "choices": SEVERITIES},
    "reporter_id": {"type": "int", "required": True, "ge": 1},
    "assignee_id": {"type": "int", "nullable": True, "ge": 1},
    "detected_at": {"type": "datetime"},
}
UPDATE_RULES = {**RULES, "status": {"type": "str", "choices": INCIDENT_STATUS}}

# Alur status yang diizinkan (state machine sederhana).
TRANSITIONS = {
    "open": {"investigating", "closed"},
    "investigating": {"contained", "resolved"},
    "contained": {"investigating", "resolved"},
    "resolved": {"closed", "investigating"},
    "closed": set(),
}

LINK_RULES = {
    "asset_id": {"type": "int", "required": True, "ge": 1},
    "impact_note": {"type": "str", "nullable": True, "allow_empty": True, "max_len": 255},
}


def _check_people(data):
    if "reporter_id" in data:
        require_ref(User, data["reporter_id"], "reporter_id")
    if data.get("assignee_id") is not None:
        assignee = require_ref(User, data["assignee_id"], "assignee_id")
        if assignee.role not in ("admin", "analyst") or not assignee.is_active:
            raise APIError(422, "validation_error", "Data yang dikirim tidak valid",
                           {"assignee_id": "Assignee harus user aktif dengan role admin/analyst"})


@bp.post("")
def create_incident():
    data = parse(RULES)
    _check_people(data)
    incident = Incident(**data)
    db.session.add(incident)
    db.session.flush()
    log_action("create", "incident", incident.id, {"title": incident.title, "severity": incident.severity})
    db.session.commit()
    return ok(incident_out(incident), 201)


@bp.get("")
def list_incidents():
    stmt = select(Incident)
    for field, choices in (("status", INCIDENT_STATUS), ("severity", SEVERITIES), ("incident_type", INCIDENT_TYPES)):
        value = choice_arg(field, choices)
        if value:
            stmt = stmt.where(getattr(Incident, field) == value)
    assignee_id = int_arg("assignee_id")
    if assignee_id:
        stmt = stmt.where(Incident.assignee_id == assignee_id)
    q = request.args.get("q")
    if q:
        pat = like_pattern(q)
        stmt = stmt.where(or_(Incident.title.ilike(pat, escape="\\"), Incident.description.ilike(pat, escape="\\")))
    stmt = apply_sort(stmt, Incident, {"id", "severity", "status", "detected_at", "created_at"}, default="-created_at")
    return paginate(stmt, incident_out)


@bp.get("/stats")
def incident_stats():
    by_status = db.session.execute(select(Incident.status, func.count()).group_by(Incident.status)).all()
    by_severity = db.session.execute(select(Incident.severity, func.count()).group_by(Incident.severity)).all()
    total = db.session.scalar(select(func.count()).select_from(Incident))
    return ok({"total": total, "by_status": dict(by_status), "by_severity": dict(by_severity)})


@bp.get("/<int:incident_id>")
def get_incident(incident_id):
    return ok(incident_out(get_or_404(Incident, incident_id)))


@bp.route("/<int:incident_id>", methods=["PUT", "PATCH"])
def update_incident(incident_id):
    incident = get_or_404(Incident, incident_id)
    data = parse(UPDATE_RULES, partial=request.method == "PATCH")
    _check_people(data)

    new_status = data.pop("status", None)
    if new_status and new_status != incident.status:
        if new_status not in TRANSITIONS[incident.status]:
            allowed = ", ".join(sorted(TRANSITIONS[incident.status])) or "(tidak ada)"
            raise APIError(409, "invalid_transition",
                           f"Status '{incident.status}' tidak dapat langsung menjadi '{new_status}'. Diizinkan: {allowed}")
        incident.status = new_status
        if new_status in ("resolved", "closed") and incident.resolved_at is None:
            incident.resolved_at = utcnow()
        elif new_status == "investigating":
            incident.resolved_at = None

    for key, value in data.items():
        setattr(incident, key, value)
    log_action("update", "incident", incident.id, {"fields": sorted(list(data) + (["status"] if new_status else []))})
    db.session.commit()
    return ok(incident_out(incident))


@bp.delete("/<int:incident_id>")
def delete_incident(incident_id):
    incident = get_or_404(Incident, incident_id)
    db.session.delete(incident)  # relasi incident_assets ikut terhapus (cascade)
    log_action("delete", "incident", incident_id, {"title": incident.title})
    db.session.commit()
    return no_content()


@bp.post("/<int:incident_id>/assets")
def link_asset(incident_id):
    incident = get_or_404(Incident, incident_id)
    data = parse(LINK_RULES)
    require_ref(Asset, data["asset_id"], "asset_id")
    if exists(select(IncidentAsset.asset_id).where(
            IncidentAsset.incident_id == incident.id, IncidentAsset.asset_id == data["asset_id"])):
        raise APIError(409, "conflict", "Aset sudah terhubung dengan insiden ini")
    db.session.add(IncidentAsset(incident_id=incident.id, **data))
    log_action("link_asset", "incident", incident.id, {"asset_id": data["asset_id"]})
    db.session.commit()
    db.session.refresh(incident)
    return ok(incident_out(incident), 201)


@bp.delete("/<int:incident_id>/assets/<int:asset_id>")
def unlink_asset(incident_id, asset_id):
    link = db.session.get(IncidentAsset, (incident_id, asset_id))
    if link is None:
        raise APIError(404, "not_found", "Relasi insiden-aset tidak ditemukan")
    db.session.delete(link)
    log_action("unlink_asset", "incident", incident_id, {"asset_id": asset_id})
    db.session.commit()
    return no_content()
