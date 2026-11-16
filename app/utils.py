"""Helper umum: format respons, error, parsing request, pagination, audit log."""
import json

from flask import jsonify, request
from sqlalchemy import select

from .extensions import db
from .models import AuditLog, User
from .validation import ValidationError, validate


class APIError(Exception):
    def __init__(self, status, code, message, details=None):
        super().__init__(message)
        self.status, self.code, self.message, self.details = status, code, message, details


def error_body(code, message, details=None):
    err = {"code": code, "message": message}
    if details:
        err["details"] = details
    return {"error": err}


def ok(data, status=200, meta=None):
    body = {"data": data}
    if meta is not None:
        body["meta"] = meta
    resp = jsonify(body)
    resp.status_code = status
    return resp


def no_content():
    return "", 204


def json_body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise APIError(400, "invalid_json", "Body harus berupa JSON object (Content-Type: application/json)")
    return data


def parse(rules, partial=False):
    try:
        return validate(json_body(), rules, partial)
    except ValidationError as exc:
        raise APIError(422, "validation_error", "Data yang dikirim tidak valid", exc.errors)


def get_or_404(model, obj_id):
    obj = db.session.get(model, obj_id)
    if obj is None:
        raise APIError(404, "not_found", f"{model.__name__} dengan id {obj_id} tidak ditemukan")
    return obj


def require_ref(model, obj_id, field):
    """Pastikan foreign key menunjuk data yang ada (422 jika tidak)."""
    obj = db.session.get(model, obj_id)
    if obj is None:
        raise APIError(422, "validation_error", "Data yang dikirim tidak valid",
                       {field: f"{model.__name__} dengan id {obj_id} tidak ditemukan"})
    return obj


def exists(stmt):
    return db.session.scalar(stmt.limit(1)) is not None


# ---------- query parameter ----------
def choice_arg(name, choices):
    value = request.args.get(name)
    if value in (None, ""):
        return None
    if value not in choices:
        raise APIError(400, "invalid_query", f"Parameter '{name}' harus salah satu dari: {', '.join(choices)}")
    return value


def int_arg(name):
    value = request.args.get(name)
    if value in (None, ""):
        return None
    try:
        return int(value)
    except ValueError:
        raise APIError(400, "invalid_query", f"Parameter '{name}' harus integer")


def float_arg(name):
    value = request.args.get(name)
    if value in (None, ""):
        return None
    try:
        return float(value)
    except ValueError:
        raise APIError(400, "invalid_query", f"Parameter '{name}' harus angka")


def like_pattern(text):
    escaped = text.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def apply_sort(stmt, model, allowed, default):
    sort = request.args.get("sort", default)
    name = sort.lstrip("-")
    if name not in allowed:
        raise APIError(400, "invalid_query", f"Parameter 'sort' harus salah satu dari: {', '.join(sorted(allowed))} (awali '-' untuk descending)")
    col = getattr(model, name)
    return stmt.order_by(col.desc() if sort.startswith("-") else col.asc(), model.id.asc())


def paginate(stmt, serializer):
    try:
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 10))
    except ValueError:
        raise APIError(400, "invalid_query", "page dan per_page harus integer")
    if page < 1 or not 1 <= per_page <= 100:
        raise APIError(400, "invalid_query", "page minimal 1 dan per_page antara 1-100")
    p = db.paginate(stmt, page=page, per_page=per_page, error_out=False)
    meta = {"page": page, "per_page": per_page, "total": p.total, "pages": p.pages}
    return ok([serializer(item) for item in p.items], meta=meta)


# ---------- audit log ----------
def current_actor_id():
    """Aktor diambil dari header X-User-Id (sementara, sampai JWT di UAS)."""
    raw = request.headers.get("X-User-Id", "")
    if raw.isdigit() and db.session.get(User, int(raw)) is not None:
        return int(raw)
    return None


def log_action(action, entity_type, entity_id, detail=None):
    """Tambahkan catatan audit ke session (commit dilakukan oleh pemanggil)."""
    db.session.add(AuditLog(
        user_id=current_actor_id(),
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        detail=json.dumps(detail) if detail is not None else None,
        ip_address=request.remote_addr,
    ))
