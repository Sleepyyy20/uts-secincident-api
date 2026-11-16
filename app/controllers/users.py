from flask import Blueprint, request
from sqlalchemy import or_, select

from ..extensions import db
from ..models import ROLES, Asset, AuditLog, Incident, User
from ..utils import (APIError, apply_sort, choice_arg, exists, get_or_404, like_pattern,
                     log_action, no_content, ok, paginate, parse)
from ..validation import EMAIL_RE
from ..views.serializers import user_out

bp = Blueprint("users", __name__, url_prefix="/api/users")

RULES = {
    "username": {"type": "str", "required": True, "min_len": 3, "max_len": 50,
                 "pattern": r"[A-Za-z0-9_.-]+", "pattern_msg": "Hanya huruf, angka, titik, strip, underscore"},
    "email": {"type": "str", "required": True, "max_len": 120, "pattern": EMAIL_RE, "pattern_msg": "Format email tidak valid"},
    "password": {"type": "str", "required": True, "min_len": 8, "max_len": 128, "strip": False},
    "role": {"type": "str", "choices": ROLES},
    "is_active": {"type": "bool"},
}
UPDATE_RULES = {**RULES, "password": {**RULES["password"], "required": False}}


def _check_unique(data, current_id=None):
    for field in ("username", "email"):
        if field in data:
            stmt = select(User.id).where(getattr(User, field) == data[field])
            if current_id:
                stmt = stmt.where(User.id != current_id)
            if exists(stmt):
                raise APIError(409, "conflict", f"{field} '{data[field]}' sudah digunakan")


@bp.post("")
def create_user():
    data = parse({k: v for k, v in RULES.items() if k != "is_active"})
    data["email"] = data["email"].lower()
    _check_unique(data)
    password = data.pop("password")
    user = User(**data)
    user.set_password(password)
    db.session.add(user)
    db.session.flush()
    log_action("create", "user", user.id, {"username": user.username})
    db.session.commit()
    return ok(user_out(user), 201)


@bp.get("")
def list_users():
    stmt = select(User)
    role = choice_arg("role", ROLES)
    if role:
        stmt = stmt.where(User.role == role)
    q = request.args.get("q")
    if q:
        pat = like_pattern(q)
        stmt = stmt.where(or_(User.username.ilike(pat, escape="\\"), User.email.ilike(pat, escape="\\")))
    stmt = apply_sort(stmt, User, {"id", "username", "created_at"}, default="id")
    return paginate(stmt, user_out)


@bp.get("/<int:user_id>")
def get_user(user_id):
    return ok(user_out(get_or_404(User, user_id)))


@bp.route("/<int:user_id>", methods=["PUT", "PATCH"])
def update_user(user_id):
    user = get_or_404(User, user_id)
    data = parse(UPDATE_RULES, partial=request.method == "PATCH")
    if "email" in data:
        data["email"] = data["email"].lower()
    _check_unique(data, current_id=user.id)
    password = data.pop("password", None)
    for key, value in data.items():
        setattr(user, key, value)
    if password:
        user.set_password(password)
    log_action("update", "user", user.id, {"fields": sorted(list(data) + (["password"] if password else []))})
    db.session.commit()
    return ok(user_out(user))


@bp.delete("/<int:user_id>")
def delete_user(user_id):
    user = get_or_404(User, user_id)
    if (exists(select(Asset.id).where(Asset.owner_id == user.id))
            or exists(select(Incident.id).where((Incident.reporter_id == user.id) | (Incident.assignee_id == user.id)))
            or exists(select(AuditLog.id).where(AuditLog.user_id == user.id))):
        raise APIError(409, "conflict", "User masih direferensikan data lain; nonaktifkan dengan is_active=false")
    db.session.delete(user)
    log_action("delete", "user", user_id, {"username": user.username})
    db.session.commit()
    return no_content()
