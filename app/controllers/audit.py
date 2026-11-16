from flask import Blueprint, request
from sqlalchemy import select

from ..models import AuditLog
from ..utils import apply_sort, int_arg, paginate
from ..views.serializers import audit_out

bp = Blueprint("audit", __name__, url_prefix="/api/audit-logs")


@bp.get("")
def list_audit_logs():
    """Read-only: audit log tidak boleh diubah/dihapus lewat API."""
    stmt = select(AuditLog)
    for field in ("entity_type", "action"):
        value = request.args.get(field)
        if value:
            stmt = stmt.where(getattr(AuditLog, field) == value)
    for field in ("entity_id", "user_id"):
        value = int_arg(field)
        if value:
            stmt = stmt.where(getattr(AuditLog, field) == value)
    stmt = apply_sort(stmt, AuditLog, {"id", "created_at"}, default="-created_at")
    return paginate(stmt, audit_out)
