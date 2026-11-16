from flask import Blueprint, request
from sqlalchemy import or_, select

from ..extensions import db
from ..models import VULN_STATUS, SEVERITIES, Asset, Vulnerability
from ..utils import (APIError, apply_sort, choice_arg, exists, float_arg, get_or_404, int_arg,
                     like_pattern, log_action, no_content, ok, paginate, parse, require_ref)
from ..views.serializers import vuln_out

bp = Blueprint("vulnerabilities", __name__, url_prefix="/api/vulnerabilities")

RULES = {
    "asset_id": {"type": "int", "required": True, "ge": 1},
    "title": {"type": "str", "required": True, "min_len": 3, "max_len": 200},
    "cve_id": {"type": "str", "nullable": True, "pattern": r"CVE-\d{4}-\d{4,}", "pattern_msg": "Format CVE-YYYY-NNNN"},
    "cvss_score": {"type": "float", "required": True, "ge": 0, "le": 10},
    "status": {"type": "str", "choices": VULN_STATUS},
    "discovered_at": {"type": "datetime"},
}


def severity_from_cvss(score):
    """Skala CVSS v3: 0.0-3.9 low, 4.0-6.9 medium, 7.0-8.9 high, 9.0-10.0 critical."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _prepare(data, current=None):
    if "asset_id" in data:
        require_ref(Asset, data["asset_id"], "asset_id")
    asset_id = data.get("asset_id", current.asset_id if current else None)
    cve_id = data.get("cve_id", current.cve_id if current else None)
    if cve_id and ("asset_id" in data or "cve_id" in data):
        stmt = select(Vulnerability.id).where(Vulnerability.asset_id == asset_id, Vulnerability.cve_id == cve_id)
        if current:
            stmt = stmt.where(Vulnerability.id != current.id)
        if exists(stmt):
            raise APIError(409, "conflict", f"{cve_id} sudah tercatat pada aset ini")


@bp.post("")
def create_vulnerability():
    data = parse(RULES)
    _prepare(data)
    data["severity"] = severity_from_cvss(data["cvss_score"])
    vuln = Vulnerability(**data)
    db.session.add(vuln)
    db.session.flush()
    log_action("create", "vulnerability", vuln.id, {"asset_id": vuln.asset_id, "cvss": vuln.cvss_score})
    db.session.commit()
    return ok(vuln_out(vuln), 201)


@bp.get("")
def list_vulnerabilities():
    stmt = select(Vulnerability)
    for field, choices in (("severity", SEVERITIES), ("status", VULN_STATUS)):
        value = choice_arg(field, choices)
        if value:
            stmt = stmt.where(getattr(Vulnerability, field) == value)
    asset_id = int_arg("asset_id")
    if asset_id:
        stmt = stmt.where(Vulnerability.asset_id == asset_id)
    min_cvss = float_arg("min_cvss")
    if min_cvss is not None:
        stmt = stmt.where(Vulnerability.cvss_score >= min_cvss)
    q = request.args.get("q")
    if q:
        pat = like_pattern(q)
        stmt = stmt.where(or_(Vulnerability.title.ilike(pat, escape="\\"), Vulnerability.cve_id.ilike(pat, escape="\\")))
    stmt = apply_sort(stmt, Vulnerability, {"id", "cvss_score", "discovered_at", "created_at"}, default="-cvss_score")
    return paginate(stmt, vuln_out)


@bp.get("/<int:vuln_id>")
def get_vulnerability(vuln_id):
    return ok(vuln_out(get_or_404(Vulnerability, vuln_id)))


@bp.route("/<int:vuln_id>", methods=["PUT", "PATCH"])
def update_vulnerability(vuln_id):
    vuln = get_or_404(Vulnerability, vuln_id)
    data = parse(RULES, partial=request.method == "PATCH")
    _prepare(data, current=vuln)
    if "cvss_score" in data:
        data["severity"] = severity_from_cvss(data["cvss_score"])
    for key, value in data.items():
        setattr(vuln, key, value)
    log_action("update", "vulnerability", vuln.id, {"fields": sorted(data)})
    db.session.commit()
    return ok(vuln_out(vuln))


@bp.delete("/<int:vuln_id>")
def delete_vulnerability(vuln_id):
    vuln = get_or_404(Vulnerability, vuln_id)
    db.session.delete(vuln)
    log_action("delete", "vulnerability", vuln_id, {"asset_id": vuln.asset_id})
    db.session.commit()
    return no_content()
