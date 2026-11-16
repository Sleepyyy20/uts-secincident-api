from flask import Blueprint, request
from sqlalchemy import or_, select

from ..extensions import db
from ..models import (ASSET_STATUS, ASSET_TYPES, CRITICALITY, Asset, IncidentAsset, User,
                      Vulnerability)
from ..utils import (APIError, apply_sort, choice_arg, exists, get_or_404, int_arg, like_pattern,
                     log_action, no_content, ok, paginate, parse, require_ref)
from ..views.serializers import asset_out

bp = Blueprint("assets", __name__, url_prefix="/api/assets")

RULES = {
    "name": {"type": "str", "required": True, "min_len": 2, "max_len": 100},
    "asset_type": {"type": "str", "required": True, "choices": ASSET_TYPES},
    "ip_address": {"type": "ip", "nullable": True},
    "criticality": {"type": "str", "choices": CRITICALITY},
    "status": {"type": "str", "choices": ASSET_STATUS},
    "owner_id": {"type": "int", "nullable": True, "ge": 1},
}


def _prepare(data, current_id=None):
    if "name" in data:
        stmt = select(Asset.id).where(Asset.name == data["name"])
        if current_id:
            stmt = stmt.where(Asset.id != current_id)
        if exists(stmt):
            raise APIError(409, "conflict", f"Aset dengan nama '{data['name']}' sudah ada")
    if data.get("owner_id") is not None:
        require_ref(User, data["owner_id"], "owner_id")


@bp.post("")
def create_asset():
    data = parse(RULES)
    _prepare(data)
    asset = Asset(**data)
    db.session.add(asset)
    db.session.flush()
    log_action("create", "asset", asset.id, {"name": asset.name})
    db.session.commit()
    return ok(asset_out(asset), 201)


@bp.get("")
def list_assets():
    stmt = select(Asset)
    for field, choices in (("asset_type", ASSET_TYPES), ("criticality", CRITICALITY), ("status", ASSET_STATUS)):
        value = choice_arg(field, choices)
        if value:
            stmt = stmt.where(getattr(Asset, field) == value)
    owner_id = int_arg("owner_id")
    if owner_id:
        stmt = stmt.where(Asset.owner_id == owner_id)
    q = request.args.get("q")
    if q:
        pat = like_pattern(q)
        stmt = stmt.where(or_(Asset.name.ilike(pat, escape="\\"), Asset.ip_address.ilike(pat, escape="\\")))
    stmt = apply_sort(stmt, Asset, {"id", "name", "criticality", "created_at"}, default="id")
    return paginate(stmt, asset_out)


@bp.get("/<int:asset_id>")
def get_asset(asset_id):
    return ok(asset_out(get_or_404(Asset, asset_id)))


@bp.route("/<int:asset_id>", methods=["PUT", "PATCH"])
def update_asset(asset_id):
    asset = get_or_404(Asset, asset_id)
    data = parse(RULES, partial=request.method == "PATCH")
    _prepare(data, current_id=asset.id)
    for key, value in data.items():
        setattr(asset, key, value)
    log_action("update", "asset", asset.id, {"fields": sorted(data)})
    db.session.commit()
    return ok(asset_out(asset))


@bp.delete("/<int:asset_id>")
def delete_asset(asset_id):
    asset = get_or_404(Asset, asset_id)
    if (exists(select(Vulnerability.id).where(Vulnerability.asset_id == asset.id))
            or exists(select(IncidentAsset.asset_id).where(IncidentAsset.asset_id == asset.id))):
        raise APIError(409, "conflict", "Aset masih memiliki kerentanan/insiden terkait; ubah status menjadi decommissioned")
    db.session.delete(asset)
    log_action("delete", "asset", asset_id, {"name": asset.name})
    db.session.commit()
    return no_content()
