"""Application factory SecIncident API (Flask + SQLAlchemy ORM, pola MVC)."""
import hmac
import logging

import click
from flask import Flask, jsonify, request
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import HTTPException

from .config import Config
from .extensions import db
from .utils import APIError, error_body

log = logging.getLogger(__name__)


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)
    db.init_app(app)

    from .controllers import assets, audit, incidents, users, vulnerabilities
    for module in (users, assets, incidents, vulnerabilities, audit):
        app.register_blueprint(module.bp)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": "secincident-api", "version": "1.0.0"})

    # ---------- keamanan dasar ----------
    @app.before_request
    def enforce_api_key():
        """Endpoint tulis (POST/PUT/PATCH/DELETE) dan audit log wajib X-API-Key bila API_KEY diset."""
        key = app.config.get("API_KEY")
        if not key or not request.path.startswith("/api"):
            return None
        protected = request.method not in ("GET", "HEAD", "OPTIONS") or request.path.startswith("/api/audit-logs")
        if protected and not hmac.compare_digest(request.headers.get("X-API-Key", ""), key):
            return jsonify(error_body("unauthorized", "X-API-Key tidak ada atau tidak valid")), 401
        return None

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Content-Security-Policy"] = "default-src 'none'"
        return resp

    # ---------- format error konsisten ----------
    @app.errorhandler(APIError)
    def handle_api_error(exc):
        return jsonify(error_body(exc.code, exc.message, exc.details)), exc.status

    @app.errorhandler(IntegrityError)
    def handle_integrity(exc):
        db.session.rollback()
        log.warning("IntegrityError: %s", exc.orig)
        return jsonify(error_body("conflict", "Pelanggaran integritas data (duplikat atau relasi tidak valid)")), 409

    @app.errorhandler(HTTPException)
    def handle_http(exc):
        return jsonify(error_body(exc.name.lower().replace(" ", "_"), exc.description)), exc.code

    @app.errorhandler(Exception)
    def handle_unexpected(exc):
        db.session.rollback()
        log.exception("Unhandled error")
        return jsonify(error_body("internal_error", "Terjadi kesalahan pada server")), 500

    # ---------- CLI: inisialisasi database & seed ----------
    @app.cli.command("init-db")
    @click.option("--reset", is_flag=True, help="Hapus semua tabel dulu (data hilang!)")
    def init_db(reset):
        """Membuat semua tabel."""
        if reset:
            db.drop_all()
        db.create_all()
        click.echo("Database siap.")

    @app.cli.command("seed")
    def seed():
        """Mengisi data simulasi (tidak menyentuh sistem nyata)."""
        from .seed import seed_data
        click.echo("Seed selesai." if seed_data() else "Seed dilewati: data sudah ada.")

    return app
