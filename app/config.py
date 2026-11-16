import logging
import os

from dotenv import load_dotenv
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

load_dotenv()

log = logging.getLogger(__name__)

# Vercel otomatis mengisi variabel VERCEL=1 saat berjalan di platform mereka.
ON_VERCEL = bool(os.getenv("VERCEL"))

# Driver Python untuk tiap jenis database Filess.io.
_DRIVERS = {
    "mysql": "mysql+pymysql",
    "mariadb": "mysql+pymysql",
    "postgres": "postgresql+psycopg2",
    "postgresql": "postgresql+psycopg2",
}


def normalize_database_url(raw: str) -> str:
    """Terima URL Filess.io apa adanya (mysql://, mariadb://, postgres://) dan ubah
    ke format SQLAlchemy lengkap dengan driver. URL yang sudah lengkap tidak diubah."""
    url = make_url(raw)
    if "+" not in url.drivername and url.drivername in _DRIVERS:
        url = url.set(drivername=_DRIVERS[url.drivername])
    if url.drivername.startswith("mysql") and "charset" not in url.query:
        url = url.update_query_dict({"charset": "utf8mb4"})
    return url.render_as_string(hide_password=False)


def build_engine_options(uri: str) -> dict:
    url = make_url(uri)
    if url.get_backend_name() == "sqlite":
        return {}
    opts = {"pool_pre_ping": True, "connect_args": {"connect_timeout": 10}}
    if ON_VERCEL:
        # Serverless: tiap invocation bisa jadi proses baru, dan paket gratis Filess.io
        # membatasi jumlah koneksi. Jangan simpan koneksi menganggur -> NullPool.
        opts["poolclass"] = NullPool
    else:
        opts["pool_recycle"] = 280
    return opts


def _resolve_database_uri() -> str:
    raw = os.getenv("DATABASE_URL", "").strip()
    if not raw:
        if ON_VERCEL:
            raise RuntimeError(
                "DATABASE_URL belum diset di Vercel (Project Settings > Environment Variables). "
                "SQLite tidak bisa dipakai karena filesystem Vercel read-only."
            )
        return "sqlite:///secincident.db"
    return normalize_database_url(raw)


class Config:
    SQLALCHEMY_DATABASE_URI = _resolve_database_uri()
    SQLALCHEMY_ENGINE_OPTIONS = build_engine_options(SQLALCHEMY_DATABASE_URI)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    API_KEY = os.getenv("API_KEY", "")
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # batasi body request 1 MB


if ON_VERCEL and not Config.API_KEY:
    log.warning("API_KEY kosong: endpoint tulis dan audit log terbuka untuk publik!")


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_ENGINE_OPTIONS = {}
    API_KEY = "test-key"
