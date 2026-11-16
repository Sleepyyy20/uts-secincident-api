"""Buat tabel (dan opsional seed) di database Filess.io dari komputer lokal.

Jalankan SEKALI sebelum/sesudah deploy (Vercel tidak punya shell untuk `flask init-db`):

    python scripts/init_remote_db.py --seed
    python scripts/init_remote_db.py --reset --seed   # hapus semua tabel dulu (data hilang!)

Membaca DATABASE_URL dari .env atau environment.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.engine import make_url  # noqa: E402

from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from app.seed import seed_data  # noqa: E402


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--reset", action="store_true", help="drop semua tabel dulu")
    p.add_argument("--seed", action="store_true", help="isi data simulasi")
    args = p.parse_args()

    app = create_app()
    url = make_url(app.config["SQLALCHEMY_DATABASE_URI"])
    print(f"Target: {url.drivername}://{url.host or 'file'}:{url.port or ''}/{url.database}")
    if url.get_backend_name() == "sqlite":
        print("PERINGATAN: ini SQLite lokal, bukan Filess.io. Cek DATABASE_URL di .env.")

    with app.app_context():
        if args.reset:
            if input("Semua tabel akan DIHAPUS. Ketik 'ya' untuk lanjut: ").strip().lower() != "ya":
                sys.exit("Dibatalkan.")
            db.drop_all()
        db.create_all()
        print("Tabel siap.")
        if args.seed:
            print("Seed selesai." if seed_data() else "Seed dilewati: data sudah ada.")


if __name__ == "__main__":
    main()
