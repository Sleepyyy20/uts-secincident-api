# SecIncident API

REST API **pelaporan insiden keamanan siber & pelacakan kerentanan aset** (MVP).
Proyek UTS Pemrograman Web Lanjut (TK070) - Universitas AMIKOM Yogyakarta.

- **Stack:** Python 3.10+, Flask, Flask-SQLAlchemy (ORM), SQLite (lokal) atau MySQL/MariaDB/PostgreSQL Filess.io via `DATABASE_URL`; deploy ke Vercel (serverless)
- **Arsitektur MVC:** `app/models.py` (Model) - `app/controllers/*` (Controller / blueprint) - `app/views/serializers.py` (View JSON)
- **Domain:** cybersecurity. Semua data **simulasi**; tidak ada scanning/eksploitasi sistem lain.

## Masalah, pengguna, fitur, batasan
**Masalah:** tim IT kecil sering mencatat insiden dan kerentanan di chat/spreadsheet sehingga tidak terlacak, tidak ada riwayat perubahan, dan sulit memprioritaskan aset kritis.

| Pengguna | Kebutuhan |
|---|---|
| `reporter` (staf umum) | melaporkan insiden |
| `analyst` | menangani insiden, mencatat kerentanan, mengubah status |
| `admin` | mengelola user & aset, membaca audit log |

**Fitur utama:** manajemen user/aset/insiden/kerentanan (CRUD), relasi insiden-aset terdampak (M:N), alur status insiden terkontrol, severity kerentanan otomatis dari skor CVSS, audit log otomatis, ringkasan statistik insiden, pencarian/filter/sorting/pagination.

**Batasan (MVP):** belum ada login JWT (diganti API key + header `X-User-Id`), belum ada pemindaian otomatis, tanpa frontend, rate limiting belum ada. Lihat rencana UAS di lembar jawaban.

## ERD
![ERD](docs/erd.png)

Detail ada di [docs/ERD.md](docs/ERD.md). Tabel: `users`, `assets`, `incidents`, `incident_assets`, `vulnerabilities`, `audit_logs`.

## Instalasi
```bash
cd secincident-api
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
cp .env.example .env             # Windows: copy .env.example .env
```
### Konfigurasi (`.env`)
| Variabel | Fungsi | Default |
|---|---|---|
| `DATABASE_URL` | koneksi DB, URL Filess.io apa adanya, mis. `mysql://user:pass@host.db.filess.io:3307/nama_db` atau `postgresql://...` (driver sudah ada di requirements) | `sqlite:///secincident.db` |
| `API_KEY` | jika diisi, endpoint tulis (POST/PUT/PATCH/DELETE) dan `/api/audit-logs` wajib header `X-API-Key` | kosong (mode dev) |

### Membuat database & seed
```bash
flask --app run init-db          # buat tabel  (tambah --reset untuk mengulang dari nol)
flask --app run seed             # isi data simulasi (3 user, 5 aset, 4 insiden, 5 kerentanan)
```
Akun seed (password `Password123!`): `admin`, `analyst1`, `reporter1`.

### Menjalankan aplikasi
```bash
flask --app run run              # atau: python run.py   -> http://127.0.0.1:5000
```
### Menjalankan test
```bash
python -m pytest -v
```

## Ringkasan endpoint
Daftar lengkap: [docs/openapi.json](docs/openapi.json) (OpenAPI 3) dan [docs/postman_collection.json](docs/postman_collection.json) (import ke Postman/Insomnia).

| Method | Path | Keterangan | Sukses |
|---|---|---|---|
| GET | `/health` | status layanan | 200 |
| POST/GET | `/api/users` | buat / daftar (`role`, `q`) | 201 / 200 |
| GET/PUT/PATCH/DELETE | `/api/users/{id}` | detail / ubah / hapus | 200 / 204 |
| POST/GET | `/api/assets` | buat / daftar (`asset_type`, `criticality`, `status`, `owner_id`, `q`) | 201 / 200 |
| GET/PUT/PATCH/DELETE | `/api/assets/{id}` | | 200 / 204 |
| POST/GET | `/api/incidents` | buat / daftar (`status`, `severity`, `incident_type`, `assignee_id`, `q`) | 201 / 200 |
| GET | `/api/incidents/stats` | ringkasan per status & severity | 200 |
| GET/PUT/PATCH/DELETE | `/api/incidents/{id}` | | 200 / 204 |
| POST | `/api/incidents/{id}/assets` | hubungkan aset terdampak | 201 |
| DELETE | `/api/incidents/{id}/assets/{asset_id}` | lepas aset | 204 |
| POST/GET | `/api/vulnerabilities` | buat / daftar (`asset_id`, `severity`, `status`, `min_cvss`, `q`) | 201 / 200 |
| GET/PUT/PATCH/DELETE | `/api/vulnerabilities/{id}` | | 200 / 204 |
| GET | `/api/audit-logs` | read-only (`entity_type`, `action`, `user_id`) | 200 |

Query umum list: `page` (default 1), `per_page` (default 10, maks 100), `sort` (mis. `sort=-created_at`).
Status error: `400` query/JSON salah, `401` API key salah, `404` tidak ada, `409` konflik/duplikat/transisi status tidak valid, `422` validasi gagal, `500` error server (tanpa stack trace).

## Contoh request & response
**Buat insiden** (`X-API-Key` wajib bila `API_KEY` diisi)
```bash
curl -X POST http://127.0.0.1:5000/api/incidents \
  -H "Content-Type: application/json" -H "X-API-Key: <API_KEY>" \
  -d '{"title":"Percobaan brute force SSH","incident_type":"unauthorized_access","severity":"high","reporter_id":3,"assignee_id":2}'
```
```json
{"data": {"id": 5, "title": "Percobaan brute force SSH", "description": null,
  "incident_type": "unauthorized_access", "severity": "high", "status": "open",
  "reporter_id": 3, "assignee_id": 2, "detected_at": "2026-11-16T08:30:00Z", "resolved_at": null,
  "created_at": "2026-11-16T08:30:00Z", "updated_at": "2026-11-16T08:30:00Z", "affected_assets": []}}
```
**Error validasi (422)**
```json
{"error": {"code": "validation_error", "message": "Data yang dikirim tidak valid",
  "details": {"username": "Minimal 3 karakter", "email": "Format email tidak valid"}}}
```
**Daftar dengan filter + pagination:** `GET /api/vulnerabilities?min_cvss=7&sort=-cvss_score&page=1&per_page=5`
```json
{"data": [{"id": 4, "asset_id": 5, "title": "Kredensial default pada gateway CCTV", "cve_id": null,
  "cvss_score": 9.8, "severity": "critical", "status": "open", "...": "..."}],
 "meta": {"page": 1, "per_page": 5, "total": 4, "pages": 1}}
```
**Alur status insiden:** `open -> investigating -> contained/resolved -> closed` (`resolved -> investigating` = buka kembali). Transisi lain dijawab `409 invalid_transition`.

## Keamanan dasar yang diterapkan
Query ORM terparameter (anti SQL injection), validasi input ketat dan menolak field tak dikenal, password di-hash (Werkzeug) dan tidak pernah dikembalikan, whitelist kolom `sort`, escape wildcard pada pencarian, `CHECK`/`UNIQUE`/foreign key (pragma SQLite aktif), batas ukuran body 1 MB, header keamanan (`nosniff`, `X-Frame-Options`, `CSP`), API key dengan `hmac.compare_digest`, error 500 tidak membocorkan detail, audit log append-only.

## Penggunaan AI & referensi
Dokumentasi resmi Flask, Flask-SQLAlchemy, SQLAlchemy 2.0, OpenAPI 3.0, skala CVSS v3. Kerangka kode dan dokumentasi dibantu **Claude (Anthropic)**; seluruh kode telah ditinjau dan dijalankan/diuji oleh penulis.

## Lisensi / catatan
Dibuat untuk keperluan akademik. Seluruh data contoh fiktif.

## Deploy ke Vercel (tanpa GitHub) + database Filess.io

Prasyarat: Node.js, akun Vercel, dan database di [filess.io](https://filess.io) (MySQL/MariaDB atau PostgreSQL).

1. **Ambil connection string** dari dashboard Filess.io (host, port, user, password, nama DB), lalu susun:
   `mysql://USER:PASSWORD@HOST.db.filess.io:PORT/NAMA_DB` (atau `postgresql://...`).
   Karakter khusus di password harus di-URL-encode (`@` menjadi `%40`).
2. **Buat tabel & seed dari lokal** (Vercel tidak punya shell):
   ```bash
   pip install -r requirements-dev.txt
   cp .env.example .env              # isi DATABASE_URL dengan URL Filess.io
   python scripts/init_remote_db.py --seed
   ```
3. **Deploy langsung dengan Vercel CLI** (upload folder, tidak perlu Git):
   ```bash
   npm i -g vercel
   vercel login
   vercel                            # pertama kali: jawab pertanyaan, buat project baru (preview)
   vercel env add DATABASE_URL production
   vercel env add API_KEY production # string acak panjang, mis. hasil: openssl rand -hex 32
   vercel --prod                     # deploy produksi
   ```
   Env var harus ditambahkan **sebelum** `vercel --prod` agar terbaca.
4. **Cek**: buka `https://<project>.vercel.app/health`, lalu `/api/incidents/stats` (ini menyentuh database).
   Request tulis & `/api/audit-logs` wajib header `X-API-Key: <API_KEY>`.

Catatan: di Vercel koneksi DB memakai `NullPool` (tanpa pool) karena batas koneksi paket gratis Filess.io dan sifat serverless. Jika `DATABASE_URL` kosong saat berjalan di Vercel, aplikasi sengaja berhenti dengan pesan error (SQLite tidak bisa dipakai di sana).
