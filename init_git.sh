#!/usr/bin/env bash
# Membuat commit bertahap + tag v1.0 di dalam folder proyek.
# Jalankan di folder secincident-api. Pastikan git config user.name / user.email sudah diisi.
set -e
git init -b main
c() { git add "$@" >/dev/null; }
c .gitignore requirements.txt .env.example && git commit -q -m "chore: inisialisasi proyek, dependency, dan konfigurasi"
c app/__init__.py app/config.py app/extensions.py app/models.py && git add app/utils.py app/validation.py app/views run.py app/controllers/__init__.py 2>/dev/null; git commit -q -m "feat: model ORM 6 tabel, application factory, helper & validasi input" 
c app/controllers/users.py app/controllers/assets.py && git commit -q -m "feat: endpoint CRUD users dan assets dengan filter, sorting, pagination"
c app/controllers/incidents.py && git commit -q -m "feat: endpoint insiden, state machine status, relasi aset terdampak, statistik"
c app/controllers/vulnerabilities.py app/controllers/audit.py && git commit -q -m "feat: endpoint kerentanan (severity dari CVSS) dan audit log read-only"
c app/seed.py && git commit -q -m "feat: CLI init-db dan seed data simulasi"
c tests && git commit -q -m "test: automated test endpoint utama (skenario sukses dan error) + unit test validasi"
c docs && git commit -q -m "docs: ERD, OpenAPI spec, dan Postman collection"
c README.md && git commit -q -m "docs: README instalasi, konfigurasi, menjalankan, test, contoh request/response"
git add -A && (git diff --cached --quiet || git commit -q -m "chore: rapikan berkas")
git tag -a v1.0 -m "Rilis v1.0 - UTS Pemrograman Web Lanjut"
git log --oneline
echo "Selanjutnya: git remote add origin <URL-REPO>; git push -u origin main --tags"
