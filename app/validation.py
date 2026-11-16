"""Validasi input sederhana tanpa dependency tambahan.

Rule per field: type (str|int|float|bool|datetime|ip), required, nullable,
allow_empty, strip, min_len, max_len, ge, le, pattern, choices.
"""
import ipaddress
import re
from datetime import datetime, timezone

EMAIL_RE = r"[^@\s]+@[^@\s]+\.[^@\s]+"


class ValidationError(Exception):
    def __init__(self, errors):
        super().__init__("Validasi gagal")
        self.errors = errors


def _coerce(value, kind):
    if kind == "str":
        if not isinstance(value, str):
            raise ValueError("Harus berupa string")
        return value
    if kind == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("Harus berupa integer")
        return value
    if kind == "float":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("Harus berupa angka")
        return float(value)
    if kind == "bool":
        if not isinstance(value, bool):
            raise ValueError("Harus berupa boolean")
        return value
    if kind == "datetime":
        if not isinstance(value, str):
            raise ValueError("Harus berupa string ISO 8601")
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("Format harus ISO 8601, contoh 2026-11-16T08:30:00Z")
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    if kind == "ip":
        if not isinstance(value, str):
            raise ValueError("Harus berupa string alamat IP")
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError:
            raise ValueError("Alamat IP tidak valid")
    raise ValueError(f"Tipe tidak didukung: {kind}")


def validate(data, rules, partial=False):
    """Mengembalikan dict bersih, atau raise ValidationError berisi semua error."""
    errors, clean = {}, {}
    for field in data:
        if field not in rules:
            errors[field] = "Field tidak dikenal"

    for field, rule in rules.items():
        if field not in data:
            if rule.get("required") and not partial:
                errors[field] = "Wajib diisi"
            continue

        value = data[field]
        if value is None:
            if rule.get("nullable"):
                clean[field] = None
            else:
                errors[field] = "Tidak boleh null"
            continue

        try:
            value = _coerce(value, rule["type"])
        except ValueError as exc:
            errors[field] = str(exc)
            continue

        if rule["type"] == "str":
            if rule.get("strip", True):
                value = value.strip()
            if not value:
                if rule.get("allow_empty"):
                    clean[field] = value
                else:
                    errors[field] = "Tidak boleh kosong"
                continue
            if "min_len" in rule and len(value) < rule["min_len"]:
                errors[field] = f"Minimal {rule['min_len']} karakter"
                continue
            if "max_len" in rule and len(value) > rule["max_len"]:
                errors[field] = f"Maksimal {rule['max_len']} karakter"
                continue
            if "pattern" in rule and not re.fullmatch(rule["pattern"], value):
                errors[field] = rule.get("pattern_msg", "Format tidak valid")
                continue
        elif rule["type"] in ("int", "float"):
            if "ge" in rule and value < rule["ge"]:
                errors[field] = f"Minimal {rule['ge']}"
                continue
            if "le" in rule and value > rule["le"]:
                errors[field] = f"Maksimal {rule['le']}"
                continue

        if "choices" in rule and value not in rule["choices"]:
            errors[field] = "Harus salah satu dari: " + ", ".join(rule["choices"])
            continue

        clean[field] = value

    if errors:
        raise ValidationError(errors)
    return clean
