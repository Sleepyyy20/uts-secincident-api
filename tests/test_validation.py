"""Unit test modul validasi (tidak membutuhkan database)."""
import pytest

from app.validation import ValidationError, validate

RULES = {
    "name": {"type": "str", "required": True, "min_len": 3, "max_len": 10},
    "score": {"type": "float", "ge": 0, "le": 10},
    "kind": {"type": "str", "choices": ("a", "b")},
    "ip": {"type": "ip", "nullable": True},
    "seen": {"type": "datetime"},
}


def test_valid_data_is_cleaned():
    out = validate({"name": "  abc ", "score": 5, "ip": "192.0.2.1", "seen": "2026-11-16T08:00:00Z"}, RULES)
    assert out["name"] == "abc"
    assert out["score"] == 5.0
    assert out["seen"].tzinfo is None


def test_collects_all_errors():
    with pytest.raises(ValidationError) as exc:
        validate({"score": 11, "kind": "z", "ip": "300.1.1.1", "extra": 1}, RULES)
    assert set(exc.value.errors) == {"name", "score", "kind", "ip", "extra"}


def test_partial_skips_required():
    assert validate({"kind": "a"}, RULES, partial=True) == {"kind": "a"}


def test_bool_is_not_int():
    with pytest.raises(ValidationError):
        validate({"name": "abc", "score": True}, RULES)
