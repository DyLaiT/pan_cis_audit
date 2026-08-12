#!/usr/bin/env python3
"""pan_cis_audit 引擎單元測試——驗證每種 check type 的判斷邏輯。

跑法：python3 -m pytest tests/ -v   或   python3 tests/test_engine.py
"""
import os
import sys
from lxml import etree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pan_cis_audit import run_check, redact  # noqa: E402


def _tree(xml):
    return ET.ElementTree(ET.fromstring(xml.encode()))


# ---- exists ----
def test_exists_pass():
    t = _tree('<config><a><b>x</b></a></config>')
    st, _, _ = run_check(t, {"type": "exists", "xpath": "/config/a/b"})
    assert st == "PASS"


def test_exists_fail():
    t = _tree('<config><a/></config>')
    st, _, _ = run_check(t, {"type": "exists", "xpath": "/config/a/b"})
    assert st == "FAIL"


# ---- absent ----
def test_absent_pass():
    t = _tree('<config><a/></config>')
    st, _, _ = run_check(t, {"type": "absent", "xpath": "/config/a/profile"})
    assert st == "PASS"


def test_absent_fail():
    t = _tree('<config><a><profile/></a></config>')
    st, _, _ = run_check(t, {"type": "absent", "xpath": "/config/a/profile"})
    assert st == "FAIL"


# ---- min ----
def test_min_pass():
    t = _tree('<config><len>12</len></config>')
    st, _, _ = run_check(t, {"type": "min", "xpath": "/config/len/text()", "threshold": 12})
    assert st == "PASS"


def test_min_fail():
    t = _tree('<config><len>8</len></config>')
    st, _, _ = run_check(t, {"type": "min", "xpath": "/config/len/text()", "threshold": 12})
    assert st == "FAIL"


def test_min_missing():
    t = _tree('<config/>')
    st, _, _ = run_check(t, {"type": "min", "xpath": "/config/len/text()", "threshold": 12})
    assert st == "FAIL"


# ---- max ----
def test_max_pass():
    t = _tree('<config><to>10</to></config>')
    st, _, _ = run_check(t, {"type": "max", "xpath": "/config/to/text()", "threshold": 10})
    assert st == "PASS"


def test_max_fail():
    t = _tree('<config><to>15</to></config>')
    st, _, _ = run_check(t, {"type": "max", "xpath": "/config/to/text()", "threshold": 10})
    assert st == "FAIL"


# ---- equals ----
def test_equals_pass():
    t = _tree('<config><en>yes</en></config>')
    st, _, _ = run_check(t, {"type": "equals", "xpath": "/config/en/text()", "expected": "yes"})
    assert st == "PASS"


def test_equals_fail():
    t = _tree('<config><en>no</en></config>')
    st, _, _ = run_check(t, {"type": "equals", "xpath": "/config/en/text()", "expected": "yes"})
    assert st == "FAIL"


# ---- redact ----
def test_redact_ip():
    assert "x.x.x.x" in redact("server 192.168.1.1 down")
    assert "192.168" not in redact("192.168.1.1")


def test_redact_password():
    assert "REDACTED" in redact("password: hunter2")


# ---- --simple 子集 ----
def test_simple_subset_is_marked():
    from pan_cis_audit import load_checks
    simple = load_checks(simple=True)
    allc = load_checks()
    # simple 子集非空、且都帶 simple: true 標記、且為全集的真子集
    assert len(simple) > 0
    assert all(c.get("simple") for c in simple)
    assert len(simple) < len(allc)


def test_simple_ids_unique():
    from pan_cis_audit import load_checks
    ids = [c["id"] for c in load_checks(simple=True)]
    assert len(ids) == len(set(ids)), "simple 子集 id 應唯一（無重複標記）"


if __name__ == "__main__":
    # 無 pytest 也能跑
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"  ✓ {fn.__name__}")
            passed += 1
        except AssertionError:
            print(f"  ✗ {fn.__name__} FAILED")
    print(f"\n{passed}/{len(fns)} 通過")
    sys.exit(0 if passed == len(fns) else 1)
