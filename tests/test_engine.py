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


# ---- sibling_hint（同層診斷線索）----
def test_sibling_hint_lists_existing_siblings():
    """FAIL 時列出同層實際存在的節點，消除「UI 看到別項就以為工具判錯」的混淆。"""
    t = _tree('<config><us><threats><r/></threats></us></config>')
    c = {"type": "exists", "xpath": "/config/us/anti-virus/recurring", "fail": "未設定",
         "sibling_hint": {"parent_xpath": "/config/us", "template": "同層只有：{found}"}}
    st, detail, _ = run_check(t, c)
    assert st == "FAIL"
    assert "threats" in detail


def test_sibling_hint_empty_parent():
    """父節點存在但無子節點 → 回 empty 訊息。"""
    t = _tree('<config><us/></config>')
    c = {"type": "exists", "xpath": "/config/us/anti-virus", "fail": "未設定",
         "sibling_hint": {"parent_xpath": "/config/us", "empty": "無任何排程"}}
    _, detail, _ = run_check(t, c)
    assert "無任何排程" in detail


def test_sibling_hint_not_applied_on_pass():
    """PASS 不需要診斷線索。"""
    t = _tree('<config><us><anti-virus/><threats/></us></config>')
    c = {"type": "exists", "xpath": "/config/us/anti-virus",
         "sibling_hint": {"parent_xpath": "/config/us", "template": "同層：{found}"}}
    st, detail, _ = run_check(t, c)
    assert st == "PASS"
    assert "threats" not in detail


# ---- note（判讀脈絡附註）----
def test_note_appended_on_fail():
    """FAIL 項帶 note → 說明附上判讀脈絡。"""
    t = _tree('<config><a/></config>')
    c = {"type": "exists", "xpath": "/config/a/b", "fail": "未設定",
         "note": "UI 可能因預設顯示為已設定"}
    st, detail, _ = run_check(t, c)
    assert st == "FAIL"
    assert "UI 可能因預設顯示為已設定" in detail


def test_note_not_applied_on_pass():
    """PASS 項不加 note（已合規，無須提醒誤判風險）。"""
    t = _tree('<config><a><b>x</b></a></config>')
    c = {"type": "exists", "xpath": "/config/a/b",
         "note": "UI 可能因預設顯示為已設定"}
    st, detail, _ = run_check(t, c)
    assert st == "PASS"
    assert "UI 可能因預設顯示為已設定" not in detail


def test_note_and_mitigation_coexist():
    """note 與 mitigation 同時存在時皆附加，順序為 note 在前。"""
    t = _tree('<config><mgmt><permitted-ip><entry name="a"/></permitted-ip></mgmt></config>')
    c = {"type": "exists", "xpath": "/config/a/b", "fail": "未設定",
         "note": "預設提醒",
         "mitigation": {"xpath": "/config/mgmt/permitted-ip/entry/@name", "found": "已限來源 IP"}}
    _, detail, _ = run_check(t, c)
    assert "註：預設提醒" in detail
    assert "補償控制：已限來源 IP" in detail
    assert detail.index("註：") < detail.index("補償控制：")


# ---- not_equals（預設即啟用型欄位）----
def test_not_equals_missing_is_pass():
    """節點不存在 = 維持 PAN-OS 預設啟用 → PASS（這是 1.6.1 誤報的修正點）。"""
    t = _tree('<config><sys/></config>')
    c = {"type": "not_equals", "xpath": "/config/sys/server-verification/text()",
         "unexpected": "no"}
    st, _, _ = run_check(t, c)
    assert st == "PASS"


def test_not_equals_explicit_no_is_fail():
    """顯式設為停用值 → FAIL。"""
    t = _tree('<config><sys><server-verification>no</server-verification></sys></config>')
    c = {"type": "not_equals", "xpath": "/config/sys/server-verification/text()",
         "unexpected": "no"}
    st, _, _ = run_check(t, c)
    assert st == "FAIL"


def test_not_equals_explicit_yes_is_pass():
    """顯式設為啟用值 → PASS。"""
    t = _tree('<config><sys><server-verification>yes</server-verification></sys></config>')
    c = {"type": "not_equals", "xpath": "/config/sys/server-verification/text()",
         "unexpected": "no"}
    st, _, _ = run_check(t, c)
    assert st == "PASS"


# ---- mitigation（補償控制附註）----
def test_mitigation_note_appended_on_manual():
    """MANUAL 項命中補償控制 XPath → 說明帶附註，狀態不變。"""
    t = _tree('<config><mgmt><permitted-ip><entry name="a"/></permitted-ip></mgmt></config>')
    c = {"type": "manual", "detail": "需人工確認",
         "mitigation": {"xpath": "/config/mgmt/permitted-ip/entry/@name", "found": "已限來源 IP"}}
    st, detail, _ = run_check(t, c)
    assert st == "MANUAL"
    assert "已限來源 IP" in detail


def test_mitigation_absent_no_note():
    """補償控制 XPath 未命中 → 不加附註。"""
    t = _tree('<config><mgmt/></config>')
    c = {"type": "manual", "detail": "需人工確認",
         "mitigation": {"xpath": "/config/mgmt/permitted-ip/entry/@name", "found": "已限來源 IP"}}
    _, detail, _ = run_check(t, c)
    assert "已限來源 IP" not in detail


def test_mitigation_not_applied_on_pass():
    """PASS 項不套補償控制附註（已合規，無須補充脈絡）。"""
    t = _tree('<config><a><b>x</b></a><mgmt><permitted-ip><entry name="a"/></permitted-ip></mgmt></config>')
    c = {"type": "exists", "xpath": "/config/a/b",
         "mitigation": {"xpath": "/config/mgmt/permitted-ip/entry/@name", "found": "已限來源 IP"}}
    st, detail, _ = run_check(t, c)
    assert st == "PASS"
    assert "已限來源 IP" not in detail


def test_mitigation_does_not_change_status():
    """FAIL 項即使有補償控制，狀態仍為 FAIL（CIS 條文未滿足）。"""
    t = _tree('<config><mgmt><permitted-ip><entry name="a"/></permitted-ip></mgmt></config>')
    c = {"type": "exists", "xpath": "/config/a/b",
         "mitigation": {"xpath": "/config/mgmt/permitted-ip/entry/@name", "found": "已限來源 IP"}}
    st, detail, _ = run_check(t, c)
    assert st == "FAIL"
    assert "已限來源 IP" in detail


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
