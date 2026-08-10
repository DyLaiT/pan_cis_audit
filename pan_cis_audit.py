#!/usr/bin/env python3
r"""pan_cis_audit — Palo Alto PAN-OS 離線 CIS Benchmark 稽核（XML config）。

對照 CIS Palo Alto Firewall Benchmark。檢查項定義移植自官方
PaloAltoNetworks/cis-benchmarks（MIT，v9.0，66 項）的 skillet XPath，但改為：
  - 離線 XML 解析（官方需 live API + panhandler，本工具只吃匯出的 XML config）
  - 純 Python + lxml（無框架依賴）
  - 支援 PAN-OS 10.x（官方只保證 9.x）

資料驅動：檢查項定義在 checks/*.yaml，本引擎逐項跑 XPath + 判斷式，輸出報告。
機敏值（IP/密碼/hostname）遮罩後才輸出。

用法：
  python3 pan_cis_audit.py <config.xml>              # 文字報告
  python3 pan_cis_audit.py <config.xml> --md         # markdown 表格
  python3 pan_cis_audit.py <config.xml> --full       # 附證據行號
  python3 pan_cis_audit.py <config.xml> --section 1   # 只跑某 section

依賴：lxml、pyyaml
  pip install lxml pyyaml

檢查項來源：https://github.com/PaloAltoNetworks/cis-benchmarks （MIT，已停維護，本工具離線化 + 10.x）
"""
import argparse
import glob
import os
import re
import sys

try:
    from lxml import etree as ET
except ImportError:
    sys.exit("需要 lxml：pip install lxml")
try:
    import yaml
except ImportError:
    sys.exit("需要 pyyaml：pip install pyyaml")

CHECKS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "checks")


def redact(s):
    if s is None:
        return ""
    s = str(s)
    s = re.sub(r'(\d{1,3}\.){3}\d{1,3}', 'x.x.x.x', s)
    s = re.sub(r'(?i)(password|passwd|secret|key|phash)\s*[:=>]\s*\S+', r'\1=REDACTED', s)
    return s


def load_config(path):
    try:
        return ET.parse(path)
    except FileNotFoundError:
        sys.exit(f"找不到檔案: {path}")
    except ET.XMLSyntaxError as e:
        sys.exit(f"XML 解析失敗: {e}")


def load_checks(section=None):
    checks = []
    for f in sorted(glob.glob(os.path.join(CHECKS_DIR, "*.yaml"))):
        data = yaml.safe_load(open(f, encoding="utf-8")) or {}
        for c in data.get("checks", []):
            if section and not str(c.get("id", "")).startswith(str(section)):
                continue
            checks.append(c)
    checks.sort(key=lambda c: [int(x) if x.isdigit() else x
                               for x in re.split(r'\.', str(c.get("id", "0")))])
    return checks


def xpath_first(tree, xp):
    """回傳 (值, element)。值為 text/attr；element 供取行號。"""
    try:
        r = tree.xpath(xp)
    except ET.XPathEvalError:
        return None, None
    if not r:
        return None, None
    item = r[0]
    if isinstance(item, str):
        # lxml text()/@attr 結果是 smart string，有 getparent() 可取行號
        parent = item.getparent() if hasattr(item, 'getparent') else None
        return str(item), parent
    # element
    return (item.text if item.text else item.get('name', '')), item


def xpath_list(tree, xp):
    try:
        r = tree.xpath(xp)
    except ET.XPathEvalError:
        return []
    return r


def _ev(el):
    """element → 證據字串（有行號回 L<行號>，無則空）。lxml element 有 .sourceline。"""
    ln = getattr(el, 'sourceline', None) if el is not None else None
    return f"L{ln}" if ln else ""


def run_check(tree, c):
    """依 check 定義（type + xpath + 條件）跑，回 (status, detail, evidence)。"""
    ctype = c.get("type", "exists")
    xp = c.get("xpath", "")
    name = c.get("name", "")

    if ctype == "exists":
        # xpath 有結果 = PASS（該設定存在）
        val, el = xpath_first(tree, xp)
        if val is not None:
            return "PASS", c.get("pass", "已設定"), redact(f"L{el.sourceline}" if el is not None else val)
        return "FAIL", c.get("fail", "未設定"), ""

    if ctype == "absent":
        # xpath 無結果 = PASS（該項不該存在，如 password-profile 不該有）
        r = xpath_list(tree, xp)
        if not r:
            return "PASS", c.get("pass", "確認不存在"), ""
        return "FAIL", c.get("fail", f"存在 {len(r)} 個（不該有）"), ""

    if ctype == "min":
        # 數值 ≥ threshold
        val, el = xpath_first(tree, xp)
        if val is None:
            return "FAIL", c.get("fail_missing", "未設定"), ""
        try:
            n = int(val)
        except ValueError:
            return "MANUAL", f"值非數字: {redact(val)}", _ev(el)
        th = c.get("threshold", 0)
        if n >= th:
            return "PASS", c.get("pass", f"{n} ≥ {th}"), _ev(el)
        # 值不對的 FAIL 帶行號（有設定但不達標，可定位）
        return "FAIL", c.get("fail", f"{n} < {th}"), _ev(el)

    if ctype == "max":
        val, el = xpath_first(tree, xp)
        if val is None:
            return "FAIL", c.get("fail_missing", "未設定"), ""
        try:
            n = int(val)
        except ValueError:
            return "MANUAL", f"值非數字: {redact(val)}", _ev(el)
        th = c.get("threshold", 0)
        if n <= th:
            return "PASS", c.get("pass", f"{n} ≤ {th}"), _ev(el)
        return "FAIL", c.get("fail", f"{n} > {th}"), _ev(el)

    if ctype == "equals":
        val, el = xpath_first(tree, xp)
        want = c.get("expected")
        if val == want:
            return "PASS", c.get("pass", f"= {want}"), _ev(el)
        if val is None:
            return "FAIL", c.get("fail_missing", "未設定"), ""
        return "FAIL", c.get("fail", f"值為 {redact(val)}，期望 {want}"), _ev(el)

    if ctype == "manual":
        return "MANUAL", c.get("detail", "需人工/登入設備確認"), ""

    return "MANUAL", f"未知檢查類型: {ctype}", ""


def render(rows, md=False, full=False, src=""):
    cnt = {}
    if md:
        print(f"# Palo Alto PAN-OS CIS Benchmark 稽核報告\n")
        print(f"> 來源：`{src}`（機敏值已遮罩）· 檢查項對照 CIS Palo Alto Firewall Benchmark\n")
        hdr = "| 項次 | 檢查項 | Lv | 結果 | 說明 |"
        if full:
            hdr += " 證據 |"
        print(hdr)
        print("|---|---|:---:|:---:|---|" + ("---|" if full else ""))
        em = {'PASS': '✅', 'FAIL': '❌', 'WARN': '⚠️', 'MANUAL': '🔍', 'N/A': '➖'}
        for cid, name, lv, st, detail, ev in rows:
            cnt[st] = cnt.get(st, 0) + 1
            row = f"| {cid} | {name} | {lv} | {em.get(st,'')} {st} | {detail} |"
            if full:
                row += f" {ev or '—'} |"
            print(row.replace('\n', ' '))
        print()
        print("**" + " · ".join(f"{k} {v}" for k, v in sorted(cnt.items())) + f"** — 共 {len(rows)} 項")
    else:
        w = max((len(r[1]) for r in rows), default=20)
        print(f"\n{'項次':<9}{'檢查項':<{w+2}}{'Lv':<4}{'結果':<8}說明")
        print("─" * (9 + w + 2 + 4 + 8 + 30))
        mk = {'PASS': '✓', 'FAIL': '✗', 'WARN': '△', 'MANUAL': '?', 'N/A': '—'}
        for cid, name, lv, st, detail, ev in rows:
            cnt[st] = cnt.get(st, 0) + 1
            print(f"{cid:<9}{name:<{w+2}}L{lv:<3}{mk.get(st,' ')} {st:<6}{detail}")
            if full and ev:
                print(f"{'':>{9+w+2+4}}└ {ev}")
        print("─" * (9 + w + 2 + 4 + 8 + 30))
        print(f"共 {len(rows)} 項  |  " + "  ".join(f"{k}:{v}" for k, v in sorted(cnt.items())))


def main():
    ap = argparse.ArgumentParser(description="PAN-OS 離線 CIS Benchmark 稽核")
    ap.add_argument("config", help="PAN-OS XML config 檔")
    ap.add_argument("--md", action="store_true", help="markdown 表格輸出")
    ap.add_argument("--full", action="store_true", help="附證據行號")
    ap.add_argument("--section", help="只跑指定 section（如 1）")
    args = ap.parse_args()

    tree = load_config(args.config)
    checks = load_checks(args.section)
    if not checks:
        sys.exit("checks/ 無檢查定義，或 section 過濾後為空")
    rows = []
    for c in checks:
        try:
            st, detail, ev = run_check(tree, c)
        except Exception as e:
            st, detail, ev = "MANUAL", f"檢查例外: {e}", ""
        rows.append((c["id"], c.get("name", ""), c.get("level", 1), st, detail, ev))
    render(rows, md=args.md, full=args.full, src=os.path.basename(args.config))
    return 0


if __name__ == "__main__":
    sys.exit(main())
