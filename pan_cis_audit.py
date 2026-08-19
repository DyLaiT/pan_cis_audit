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


def load_checks(section=None, simple=False):
    checks = []
    for f in sorted(glob.glob(os.path.join(CHECKS_DIR, "*.yaml"))):
        data = yaml.safe_load(open(f, encoding="utf-8")) or {}
        for c in data.get("checks", []):
            if section and not str(c.get("id", "")).startswith(str(section)):
                continue
            # --simple：只跑標記 simple: true 的精簡子集
            if simple and not c.get("simple"):
                continue
            checks.append(c)
    # 排序鍵統一為 (數字, 字串) tuple，避免 int 與 str 混比（如 "6.6-legacy" 的非數字段）
    checks.sort(key=lambda c: [(int(x), "") if x.isdigit() else (1 << 30, x)
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


def _parent_hint(tree, xp):
    """未設定的項：逐層砍 XPath 末段，找到「存在的最近父節點」，回「補在 L<行號>（<父>下）」。
    讓 FAIL(未設定) 也能定位該補在哪，而非只給 —。"""
    # 去掉 text()/@attr 結尾
    p = re.sub(r'/(text\(\)|@[\w-]+)$', '', xp)
    while '/' in p.strip('/'):
        p = p.rsplit('/', 1)[0]
        if not p:
            break
        try:
            r = tree.xpath(p)
        except ET.XPathEvalError:
            continue
        if r and not isinstance(r[0], str):
            el = r[0]
            ln = getattr(el, 'sourceline', None)
            leaf = p.rsplit('/', 1)[-1]
            if ln:
                return f"補在 L{ln}（<{leaf}> 下）"
    return ""  # 連父都不存在 → 整段缺，無處可提示


def _mitigation(tree, c):
    """補償控制：某項不合規時，檢查是否有其他措施降低風險，回附註字串。

    實務場景：CIS 要求停用管理介面 HTTP/Telnet，但受稽單位可能改以「限制來源 IP」
    達成等效防護。純看該項會判成純風險，忽略了實際已有的補償控制。此函式讓 YAML 能
    宣告 `mitigation.xpath`，命中時在說明後附註，供報告與稽核人員判讀。

    注意：補償控制**不改變** PASS/FAIL 判定（CIS 條文仍未滿足），只補充脈絡。
    """
    m = c.get("mitigation")
    if not m:
        return ""
    xp = m.get("xpath", "")
    if not xp:
        return ""
    if xpath_list(tree, xp):
        return m.get("found", "已有補償控制")
    return m.get("missing", "")


def _sibling_hint(tree, c):
    """FAIL 時列出目標節點的「同層兄弟」，指出實際存在什麼。

    動機：update-schedule 底下同時有 anti-virus / threats / wildfire，UI 上並列顯示。
    只報「未設防毒更新排程」時，稽核者看到 UI 有個 05:00 排程就會誤以為工具判錯——
    實際上那是 threats 的排程。帶出「同層已有 threats(L990)，但無 anti-virus」能直接
    消除這個混淆（2026-08 實機核對發現）。

    YAML 宣告 `sibling_hint.parent_xpath`（父節點），列出其子節點名稱與行號。
    """
    h = c.get("sibling_hint")
    if not h:
        return ""
    parent = h.get("parent_xpath", "")
    if not parent:
        return ""
    hits = xpath_list(tree, parent)
    if not hits or isinstance(hits[0], str):
        return ""
    found = [(ch.tag, getattr(ch, 'sourceline', None)) for ch in hits[0]]
    if not found:
        return h.get("empty", "同層無任何設定")
    desc = "、".join(f"{tag}(L{ln})" if ln else tag for tag, ln in found)
    return h.get("template", "同層已有：{found}").format(found=desc)


def run_check(tree, c):
    """依 check 定義跑檢查，回 (status, detail, evidence)。

    在核心判斷之上疊加兩種判讀附註（僅非 PASS 項需要，PASS 已合規）：
      - `note`：無條件附加的判讀脈絡（如「UI 可能因 PAN-OS 預設而顯示為已設定」）
      - `sibling_hint`：僅 FAIL 時，列出同層實際存在的節點（見 _sibling_hint）
      - `mitigation`：條件式，補償控制 XPath 命中才附加（見 _mitigation）
    兩者皆**不改變** PASS/FAIL 判定，只補充報告可讀性。
    """
    st, detail, ev = _run_check_core(tree, c)
    if st != "PASS":
        note = c.get("note")
        if note:
            detail = f"{detail}｜註：{note}"
        if st == "FAIL":
            sib = _sibling_hint(tree, c)
            if sib:
                detail = f"{detail}｜{sib}"
        mit = _mitigation(tree, c)
        if mit:
            detail = f"{detail}｜補償控制：{mit}"
    return st, detail, ev


def _run_check_core(tree, c):
    """依 check 定義（type + xpath + 條件）跑，回 (status, detail, evidence)。"""
    ctype = c.get("type", "exists")
    xp = c.get("xpath", "")
    name = c.get("name", "")

    if ctype == "exists":
        # xpath 有結果 = PASS（該設定存在）
        val, el = xpath_first(tree, xp)
        if val is not None:
            return "PASS", c.get("pass", "已設定"), redact(f"L{el.sourceline}" if el is not None else val)
        return "FAIL", c.get("fail", "未設定"), _parent_hint(tree, xp)

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
            return "FAIL", c.get("fail_missing", "未設定"), _parent_hint(tree, xp)
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
            return "FAIL", c.get("fail_missing", "未設定"), _parent_hint(tree, xp)
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
            return "FAIL", c.get("fail_missing", "未設定"), _parent_hint(tree, xp)
        return "FAIL", c.get("fail", f"值為 {redact(val)}，期望 {want}"), _ev(el)

    if ctype == "not_equals":
        # 「預設即啟用」型欄位：PAN-OS 部分設定未顯式寫入 XML 時維持預設啟用，
        # 只有顯式設成停用值（通常 "no"）才算不合規。官方 skillet 用 != 'no' 判斷，
        # 若沿用 equals=="yes" 會把「未設定=預設啟用」誤判為 FAIL。
        val, el = xpath_first(tree, xp)
        bad = c.get("unexpected")
        if val is None:
            return "PASS", c.get("pass_missing", f"未顯式設定（預設非 {bad}，視為合規）"), ""
        if val == bad:
            return "FAIL", c.get("fail", f"值為 {redact(val)}（停用）"), _ev(el)
        return "PASS", c.get("pass", f"= {redact(val)}"), _ev(el)

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
    ap.add_argument("--simple", action="store_true",
                    help="只跑精簡子集（標記 simple: true 的檢查項）")
    args = ap.parse_args()

    tree = load_config(args.config)
    checks = load_checks(args.section, simple=args.simple)
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
