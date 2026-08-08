# pan_cis_audit

**Offline CIS Benchmark auditor for Palo Alto PAN-OS — no live device, no panhandler.**

Audits an exported PAN-OS XML configuration against the CIS Palo Alto Firewall
Benchmark. Runs fully offline against the config file — no API access to the
firewall and no panhandler runtime required.

> 對匯出的 PAN-OS XML config 做離線 CIS Benchmark 稽核。不需連線設備、不需 panhandler 框架，
> 只吃設定檔，適合「客戶只提供設定檔」的檢測情境。

---

## Why this exists / 為什麼做這個

The official [PaloAltoNetworks/cis-benchmarks](https://github.com/PaloAltoNetworks/cis-benchmarks)
(MIT) is the authoritative source, but it is **no longer maintained**, requires
**panhandler + live API access**, and only targets **PAN-OS 9.x**.

This tool instead:

- **Offline XML** — reads the exported config, never touches a live device
- **Pure Python + lxml** — no framework dependency
- **PAN-OS 10.x compatible**
- Check **XPath ported from the official skillet** (authoritative, not guessed)
- **Secrets redacted** (IP / password / hostname) before any output — reports are safe to share

> 官方 repo 已停維護、需 live API + panhandler、僅支援 9.x。本工具改為離線 XML、純 Python、
> 支援 10.x，檢查項 XPath 移植自官方 skillet（權威定義），輸出前遮罩機敏值。

---

## Usage / 用法

```bash
pip install -r requirements.txt

python3 pan_cis_audit.py <config.xml>             # text report / 文字報告
python3 pan_cis_audit.py <config.xml> --md        # markdown table / 表格（可貼進報告）
python3 pan_cis_audit.py <config.xml> --full      # with evidence line numbers / 附證據行號
python3 pan_cis_audit.py <config.xml> --section 1 # single section / 只跑某 section
```

See [`examples/sample_report.md`](examples/sample_report.md) for sample output,
generated from [`examples/sample_config.xml`](examples/sample_config.xml) (de-identified).

---

## Architecture / 架構 (data-driven)

- `pan_cis_audit.py` — engine: runs XPath + predicate defined in `checks/*.yaml`
- `checks/*.yaml` — check definitions (one file per section), XPath ported from official skillet
- Check types: `exists` / `absent` / `min` / `max` / `equals` / `manual`

Adding a check = editing YAML, no engine change. / 新增檢查項只需編 YAML，不動引擎。

---

## Coverage / 檢查項進度

Against official CIS v9.0 (66 items) — 34 checks implemented:

- [x] **Section 1 — Device Setup** (20 checks): syslog, login banner, permitted-IP,
  9 password-complexity items, idle-timeout, account lockout, SNMPv3, NTP redundancy
- [x] **Section 2-6 — Advanced** (14 checks): User-ID, HA, dynamic-update schedules,
  WildFire, threat-prevention profiles, zone protection

**Auto vs. manual policy**: per the official CIS↔TWGCB cross-reference, items the
baseline marks "Investigate" (profile *content* checks — AV/anti-spyware/vulnerability
profiles, per-policy profile binding, User-ID) are reported `MANUAL` rather than
force-judged from static XML. Statically-decidable items (existence of HA, update
schedules, zone-protection profiles, password policy, etc.) are auto-checked.

> Taiwan users: `docs/TWGCB_03_005_checklist.md` maps every check to its TWGCB-03-005 ID.

---

## Notes / 說明

- Some CIS items depend on runtime state not present in an exported config (e.g. live
  TLS negotiation); these are marked `MANUAL` with the command to run on the device.
- CIS is a general baseline. For an **internal L4 segmentation firewall**, some items
  (login banner, browser cert) may be advisory rather than critical — interpret in context.
- Customer configs must **not** be committed; `.gitignore` blocks `*.xml` except `examples/`.

## License

MIT — see [LICENSE](LICENSE). Check definitions adapted from
[PaloAltoNetworks/cis-benchmarks](https://github.com/PaloAltoNetworks/cis-benchmarks) (MIT).
