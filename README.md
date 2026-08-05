# pan_cis_audit — Palo Alto PAN-OS 離線 CIS Benchmark 稽核

對匯出的 PAN-OS XML config 做離線 CIS Benchmark 檢查，無需連線設備、無需 panhandler 框架。

## 為什麼做這個

官方 [PaloAltoNetworks/cis-benchmarks](https://github.com/PaloAltoNetworks/cis-benchmarks)（MIT）
是權威來源，但：**已停止維護、需 panhandler runtime + live API 存取、僅支援 PAN-OS 9.x**。

本工具改為：
- **離線 XML 解析**——只吃匯出的 config，不連活設備（適合客戶只給設定檔的檢測情境）
- **純 Python + lxml**——無框架依賴
- **PAN-OS 10.x 相容**
- 檢查項 XPath **移植自官方 skillet**（權威定義，非自行猜測）

## 用法

```bash
pip install -r requirements.txt
python3 pan_cis_audit.py <config.xml>            # 文字報告
python3 pan_cis_audit.py <config.xml> --md       # markdown 表格（可貼進報告）
python3 pan_cis_audit.py <config.xml> --full     # 附證據行號
python3 pan_cis_audit.py <config.xml> --section 1 # 只跑某 section
```

機敏值（IP/密碼/hostname）遮罩後才輸出，報告可交付。客戶 config 請放 gitignore 範圍外或本機，勿進 repo。

## 架構（資料驅動）

- `pan_cis_audit.py` — 引擎：跑 checks/*.yaml 的 XPath + 判斷式
- `checks/*.yaml` — 檢查定義（一 section 一檔），XPath 移植自官方
- 檢查類型：exists / absent / min / max / equals / manual

新增檢查項只需編 YAML，不動引擎。

## 檢查項進度（對照官方 CIS v9.0 共 66 項）

- [x] Section 1 Device Setup（20 項：syslog/banner/permitted-ip/密碼複雜度9項/逾時/鎖定/SNMPv3/NTP）
- [ ] Section 2 User-ID
- [ ] Section 3 High Availability
- [ ] Section 4 更新排程
- [ ] Section 5 WildFire
- [ ] Section 6 威脅防護 profile / Zone Protection

## 授權

MIT。檢查項定義參考官方 cis-benchmarks（MIT）。
